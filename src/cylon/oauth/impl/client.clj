;; TODO Rename to cylon.oauth.client
(ns cylon.oauth.impl.client
  (require
   [cheshire.core :refer (encode decode-stream)]
   [clj-jwt.core :refer (to-str jwt sign str->jwt verify encoded-claims)]
   [clojure.java.io :as io]
   [clojure.set :refer (union)]
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [cylon.authorization :refer (RequestAuthorizer)]
   [cylon.oauth.client :refer (AccessTokenGrantee UserIdentity solicit-access-token)]
   [cylon.oauth.client-registry :refer (register-client+)]
   [cylon.oauth.encoding :refer (encode-scope decode-scope)]
   [cylon.session :refer (session respond-with-new-session! assoc-session-data! respond-close-session!)]
   [cylon.util :refer (as-set absolute-uri as-query-string)]
   [modular.bidi :refer (WebService)]
   [org.httpkit.client :refer (request) :rename {request http-request}]
   [ring.middleware.cookies :refer (wrap-cookies cookies-request cookies-response)]
   [ring.middleware.params :refer (wrap-params)]
   [ring.util.response :refer (redirect)]
   [schema.core :as s]
   ))

;; -------- Convenience - TODO promote somewhere

(defprotocol TempState
  (expect-state [_ state])
  (expecting-state? [this state]))

;; It's nice for me to write down my thoughts to you because it captures what i'm thinking and we discuss here via typing !!

;; What I was saying was, in summary, that OpenID/Connect layers on top of OAuth2 - but in doing so complects the two processes: the first process (OAuth2) is responsible for authenticating the client application (let's call this Astro, a web ui for managing iot devices)
;; Alice is a user. She is using Astro to manage her azondi devices. The Oauth2 process is authenticating that Astro is a valid application.

(defrecord WebClient [store access-token-uri
                      end-session-endpoint post-logout-redirect-uri
                      session-store client-registry]
  component/Lifecycle
  (start [this]
    ;; If there's an :client-registry dependency, use it to
    ;; register this app.
    (if-let [reg client-registry]
      (let [{:keys [client-id client-secret]}
            (s/with-fn-validation
              (register-client+
               reg
               (select-keys
                this
                [:client-id
                 :client-secret
                 :application-name
                 :homepage-uri
                 :description
                 :redirection-uri
                 :required-scopes
                 :requires-user-acceptance?
                 ])))]
        ;; In case these are generated
        (assoc this :client-id client-id :client-secret client-secret))

      ;; If no app registry, make sure we can standalone as an app.
      (s/validate {:client-id s/Str
                   :client-secret s/Str
                   s/Keyword s/Any} this)))
  (stop [this] this)

  WebService
  (request-handlers [this]
    {::redirection-endpoint
     ;; Used by the authorization server to return responses containing
     ;; authorization credentials to the client via the resource owner
     ;; user-agent.
     (->
      (fn [req]
        (let [params (:query-params req)
              state (get params "state")]

          (if (not (expecting-state? this state))
            {:status 400 :body "Unexpected user state"}

            (let [code (get params "code")

                  ;; Exchange the code for an access token
                  ;; This is a blocking operation. We elect to wait for
                  ;; the response. In a future version we might go fully
                  ;; async.
                  at-resp
                  @(http-request
                    {:method :post
                     :url access-token-uri
                     :headers {"content-type" "application/x-www-form-urlencoded"}
                     ;; Exchange the code for an access token - application/x-www-form-urlencoded format
                     ;; 2.3.1: "Including the client credentials in the
                     ;; request-body using the two parameters is NOT
                     ;; RECOMMENDED and SHOULD be limited to clients
                     ;; unable to directly utilize the HTTP Basic
                     ;; authentication scheme (or other password-based
                     ;; HTTP authentication schemes)."

                     ;; TODO Support Basic Authentication in preference
                     ;; to client secrets.

                     ;; 4.1.3. Access Token Request redirect_uri
                     ;; REQUIRED, if the "redirect_uri" parameter was
                     ;; included in the authorization request as
                     ;; described in Section 4.1.1, and their values
                     ;; MUST be identical.

                     ;; TODO: Better if we could construct this string
                     ;; with the help of some utility function.
                     :body (format "grant_type=%s&code=%s&client_id=%s&client_secret=%s"
                                   "authorization_code"
                                   code
                                   (:client-id this)
                                   (:client-secret this))}
                    #(if (:error %)
                       %
                       (update-in % [:body] (comp decode-stream io/reader))))]

              (if-let [error (:error at-resp)]
                {:status 403
                 :body (format "Something went wrong: status of underlying request, error was %s" error)}

                (if (not= (:status at-resp) 200)
                  {:status 403
                   :body (format "Something went wrong: status of underlying request %s" (:status at-resp))}


                  (let [original-uri (:cylon/original-uri (session session-store req))
                        access-token (get (:body at-resp) "access_token")

                        ;; TODO If scope not there it is the same as
                        ;; requested (see 5.1)
                        scope (decode-scope (get (:body at-resp) "scope"))

                        id-token (-> (get (:body at-resp) "id_token") str->jwt)]
                    (if (verify id-token "secret")
                      (do
                        (assert original-uri (str "Failed to get original-uri from session " (session session-store req)))

                        (infof "Verified id_token: %s" id-token)
                        (infof "Scope is %s" scope)
                        (infof "Claims are %s" (:claims id-token))

                        (assoc-session-data! session-store req {:access-token access-token :scope scope :open-id (-> id-token :claims) })
                        (redirect original-uri))))))))))
      wrap-params)

     ::logout (fn [req]
                ;; http://openid.net/specs/openid-connect-session-1_0.html - chapter 5

                ;; "An RP can notify the OP that the End-User has logged
                ;; out of the site, and might want to log out of the OP
                ;; as well. In this case, the RP, after having logged
                ;; the End-User out of the RP, redirects the End-User's
                ;; User Agent to the OP's logout endpoint URL. This URL
                ;; is normally obtained via the end_session_endpoint
                ;; element of the OP's Discovery response, or may be
                ;; learned via other mechanisms."

                ;; post_logout_redirect_uri
                ;; OPTIONAL. URL to which the RP is requesting that the
                ;; End-User's User
                ;; Agent be redirected after a logout has been performed. The value MUST
                ;; have been previously registered with the OP, either using the
                ;; post_logout_redirect_uris Registration parameter or via another
                ;; mechanism. If supplied, the OP SHOULD honor this request following
                ;; the logout.

                ;; TODO Perhaps we need to redirect to a logout on the auth-server side, with a original-uri of location-after-logout

                (respond-close-session!
                 session-store req
                 (cond
                  end-session-endpoint
                  ;; "An RP can notify the OP that the End-User has logged out of the site"
                  ;; If specified, add the OPTIONAL post_logout_redirect_uri query parameter
                  (redirect (str end-session-endpoint (when post-logout-redirect-uri (str "?post_logout_redirect_uri=" post-logout-redirect-uri))))

                  ;; If there's only a post-logout-redirect-uri, then redirect to it
                   post-logout-redirect-uri (redirect post-logout-redirect-uri)
                   :otherwise {:status 200 :body "Logged out"}
                   )))})

  (routes [this] ["/" {"oauth/grant" {:get ::redirection-endpoint}
                       "logout" {:get ::logout}}])
  (uri-context [this] "")

  AccessTokenGrantee
  (get-access-token [this req]
    (session session-store req))

  (solicit-access-token [this req authorize-uri]
    (solicit-access-token this req authorize-uri []))

  ;; RFC 6749 4.1. Authorization Code Grant (A)
  (solicit-access-token [this req authorize-uri scopes]
    (let [original-uri (absolute-uri req)
          state (str (java.util.UUID/randomUUID))

          ;; 4.1.1.  Authorization Request
          response
          (let [loc (str
                     authorize-uri
                     (as-query-string
                      {"response_type" "code"        ; REQUIRED
                       "client_id" (:client-id this) ; REQUIRED
                       ;; "redirect_uri" nil ; OPTIONAL (TODO)
                       "scope" (encode-scope
                                (union (as-set scopes) ; OPTIONAL
                                       (:required-scopes this)))
                       "state" state    ; RECOMMENDED to prevent CSRF
                       }))]
            (debugf "Redirecting to %s" loc)
            (redirect loc))]

      (expect-state this state)
      ;; We create a session
      (debugf "Creating session to store original uri of %s" original-uri)
      ;; We redirect to the (authorization) uri send the redirect response, but first

      ;; We need a session to store the original uri
      (respond-with-new-session!
       session-store req {:cylon/original-uri original-uri} response)))

  (expired? [_ req access-token] false)

  UserIdentity
  (get-claims [this req]
    (when-let [session (session session-store req)]
      (:open-id session)))

  ;; TODO Deprecate this!
  TempState
  (expect-state [this state]
    (swap! store update-in [:expected-states] conj state))
  (expecting-state? [this state]
    (if (contains? (:expected-states @store) state)
      (do
        (swap! store update-in [:expected-states] disj state)
        true))))

(defn new-web-client
  "Represents an OAuth2 client. This component provides all the web
  routes necessary to provide signup, login and password resets. It also
  acts as a RequestAuthorizer, which returns an OAuth2 access token from a
  call to authorized?"
  [& {:as opts}]
  (component/using
   (->> opts
        (merge {:store (atom {:expected-states #{}})
                :requires-user-acceptance? true})
        (s/validate {(s/optional-key :client-id) s/Str
                     (s/optional-key :client-secret) s/Str
                     :application-name s/Str
                     :homepage-uri s/Str
                     :redirection-uri s/Str
                     (s/optional-key :post-logout-redirect-uri) s/Str

                     :required-scopes #{s/Keyword}
                     ;; TODO What's this? Can we document it?
                     :store s/Any

                     :authorize-uri s/Str
                     :access-token-uri s/Str
                     (s/optional-key :end-session-endpoint) s/Str

                     :requires-user-acceptance? s/Bool
                     (s/optional-key :location-after-logout) s/Str
                     })
        map->WebClient)
   [:client-registry :session-store]))

;; But this isn't authorization - this is authentication
;; can you write?
;; > sorry; I thnk it can be renamed to : start-app-grant-workflow
;; this fn encapsulates this kind of knowledge,, related to how start this process, where to go to grant the app privileges , so it has to be redirected , but doesn't check any value related to authentication there is not conditional here

;; yes, but I would argue that this is still an authentication process which results in an access token
;; an access token doesn't let you do anything, you must be authorized first
;; the access token is a parameter into the authorizer
;; authentication process results in a) user's identity b) an access token
;; but the first step is totally independent of the second step
;; both a) and b) are the results of a single workflow - the OAuth2 with OpenID/Connect layered on it
;; i don't think so :)
;; but we wouldn't run the oauth2 process (code exchange) twice - once for the user identity and another time for the access token - they are both established together using a single workflow
; yes this is right , but i think that we are a bit mixing 2 workflows
;; authn and authz will happen at the same time - you're right
;; process A: it's really authn and partial authz, because
;; process B is the completion of the authz step
;; process B can assume that the access token is real and authentic.
;; process B can also trust that the scopes associated with the access token are accurate and authentic
;; process B can still choose to deny the user access to the resource, if the access token does not correspond to sufficient scopes
;; so this discussion, is relaly about what to name this function
;; and I don't think authorize captures the meaning
;; process A: it's really authn and partial authz, because
;; it would be more accurate to name this function 'process A'
;; (but that would be silly)
;; so I think we should name it authenticate because that captures more precisely (although not 100% accurately) what the process does
;; but later we will run process B and that will be called authorization

;; why don't you name it (defn grant app req)
;; i think that really represents the fact or the start moment that the resource-owner grants the client to access the resource-server
;; ok
;; great!
;; i see
;; i'm going to the toilet )
;; :)
;; these comments wil be saved in github perhaps :)
;; i'm getting coffee - i think you're right

;; So this function does not belong in client.clj - it belongs in auth-server authorization.clj
