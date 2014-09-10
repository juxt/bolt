;; TODO Rename to cylon.oauth.client
(ns cylon.oauth.impl.client
  (require
   [com.stuartsierra.component :as component]
   [clojure.tools.logging :refer :all]
   [clojure.set :refer (union)]
   [schema.core :as s]
   [modular.bidi :refer (WebService)]
   [cylon.oauth.client :refer (AccessTokenGrantee UserIdentity solicit-access-token)]
   [cylon.authorization :refer (RequestAuthorizer)]
   [cylon.session :refer (->cookie get-session assoc-session! create-session! cookies-response-with-session get-session-value get-session-id purge-session!)]
   [ring.middleware.cookies :refer (wrap-cookies cookies-request cookies-response)]
   [ring.util.response :refer (redirect)]
   [ring.middleware.params :refer (wrap-params)]
   [org.httpkit.client :refer (request) :rename {request http-request}]
   [cheshire.core :refer (encode decode-stream)]
   [cylon.oauth.client-registry :refer (register-client+)]
   [clojure.java.io :as io]
   [clj-jwt.core :refer (to-str jwt sign str->jwt verify encoded-claims)]
   [cylon.util :refer (as-set absolute-uri)]
   [cylon.oauth.encoding :refer (encode-scope as-query-string decode-scope)]
   ))

;; -------- Convenience - TODO promote somewhere

(defprotocol TempState
  (expect-state [_ state])
  (expecting-state? [this state]))

;; It's nice for me to write down my thoughts to you because it captures what i'm thinking and we discuss here via typing !!

;; What I was saying was, in summary, that OpenID/Connect layers on top of OAuth2 - but in doing so complects the two processes: the first process (OAuth2) is responsible for authenticating the client application (let's call this Astro, a web ui for managing iot devices)
;; Alice is a user. She is using Astro to manage her azondi devices. The Oauth2 process is authenticating that Astro is a valid application.

(def APP-SESSION-ID "app-session-id")

(defrecord WebClient [store access-token-uri location-after-logout]
  component/Lifecycle
  (start [this]
    ;; If there's an :client-registry dependency, use it to
    ;; register this app.
    (if-let [reg (:client-registry this)]
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


                  (let [app-session-id (get-session-id req APP-SESSION-ID)
                        original-uri (get-session-value req APP-SESSION-ID (:session-store this) :original-uri)
                        access-token (get (:body at-resp) "access_token")

                        ;; TODO If scope not there it is the same as
                        ;; requested (see 5.1)
                        scope (decode-scope (get (:body at-resp) "scope"))

                        id-token (-> (get (:body at-resp) "id_token") str->jwt)]
                    (if (verify id-token "secret")
                      (do
                        (infof "Verified id_token: %s" id-token)
                        (assert original-uri (str "Failed to get original-uri from session " app-session-id))
                        (assoc-session! (:session-store this) app-session-id :access-token access-token)

                        (infof "Scope is %s" scope)
                        (assoc-session! (:session-store this) app-session-id :scope scope)

                        (infof "Claims are %s" (:claims id-token))
                        (assoc-session! (:session-store this) app-session-id :open-id (-> id-token :claims))
                        (redirect original-uri))))))))))
      wrap-params)

     ::logout (fn [req]
                (purge-session! (:session-store this) (get-session-id req APP-SESSION-ID))
                (if location-after-logout
                  (redirect location-after-logout)
                  {:status 200
                   :body "You have logged out"}))})

  (routes [this] ["/" {"oauth/grant" {:get ::redirection-endpoint}
                       "logout" {:get ::logout}}])
  (uri-context [this] "")

  AccessTokenGrantee
  (get-access-token [this req]
    (when-let [app-session-id (get-session-id req APP-SESSION-ID)]
      (-> (get-session (:session-store this) app-session-id))))

  (solicit-access-token [this req]
    (solicit-access-token this req []))

  ;; RFC 6749 4.1. Authorization Code Grant (A)
  (solicit-access-token [this req scopes]
    (let [original-uri (absolute-uri req)
          ;; We need a session to store the original uri
          session (create-session!
                   (:session-store this)
                   {:original-uri original-uri})
          state (str (java.util.UUID/randomUUID))]

      (expect-state this state)
      ;; 4.1.1.  Authorization Request
      (cookies-response-with-session
       (let [loc (str
                  (:authorize-uri this)
                  (as-query-string {"response_type" "code" ; REQUIRED
                                    "client_id" (:client-id this) ; REQUIRED
                                    ; "redirect_uri" nil ; OPTIONAL (TODO)
                                    "scope" (encode-scope
                                             (union (as-set scopes) ; OPTIONAL
                                                    (:required-scopes this)))
                                    "state" state ; RECOMMENDED to prevent CSRF
                                    }))]
         (debugf "Redirecting to %s" loc)
         (redirect loc))

       APP-SESSION-ID
       session)))

  (expired? [_ req access-token] false)

  UserIdentity
  (get-claims [this req]
    (let [app-session-id (get-session-id req APP-SESSION-ID)]
      (-> (get-session (:session-store this) app-session-id) :open-id)))

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

                     :required-scopes #{s/Keyword}
                     :store s/Any

                     :authorize-uri s/Str
                     :access-token-uri s/Str

                     :requires-user-acceptance? s/Bool
                     (s/optional-key :location-after-logout) s/Str
                     })
        map->WebClient)
   [:session-store :client-registry]))

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
