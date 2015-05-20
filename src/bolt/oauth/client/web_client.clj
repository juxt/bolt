;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns bolt.oauth.client.web-client
  (:require
   [bidi.bidi :refer (RouteProvider tag)]
   [cheshire.core :refer (encode decode-stream)]
   [clj-jwt.core :refer (to-str jwt sign str->jwt verify encoded-claims)]
   [clojure.java.io :as io]
   [clojure.set :refer (union)]
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [bolt.authentication.protocols :refer (RequestAuthenticator)]
   [bolt.oauth.client :refer (AccessTokenGrantee solicit-access-token expired?)]
   [bolt.oauth.registry :refer (register-client)]
   [bolt.oauth.registry.protocols :refer (ClientRegistry)]
   [bolt.oauth.encoding :refer (encode-scope decode-scope)]
   [bolt.session :refer (session respond-with-new-session! assoc-session-data! respond-close-session!)]
   [bolt.token-store :refer (create-token! get-token-by-id purge-token!)]
   [bolt.util :refer (as-set absolute-uri as-www-form-urlencoded as-query-string)]
   [aleph.http :as http]
   [ring.middleware.cookies :refer (wrap-cookies cookies-request cookies-response)]
   [ring.middleware.params :refer (wrap-params)]
   [ring.util.response :refer (redirect)]
   [schema.core :as s]
   ))

(defrecord WebClient [access-token-uri
                      end-session-endpoint post-logout-redirect-uri
                      session-store state-store
                      client-registry
                      uri-context]
  component/Lifecycle
  (start [this]
    ;; If there's an :client-registry dependency, use it to
    ;; register this app.
    (debugf "Starting web client and registering with the client-registry: %s" client-registry)

    (if client-registry
      (let [{:keys [client-id client-secret]}
            (s/with-fn-validation
              (register-client
               client-registry
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

  RouteProvider
  (routes [this]
    [uri-context
     {"grant"
      {:get
       (->
        ;; Used by the authorization server to return responses containing
        ;; authorization credentials to the client via the resource owner
        ;; user-agent.
        (fn [req]
          (let [params (:query-params req)
                state (get params "state")
                tok (get-token-by-id state-store state)]

            (if (nil? tok)
              (let [session (session session-store req)
                    original-uri (:bolt/original-uri session)]
                (if original-uri
                  (redirect original-uri)
                  {:status 400 :body "Unexpected user state"}))

              (let [code (get params "code")

                    _ (infof "Exchanging code (%s) for access token via %s" code access-token-uri)

                    ;; Exchange the code for an access token
                    ;; This is a blocking operation. We elect to wait for
                    ;; the response. In a future version we might go fully
                    ;; async.
                    at-resp
                    @(http/post access-token-uri
                      {:headers {"content-type" "application/x-www-form-urlencoded"}
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

                       :body (as-www-form-urlencoded
                              {"grant_type" "authorization_code"
                               "code" code
                               "client_id" (:client-id this)
                               "client_secret" (:client-secret this)})}

                      ;; TODO Arguably we need better error handling here
                      #(if (:error %)
                         (do
                           (errorf "Failed to get token from %s, response was %s" access-token-uri %)
                           %)
                         (update-in % [:body] (if-let [decode-fn (:decode-server-response-fn this)]
                                                decode-fn
                                                ;; add default decode to bolt oauth server response
                                                (comp decode-stream io/reader)))))]

                (purge-token! state-store state)

                (if-let [error (:error at-resp)]
                  {:status 403
                   :body (format "Something went wrong: status of underlying request, error was %s" error)}

                  (if (not= (:status at-resp) 200)
                    {:status 403
                     :body (format "Something went wrong: status of underlying request %s" (:status at-resp))}


                    (let [original-uri (:bolt/original-uri (session session-store req))
                          access-token (get (:body at-resp) "access_token")

                          ;; TODO If scope not there it is the same as
                          ;; requested (see 5.1)
                          scope (decode-scope (get (:body at-resp) "scope") (keyword? (first (:required-scopes this))))

                          id-token (-> (get (:body at-resp) "id_token") str->jwt)]
                      (if (verify id-token "secret")
                        (do
                          (assert original-uri (str "Failed to get original-uri from session " (session session-store req)))

                          (infof "Verified id_token: %s" id-token)
                          (infof "Scope is %s" scope)
                          (infof "Claims are %s" (:claims id-token))

                          (assoc-session-data!
                           session-store req {:bolt/access-token access-token
                                              :bolt/scopes scope
                                              :bolt/open-id (-> id-token :claims)
                                              :bolt/subject-identifier (-> id-token :claims :sub)})
                          (redirect original-uri))))))))))
        wrap-params
        (tag ::redirection-endpoint))}

      "logout"
      {:get
       (->
        (fn [req]
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
             )))
        (tag ::logout))}}])

  AccessTokenGrantee
  (solicit-access-token [this req target-uri]
    (solicit-access-token this req target-uri []))

  ;; RFC 6749 4.1. Authorization Code Grant (A)
  (solicit-access-token [this req target-uri scopes]
    (let [
          state (str (java.util.UUID/randomUUID))

          ;; 4.1.1.  Authorization Request
          loc (str
               (:authorize-uri this)
               (as-query-string
                {"response_type" "code"        ; REQUIRED
                 "client_id" (:client-id this) ; REQUIRED
                 ;; "redirect_uri" nil ; OPTIONAL (TODO)
                 "scope" (encode-scope
                          (union (as-set scopes) ; OPTIONAL
                                 (:required-scopes this)))
                 "state" state          ; RECOMMENDED to prevent CSRF
                 }))]

      (create-token! state-store state {})
      ;; We create a session
      (debugf "Creating session to store original uri of %s" target-uri)
      ;; We redirect to the (authorization) uri send the redirect response, but first

      ;; We need a session to store the original uri
      (respond-with-new-session!
       session-store req
       {:bolt/original-uri target-uri}
       (redirect loc))))

  (expired? [_ req access-token] false)

  RequestAuthenticator
  (authenticate [component request]
    (session session-store request)))

(defn new-web-client
  "Represents an OAuth2 client. This component provides all the web
  routes necessary to provide signup, login and password resets. It also
  acts as a RequestAuthorizer, which returns an OAuth2 access token from a
  call to authorized?"
  [& {:as opts}]
  (component/using
   (->> opts
        (merge {:requires-user-acceptance? true
                :uri-context "/"})
        (s/validate {(s/optional-key :client-id) s/Str
                     (s/optional-key :client-secret) s/Str
                     :application-name s/Str
                     :homepage-uri s/Str
                     :redirection-uri s/Str
                     (s/optional-key :post-logout-redirect-uri) s/Str

                     :required-scopes (s/either #{s/Keyword} #{s/Str})

                     :authorize-uri s/Str
                     :access-token-uri s/Str
                     (s/optional-key :end-session-endpoint) s/Str

                     :requires-user-acceptance? s/Bool
                     :uri-context s/Str
                     (s/optional-key :decode-server-response-fn) s/Any
                     })
        map->WebClient)
   [:session-store :state-store]))
