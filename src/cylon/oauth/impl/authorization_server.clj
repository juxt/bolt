(ns cylon.oauth.impl.authorization-server
  (require
   [com.stuartsierra.component :as component]
   [clojure.tools.logging :refer :all]
   [modular.bidi :refer (WebService)]
   [bidi.bidi :refer (path-for)]
   [hiccup.core :refer (html h)]
   [schema.core :as s]
   [plumbing.core :refer (<-)]
   [clojure.string :as str]
   [cylon.oauth.client-registry :refer (lookup-client+)]
   [cylon.oauth.authorization :refer (AccessTokenAuthorizer authorized?)]
   [cylon.authorization :refer (RequestAuthorizer request-authorized?)]
   [cylon.authentication :refer (initiate-authentication-interaction get-result clean-resources!)]
   [cylon.user :refer (verify-user)]
   [cylon.totp :refer (OneTimePasswordStore get-totp-secret totp-token)]
   [clj-time.core :refer (now plus days)]
   [cheshire.core :refer (encode)]
   [clj-jwt.core :refer (to-str sign jwt)]
   [ring.middleware.params :refer (wrap-params)]
   [ring.middleware.cookies :refer (cookies-request)]
   [cylon.session :refer (create-session! assoc-session! ->cookie get-session-value get-session-id get-session cookies-response-with-session get-session-from-cookie)]
   [ring.middleware.cookies :refer (wrap-cookies cookies-request cookies-response)]))

(def SESSION-ID "auth-session-id")

(defrecord AuthorizationServer [store scopes iss]

  WebService
  (request-handlers [this]
    {::authorize
     (-> (fn [req]
           ;; TODO Establish whether the user-agent is already authenticated.
           ;; If not, create a session with client-id, scope and state and redirect to the login form
           (println "")
           (println "::::::::::::::::::::::::::::: authorize!! :::::::::::::::::::::::::::::")
           (println "")
           (let [session (get-session-from-cookie req  SESSION-ID (:session-store this))]
             (if-let [auth-interaction-session (get-result (:authenticator this) req)]
               ;; the session can be authenticated or maybe we are coming from the authenticator workflow
               (if (:cylon/authenticated? auth-interaction-session)
                 ;; "you are authenticated now!"
                 (let [_ (clean-resources! (:authenticator this) req)
                       code (str (java.util.UUID/randomUUID))
                       client-id (:client-id session)
                       {:keys [callback-uri] :as client} (lookup-client+ (:client-registry this) client-id)]

                   ;; Remember the code for the possible exchange - TODO expiry these
                   (swap! store assoc
                          {:client-id client-id
                           :code code}
                          {:created (java.util.Date.)
                           :cylon/identity (:cylon/identity auth-interaction-session)})
                   {:status 302
                    :headers {"Location"
                              (format
                               ;; TODO: Replace this with the callback uri
                               "%s?code=%s&state=%s"
                               callback-uri  code (:state session))}})
               ;; you have auth-session although you are NOT authenticated but ,,, we carry on with this session"
                 (initiate-authentication-interaction (:authenticator this) req {}))
               ;; You are not authenticated, so let's authenticate first.
               (let [auth-session (create-session! (:session-store this)
                                                    {:client-id (-> req :query-params (get "client_id"))
                                                     :scope (-> req :query-params (get "scope"))
                                                     :state (-> req :query-params (get "state"))})]
                 (cookies-response-with-session
                  (initiate-authentication-interaction (:authenticator this) req {})
                  SESSION-ID auth-session)))))
         wrap-params)

     ::exchange-code-for-access-token
     (-> (fn [req]
           (let [params (:form-params req)
                 code (get params "code")
                 client-id (get params "client_id")
                 client-secret (get params "client_secret")
                 client (lookup-client+ (:client-registry this) client-id)]

             (if (not= (:client-secret client) client-secret)
               {:status 400 :body "Invalid request - bad secret"}

               (if-let [{identity :cylon/identity}
                        (get @store
                             ;; I don't think this key has to include client-id
                             ;; - it can just be 'code'.
                             {:client-id client-id :code code})]

                 (let [{access-token :cylon.session/key}
                       (create-session! (:access-token-store this) {:scopes #{:superuser/read-users :repo :superuser/gist :admin}})
                       claim {:iss iss
                              :sub identity
                              :aud client-id
                              :exp (plus (now) (days 1)) ; expiry
                              :iat (now)}]

                   (infof "Claim is %s" claim)

                   {:status 200
                    :body (encode {"access_token" access-token
                                   "scope" "repo gist openid profile email"
                                   "token_type" "Bearer"
                                   "expires_in" 3600
                                   ;; TODO Refresh token (optional)
                                   ;; ...
                                   ;; OpenID Connect ID Token
                                   "id_token" (-> claim
                                                  jwt
                                                  (sign :HS256 "secret") to-str)
                                   })})
                 {:status 400
                  :body "Invalid request - unknown code"}))))
         wrap-params )})

  (routes [this]
    ["/" {"authorize" {:get ::authorize}
          "access_token" {:post ::exchange-code-for-access-token}}])

  (uri-context [this] "/login/oauth")

  AccessTokenAuthorizer
  (authorized? [this access-token scope]
    (if-not (contains? (set (keys scopes)) scope)
      (throw (ex-info "Invalid scope" {:scope scope}))
      (contains? (:scopes (get-session (:access-token-store this) access-token))
                 scope)))

  RequestAuthorizer
  (request-authorized? [this request scope]
    (when-let [auth-header (get (:headers request) "authorization")]
      (let [access-token (second (re-matches #"\Qtoken\E\s+(.*)" auth-header))]
        (authorized? this access-token scope)))))

(defn new-authorization-server [& {:as opts}]
  (->> opts
       (merge {:store (atom {})})
       (s/validate
        {:scopes {s/Keyword {:description s/Str}}
         :store s/Any
         :iss s/Str             ; uri actually, see openid-connect ch 2.
         })
       map->AuthorizationServer
       (<- (component/using
            [:access-token-store
             :session-store
             :user-domain
             :client-registry
             :authenticator]))))
