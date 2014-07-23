(ns cylon.oauth.impl.authorization-server
  (require
   [com.stuartsierra.component :as component]
   [clojure.tools.logging :refer :all]
   [modular.bidi :refer (WebService)]
   [bidi.bidi :refer (path-for)]
   [hiccup.core :refer (html h)]
   [schema.core :as s]
   [clojure.string :as str]
   [cylon.oauth.client-registry :refer (lookup-client+)]
   [cylon.oauth.authorization :refer (AccessTokenAuthorizer authorized?)]
   [cylon.authorization :refer (RequestAuthorizer request-authorized?)]
   [cylon.authentication :refer (initiate-authentication-interaction get-result)]
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
                 #_{:status 200
                    :body (format "you: %s are authenticated now!" (:cylon/identity auth-interaction-session))}
                 (let [code (str (java.util.UUID/randomUUID))
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



                 ;; "you are NOT authenticated but you have auth-session already so we carry on with this session"
                 (initiate-authentication-interaction
                        (:authenticator this) req {})
                 )
               ;; We are not authenticated, so let's authenticate first.
               (let [auth-session (create-session! (:session-store this)
                                                    {:client-id (-> req :query-params (get "client_id"))
                                                     :scope (-> req :query-params (get "scope"))
                                                     :state (-> req :query-params (get "state"))})
                   res (initiate-authentication-interaction
                        (:authenticator this) req {})]
               (cookies-response-with-session res SESSION-ID auth-session))
               )))
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
  (component/using
   (->> opts
        (merge {:store (atom {})})
        (s/validate {:scopes {s/Keyword {:description s/Str}}
                     :store s/Any
                     :iss s/Str ; uri actually, see openid-connect ch 2.
                     })
        map->AuthorizationServer)
   [:access-token-store
    :session-store
    :user-domain
    :client-registry
    :authenticator]))



(comment
     ::get-login-form
     (->
      (fn [req]
        {:status 200
         :body (html
                [:body
                 [:h1 "API Server"]
                 [:p "The application with client id " (get-session-value req  SESSION-ID (:session-store this) :client-id)
                  " is requesting access to the Azondi API on your behalf. Please login if you are happy to authorize this client."]
                 [:form {:method :post
                         :action (path-for (:modular.bidi/routes req) ::post-login-form)}
                  [:p
                   [:label {:for "user"} "User"]
                   [:input {:name "user" :id "user" :type "text"}]]
                  [:p
                   [:label {:for "password"} "Password"]
                   [:input {:name "password" :id "password" :type "password"}]]
                  [:p [:input {:type "submit"}]]
                  [:p [:a {:href (path-for (:modular.bidi/routes req) :cylon.impl.signup/signup-form)} "Signup"]]]])})
      wrap-params)

     ::post-login-form
     (-> (fn [req]
           (let [params (-> req :form-params)
                 identity (get params "user")
                 password (get params "password")

                 session (get-session (:session-store this) (get-session-id req SESSION-ID))

                 client-id (get session :client-id)
                 scope (or (get session :scope) "") ; to avoid a java.lang.NullPointerException on str/split
                 state (get session :state)

                 ;;scopes (set (str/split scope #"[\s]+"))

                 ;; Lookup client
                 {:keys [callback-uri] :as application}
                 (lookup-client+ (:client-registry this) client-id)]

             ;; openid-connect core 3.1.2.2
             ;;(if (contains? scopes "openid"))

             (if (and identity
                      (not-empty identity)
                      (verify-user (:user-domain this) (.trim identity) password))

               (let [session (create-session! (:session-store this) {:cylon/identity identity})]
                 (if (and ; we want one clause here, so we only have one then and one else clause to code
                      (satisfies? OneTimePasswordStore (:user-domain this))
                      (when-let [secret (get-totp-secret (:user-domain this) identity password)]
                        (assoc-session! (:session-store this)
                                        (:cylon.session/key session)
                                        :totp-secret secret)
                        true ; it does, but just in case assoc-session! semantics change
                        )
                      )

                   ;; So it's 2FA
                   (do
                     ;; Let's remember the client-id and state in the
                     ;; session, we'll need them later
                     (assoc-session! (:session-store this)
                                     (:cylon.session/key session)
                                     :client-id client-id)

                     (assoc-session! (:session-store this)
                                     (:cylon.session/key session)
                                     :state state)

                     (cookies-response {:status 302
                                        :headers {"Location" (path-for (:modular.bidi/routes req) ::get-totp-code)}
                                        :cookies {SESSION-ID (->cookie session)}}))

                   ;; So it's not 2FA, continue with OAuth exchange
                   ;; Generate the temporary code that we'll exchange for an access token later
                   (let [code (str (java.util.UUID/randomUUID))]

                     ;; Remember the code for the possible exchange - TODO expiry these
                     (swap! store assoc
                            {:client-id client-id :code code}
                            {:created (java.util.Date.)
                             :cylon/identity identity})

                     (cookies-response {:status 302
                                        :headers {"Location"
                                                  (format
                                                   ;; TODO: Replace this with the callback uri
                                                   "%s?code=%s&state=%s"
                                                   callback-uri code state
                                                   )}
                                        :cookies {SESSION-ID (->cookie session)}}))))
               ;; Fail
               {:status 302
                :headers {"Location" (format "%s" (path-for (:modular.bidi/routes req) ::get-login-form))}
                :body "Try again"})))

         wrap-params wrap-cookies s/with-fn-validation)

          ::get-totp-code
     (fn [req]
       {:status 200
        :body (html
               [:h1 "Please can I have your auth code"]

               (let [secret (get-session-value req SESSION-ID (:session-store this) :totp-secret)]
                 [:div


                  [:form {:method :post
                          :action (path-for (:modular.bidi/routes req)
                                            ::post-totp-code)}
                   [:input {:type "text" :id "code" :name "code"}]
                   [:input {:type "submit"}]]

                  [:p "(Hint, maybe it's something like... this ? " (totp-token secret) ")"]]))})

     ::post-totp-code
     (-> (fn [req]
           (let [totp-code (-> req :form-params (get "code"))
                 secret (get-session-value req SESSION-ID (:session-store this) :totp-secret)
                 ]
             (if (= totp-code (totp-token secret))
               ;; Success, set up the exchange
               (let [session (get-session (:session-store this) (get-session-id req SESSION-ID))
                     client-id (get session :client-id)
                     _ (infof "Looking up app with client-id %s yields %s" client-id (lookup-client+ (:client-registry this) client-id))
                     {:keys [callback-uri] :as client}
                     (lookup-client+ (:client-registry this) client-id)
                     state (get session :state)
                     identity (get session :cylon/identity)
                     ;; This is the code that will be exchanged for an access-token
                     code (str (java.util.UUID/randomUUID))]

                 ;; Remember the code for the possible exchange - TODO expire these
                 (swap! store assoc
                        {:client-id client-id :code code}
                        {:created (java.util.Date.)
                         :cylon/identity identity})

                 {:status 302
                  :headers {"Location"
                            (format "%s?code=%s&state=%s" callback-uri code state)}})

               ;; Failed, have another go!
               {:status 302
                :headers {"Location"
                          (path-for (:modular.bidi/routes req) ::get-totp-code)}
                }

               )))
         wrap-params wrap-cookies s/with-fn-validation)

)
