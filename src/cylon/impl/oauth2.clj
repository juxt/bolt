(ns cylon.impl.oauth2
  (:require
   [com.stuartsierra.component :as component]
   [clojure.tools.logging :refer :all]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [hiccup.core :refer (html h)]
   [modular.bidi :refer (WebService)]
   [bidi.bidi :refer (path-for)]
   [ring.middleware.params :refer (wrap-params)]
   [org.httpkit.client :refer (request) :rename {request http-request}]
   [cheshire.core :refer (encode decode-stream)]
   [cylon.authorization :refer (Authorizer)]
   [cylon.session :refer (create-session! get-session assoc-session!)]
   [ring.middleware.cookies :refer (wrap-cookies cookies-request cookies-response)]
   [ring.util.codec :refer (url-encode)]
   [schema.core :as s]
   [cylon.user :refer (verify-user)]
   [cylon.session :refer (create-session! assoc-session! ->cookie get-session-value get-cookie-value)]
   [cylon.totp :refer (OneTimePasswordStore get-totp-secret totp-token)]
   [clj-jwt.core :refer (to-str jwt sign str->jwt verify encoded-claims)]
   [clj-time.core :refer (now plus days)]
   ))

(defprotocol Scopes
  (valid-scope? [_ scope]))

(defprotocol ApplicationRegistry
  (register-application [_ properties])
  (lookup-application [_ client-id]))

(s/defn register-application+ :- {:client-id s/Str
                                  :client-secret s/Str}
  [p :- (s/protocol ApplicationRegistry)
   ;; If client-id and/or client-secret are not specified, they will be
   ;; generated.
   properties :- {(s/optional-key :client-id) s/Str
                  (s/optional-key :client-secret) s/Str
                  :application-name s/Str
                  :homepage-uri s/Str
                  (s/optional-key :description) s/Str
                  :callback-uri s/Str}]
  (register-application p properties))

(s/defn lookup-application+ :- {:application-name s/Str
                                :homepage-uri s/Str
                                (s/optional-key :description) s/Str
                                :callback-uri s/Str
                                :client-id s/Str
                                :client-secret s/Str}
  [p :- (s/protocol ApplicationRegistry)
   client-id :- s/Str]
  (lookup-application p client-id))

;; TODO: client secret
;; TODO: callback uri

(defrecord AuthServer [store scopes iss]
  Scopes
  (valid-scope? [_ scope] (contains? scopes scope))

  WebService
  (request-handlers [this]
    {::authorize
     (fn [req]
       ;; TODO Establish whether the user-agent is already authenticated.
       ;; If not, create a session with client-id, scope and state and redirect to the login form
       (if-let [session
                (get-session
                 (:session-store this)
                 (-> req cookies-request :cookies (get "session-id") :value))]
         ;; TODO Obey the 'prompt' value in OpenID/Connect
         {:status 200 :body (str "Hi - it appears you're already logged in, session is " (pr-str session))}

         (let [session (create-session!
                        (:session-store this)
                        {:client-id (-> req :query-params (get "client_id"))
                         :scope (-> req :query-params (get "scope"))
                         :state (-> req :query-params (get "state"))
                         })]
           (cookies-response
            {:status 200
             :body "Hi - it appears you're not already logged in, so I'm going to create a session for you and redirect you"
             :cookies {"session-id" (->cookie session)}}))))

     ::get-authenticate-form
     (->
      (fn [req]
        {:status 200
         :body (html
                [:body
                 [:h1 "Azondi MQTT Broker API Server"]
                 [:p "The application with client id " (-> req :query-params (get "client_id"))
                  " is requesting access to the Azondi API on your behalf. Please login if you are happy to authorize this application."]
                 [:form {:method :post
                         :action (path-for (:modular.bidi/routes req) ::post-authenticate-form)}
                  [:p
                   [:label {:for "user"} "User"]
                   [:input {:name "user" :id "user" :type "text" :value "juan"}]]
                  [:p
                   [:label {:for "password"} "Password"]
                   [:input {:name "password" :id "password" :type "password"}]]

                  ;; TODO - Hidden fields - I think we should first
                  ;; redirect to a oauth2 handler which validates the
                  ;; request, if the request is valid, then tries to
                  ;; authenticate the user against an existing session,
                  ;; if no existing session then redirects to a login
                  ;; form such as this. Then we wouldn't need to 'hide'
                  ;; these fields in the form.
                  [:input {:name "client_id" :type "hidden" :value (-> req :query-params (get "client_id"))}]
                  [:input {:name "scope" :type "hidden" :value (-> req :query-params (get "scope"))}]
                  [:input {:name "state" :type "hidden" :value (-> req :query-params (get "state"))}]

                  [:p [:input {:type "submit"}]]
                  [:p [:a {:href (path-for (:modular.bidi/routes req) :cylon.impl.signup/signup-form)} "Signup"]]]])})
      wrap-params)

     ::post-authenticate-form
     (-> (fn [req]
           (let [params (-> req :form-params)
                 identity (get params "user")
                 password (get params "password")
                 client-id (get params "client_id")
                 scope (get params "scope")
                 state (get params "state")
                 scopes (set (str/split scope #"[\s]+"))
                 ;; Lookup application
                 {:keys [callback-uri] :as application}
                 (lookup-application+ (:application-registry this) client-id)]

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
                        ))

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

                     {:status 302
                      :headers {"Location" (path-for (:modular.bidi/routes req) ::get-totp-code)}
                      :cookies {"session-id" (->cookie session)}})

                   ;; So it's not 2FA, continue with OAuth exchange
                   ;; Generate the temporary code that we'll exchange for an access token later
                   (let [code (str (java.util.UUID/randomUUID))]

                     ;; Remember the code for the possible exchange - TODO expiry these
                     (swap! store assoc
                            {:client-id client-id :code code}
                            {:created (java.util.Date.)
                             :cylon/identity identity})

                     {:status 302
                      :headers {"Location"
                                (format
                                 ;; TODO: Replace this with the callback uri
                                 "%s?code=%s&state=%s"
                                 callback-uri code state
                                 )}
                      :cookies {"session-id" (->cookie session)}})))
               ;; Fail
               {:status 302
                :headers {"Location" (format "%s?client_id=%s" (path-for (:modular.bidi/routes req) ::get-authenticate-form) client-id)}
                :body "Try again"})))

         wrap-params wrap-cookies s/with-fn-validation)

     ::get-totp-code
     (fn [req]
       {:status 200
        :body (html
               [:h1 "Please can I have your auth code"]

               (let [secret (get-session-value req "session-id" (:session-store this) :totp-secret)]
                 [:p "Secret is " secret]
                 [:p "Hint, Type this: " (totp-token secret)])

               [:form {:method :post
                       :action (path-for (:modular.bidi/routes req)
                                         ::post-totp-code)}
                [:input {:type "text" :id "code" :name "code"}]])})

     ::post-totp-code
     (-> (fn [req]
           (let [code (-> req :form-params (get "code"))
                 secret (get-session-value req "session-id" (:session-store this) :totp-secret)
                 ]
             (if (= code (totp-token secret))
               ;; Success, set up the exchange
               (let [session (get-session (:session-store this) (get-cookie-value req "session-id"))
                     client-id (get session :client-id)
                     _ (infof "Looking up app with client-id %s yields %s" client-id (lookup-application+ (:application-registry this) client-id))
                     {:keys [callback-uri] :as application}
                     (lookup-application+ (:application-registry this) client-id)
                     state (get session :state)
                     identity (get session :cylon/identity)
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

     ::exchange-code-for-access-token
     (-> (fn [req]
           (let [params (:form-params req)
                 code (get params "code")
                 client-id (get params "client_id")
                 client-secret (get params "client_secret")
                 application (lookup-application+ (:application-registry this) client-id)]

             (if (not= (:client-secret application) client-secret)
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

                   (info "Claim is %s" claim)

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
         wrap-params s/with-fn-validation)})

  (routes [this]
    ["/" {"authorize" {:get ::authorize}
          "login" {:get ::get-authenticate-form
                   :post ::post-authenticate-form}
          "totp" {:get ::get-totp-code
                  :post ::post-totp-code}
          "access_token" {:post ::exchange-code-for-access-token}}])

  (uri-context [this] "/login/oauth"))

(defn new-auth-server [& {:as opts}]
  (component/using
   (->> opts
        (merge {:store (atom {})})
        (s/validate {:scopes {s/Keyword {:description s/Str}}
                     :store s/Any
                     :iss s/Str ; uri actually, see openid-connect ch 2.
                     })
        map->AuthServer)
   [:access-token-store
    :session-store
    :user-domain
    :application-registry]))

;; --------

(defprotocol TempState
  (expect-state [_ state])
  (expecting-state? [this state]))

(defrecord Application [store access-token-uri]
  component/Lifecycle
  (start [this]
    ;; If there's an :application-registry dependency, use it to
    ;; register this app.
    (if-let [reg (:application-registry this)]
      (let [{:keys [client-id client-secret]}
            (s/with-fn-validation
              (register-application+
               reg
               (select-keys this [:client-id
                                  :client-secret
                                  :application-name
                                  :homepage-uri
                                  :description
                                  :callback-uri])))]
        ;; In case these are generated
        (assoc this :client-id client-id :client-secret client-secret))

      ;; If no app registry, make sure we can standalone as an app.
      (s/validate {:client-id s/Str
                   :client-secret s/Str
                   s/Keyword s/Any} this)))
  (stop [this] this)

  WebService
  (request-handlers [this]
    {::grant
     (->
      (fn [req]
        (let [params (:query-params req)
              state (get params "state")]

          (if (not (expecting-state? this state))
            {:status 400 :body "Unexpected user state"}

            ;; otherwise
            (let [code (get params "code")

                  ;; Exchange the code for an access token
                  at-resp
                  @(http-request
                    {:method :post
                     :url access-token-uri
                     :headers {"content-type" "application/x-www-form-urlencoded"}
                     ;; Exchange the code for an access token - application/x-www-form-urlencoded format

                     ;; TODO: From reading OAuth2 4.1.2 I
                     ;; don't think we should use client_id -
                     ;; that looks to be a github thing.

                     :body (format "client_id=%s&client_secret=%s&code=%s"
                                   (:client-id this) (:client-secret this) code)}
                    #(if (:error %)
                       %
                       (update-in % [:body] (comp decode-stream io/reader))))]

              (if-let [error (:error at-resp)]
                {:status 403
                 :body (format "Something went wrong: status of underlying request, error was %s"
                               error)
                 }
                (if (not= (:status at-resp) 200)
                  {:status 403
                   :body (format "Something went wrong: status of underlying request %s" (:status at-resp))}


                  (let [app-session-id (-> req cookies-request :cookies (get "app-session-id") :value)
                        original-uri (:original-uri (get-session (:session-store this) app-session-id))
                        access-token (get (:body at-resp) "access_token")
                        id-token (-> (get (:body at-resp) "id_token") str->jwt)
                        ]
                    (if (verify id-token "secret")
                      (do
                        (infof "Verified id_token: %s" id-token)
                        (assert original-uri (str "Failed to get original-uri from session " app-session-id))
                        (assoc-session! (:session-store this) app-session-id :access-token access-token)
                        (infof "Claims are %s" (:claims id-token))
                        (assoc-session! (:session-store this) app-session-id :cylon/identity (-> id-token :claims :sub))

                        {:status 302
                         :headers {"Location" original-uri}
                         :body (str "Logged in, and we got an access token: " (:body at-resp))

                         })
                      ;; Error response - id_token failed verification
                      ))))))))
      wrap-params wrap-cookies)})
  (routes [this] ["/grant" {:get ::grant}])
  (uri-context [this] "/oauth")

  Authorizer
  ;; Return the access-token, if you can!
  (authorized? [this req scope]
    (let [app-session-id (-> req cookies-request :cookies (get "app-session-id") :value)]
      (select-keys (get-session (:session-store this) app-session-id) [:access-token :cylon/identity])))

  ;; TODO Deprecate this!
  TempState
  (expect-state [this state]
    (swap! store update-in [:expected-states] conj state))
  (expecting-state? [this state]
    (if (contains? (:expected-states @store) state)
      (do
        (swap! store update-in [:expected-states] disj state)
        true))))

(defn new-application
  "Represents an OAuth2 application. This component provides all the web
  routes necessary to provide signup, login and password resets. It also
  acts as an Authorizer, which returns an OAuth2 access token from a
  call to authorized?"
  [& {:as opts}]
  (component/using
   (->> opts
        (merge {:store (atom {:expected-states #{}})})
        (s/validate {(s/optional-key :client-id) s/Str
                     (s/optional-key :client-secret) s/Str
                     :application-name s/Str
                     :homepage-uri s/Str
                     :callback-uri s/Str

                     :required-scopes #{s/Keyword}
                     :store s/Any

                     :authorize-uri s/Str
                     :access-token-uri s/Str
                     })
        map->Application)
   [:session-store]))

(defn authorize [app req]
  (let [original-uri (apply format "%s://%s%s" ((juxt (comp name :scheme) (comp #(get % "host") :headers) :uri) req))
        ;; We need a session to store the original uri
        session (create-session!
                 (:session-store app)
                 {:original-uri original-uri})
        state (str (java.util.UUID/randomUUID))]

    (expect-state app state)
    (cookies-response
     {:status 302
      :headers {"Location"
                (format "%s?client_id=%s&state=%s&scope=%s"
                        (:authorize-uri app)
                        ;;
                        (:client-id app)
                        state
                        (url-encode "openid profile email")
                        )}
      :cookies {"app-session-id"
                {:value (:cylon.session/key session)
                 :expires (.toGMTString
                           (doto (new java.util.Date)
                             (.setTime (:cylon.session/expiry session))
                             ))}}})))



(defrecord OAuth2AccessTokenAuthorizer []
  Authorizer
  (authorized? [this request scope]
    (if (valid-scope? (:auth-server this) scope)

      (let [access-token (second (re-matches #"\Qtoken\E\s+(.*)" (get (:headers request) "authorization")))
            session (get-session (:access-token-store this) access-token)
            scopes (:scopes session)]
        (infof "session is %s, scopes is %s" session scopes)
        (when scopes (scopes scope)))

      ;; Not a valid scope
      (throw (ex-info "Not a valid scope!" {:scope scope})))))

(defn new-oauth2-access-token-authorizer [& {:as opts}]
  (component/using (->OAuth2AccessTokenAuthorizer) [:access-token-store :auth-server]))

;; Optional ApplicationRegistry implementation

(defrecord RefBackedApplicationRegistry []
  component/Lifecycle
  (start [this]
    (assoc this :store {:last-client-id (ref 1000)
                        :applications (ref {})}))
  (stop [this] this)

  ApplicationRegistry
  (register-application [this properties]
    (dosync
     (let [client-id (or (:client-id properties)
                         (str (alter (-> this :store :last-client-id) inc)))
           properties (assoc properties
                        :client-id client-id
                        :client-secret (or (:client-secret properties)
                                           (str (java.util.UUID/randomUUID))))]
       (alter (-> this :store :applications) assoc client-id properties)
       (select-keys properties [:client-id :client-secret]))))

  (lookup-application [this client-id]
    (-> this :store :applications deref (get client-id))))

(defn new-ref-backed-application-registry []
  (->RefBackedApplicationRegistry))
