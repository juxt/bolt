(ns cylon.impl.oauth2
  (:require
   [com.stuartsierra.component :as component]
   [clojure.java.io :as io]
   [hiccup.core :refer (html h)]
   [modular.bidi :refer (WebService)]
   [bidi.bidi :refer (path-for)]
   [ring.middleware.params :refer (wrap-params)]
   [org.httpkit.client :refer (request) :rename {request http-request}]
   [cheshire.core :refer (encode decode-stream)]
   [cylon.authorization :refer (Authorizer)]
   [cylon.session :refer (create-session! get-session assoc-session!)]
   [ring.middleware.cookies :refer (wrap-cookies cookies-request cookies-response)]
   [schema.core :as s]
   [cylon.user :refer (verify-user)]
   [cylon.session :refer (create-session! assoc-session! ->cookie get-session-value)]
   [cylon.totp :refer (OneTimePasswordStore get-totp-secret totp-token)]))


(defprotocol Scopes
  (valid-scope? [_ scope]))

(defrecord AuthServer [store scopes]
  Scopes
  (valid-scope? [_ scope] (contains? scopes scope))

  WebService
  (request-handlers [this]
    {::authorize-form
     (->
      (fn [req]
        {:status 200
         :body (html
                (if-let [client-id (-> req :query-params (get "client_id"))]
                  [:body
                   [:h1 "Azondi MQTT Broker API Server"]
                   [:p "The application with client id " client-id
                    " is requesting access to the Azondi API on your behalf. Please login if you are happy to authorize this application."]
                   [:form {:method :post
                           :action (path-for (:modular.bidi/routes req) ::authorize)}
                    [:p
                     [:label {:for "user"} "User"]
                     [:input {:name "user" :id "user" :type "text" :value "juan"}]]
                    [:p
                     [:label {:for "password"} "Password"]
                     [:input {:name "password" :id "password" :type "password"}]]
                    [:input {:name "client_id" :type "hidden" :value client-id}]
                    [:input {:name "state" :type "hidden" :value (-> req :query-params (get "state"))}]
                    [:p [:input {:type "submit"}]]
                    [:p [:a {:href (path-for (:modular.bidi/routes req) :cylon.impl.signup/signup-form)} "Signup"]]]]
                  [:body "Nothing here"]))})
      wrap-params)

     ::authorize
     (-> (fn [req]
           (let [params (-> req :form-params)
                 identity (get params "user")
                 password (get params "password")
                 client-id (get params "client_id")
                 state (get params "state")]

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
                      :headers {"Location" (path-for (:modular.bidi/routes req) ::second-authenticator-form)}
                      :cookies {"session-id" (->cookie session)}})

                   ;; So it's not 2FA, continue with OAuth exchange
                   ;; Generate the temporary code that we'll exchange for an access token later
                   (let [code (str (java.util.UUID/randomUUID))]

                     ;; Remember the code for the possible exchange - TODO expiry these
                     (swap! store assoc
                            {:client-id client-id :code code}
                            {:created (java.util.Date.)})

                     {:status 302
                      :headers {"Location"
                                (format
                                 "http://localhost:8010/oauth/grant?code=%s&state=%s"
                                 code state
                                 )}
                      :cookies {"session-id" (->cookie session)}})))
               ;; Fail
               {:status 302
                :headers {"Location" (str "/login/oauth/authorize?client_id=" client-id)}
                :body "Try again"}
               )

             )
           )
         wrap-params wrap-cookies)

     ::second-authenticator-form
     (fn [req]
       {:status 200
        :body (html
               [:h1 "Please can I have your auth code"]

               (let [secret (get-session-value req "session-id" (:session-store this) :totp-secret)]
                 [:p "Secret is " secret]
                 [:p "Hint, Type this: " (totp-token secret)])

               [:form {:method :post
                       :action (path-for (:modular.bidi/routes req)
                                         ::process-authenticator-code)}
                [:input {:type "text" :id "code" :name "code"}]])})

     ::process-authenticator-code
     (-> (fn [req]
           (let [code (-> req :form-params (get "code"))
                 secret (get-session-value req "session-id" (:session-store this) :totp-secret)]
             (if (= code (totp-token secret))
               ;; Success, set up the exchange
               (let [client-id (get-session-value req "session-id" (:session-store this) :client-id)
                     state (get-session-value req "session-id" (:session-store this) :state)
                     code (str (java.util.UUID/randomUUID))]

                 ;; Remember the code for the possible exchange - TODO expire these
                 (swap! store assoc
                        {:client-id client-id :code code}
                        {:created (java.util.Date.)})

                 {:status 302
                  :headers {"Location"
                            (format
                             "http://localhost:8010/oauth/grant?code=%s&state=%s"
                             code state
                             )}})

               ;; Failed, have another go!
               {:status 302
                :headers {"Location"
                          (path-for (:modular.bidi/routes req) ::second-authenticator-form)}
                }

               )))
         wrap-params wrap-cookies)

     ::exchange-code-for-access-token
     (-> (fn [req]
           (let [params (:form-params req)
                 code (get params "code")
                 client-id (get params "client_id")]
             (if (get @store {:client-id client-id :code code})
               (let [{access-token :cylon.session/key}
                     (create-session! (:access-token-store this) {:scopes #{:superuser/read-users :repo :superuser/gist :admin}})]

                 {:status 200
                  :body (encode {:access-token access-token
                                 :scope "repo,gist"
                                 :token-type "bearer"})})
               {:status 400
                :body "You did not supply a valid code!"})))
         wrap-params)})

  (routes [this]
    ["/" {"authorize" {:get ::authorize-form
                       :post ::authorize}
          "second-authenticator" {:get ::second-authenticator-form
                                  :post ::process-authenticator-code}
          "access_token" {:post ::exchange-code-for-access-token}}])

  (uri-context [this] "/login/oauth"))

(defn new-auth-server [& {:as opts}]
  (component/using
   (->> opts
        (merge {:store (atom {})})
        (s/validate {:scopes {s/Keyword {:description s/Str}}
                     :store s/Any})
        map->AuthServer)
   [:access-token-store
    :session-store
    :user-domain]))

;; --------

(defprotocol TempState
  (expect-state [_ state])
  (expecting-state? [this state]))

(defrecord Application [client-id secret store]
  WebService
  (request-handlers [this]
    {::grant (-> (fn [req]
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
                                :url "http://localhost:8020/login/oauth/access_token"
                                :headers {"content-type" "application/x-www-form-urlencoded"}
                                ;; Exchange the code for an access token
                                :body (format "client_id=%s&client_secret=%s&code=%s"
                                              client-id secret code)}
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
                                   access-token (get (:body at-resp) "access-token")
                                   ]
                               (assert original-uri (str "Failed to get original-uri from session " app-session-id))
                               (assoc-session! (:session-store this) app-session-id :access-token access-token)
                               {:status 302
                                :headers {"Location" original-uri}
                                :body (str "Logged in, and we got an access token: " (:body at-resp))

                                })))))))
                 wrap-params wrap-cookies)})
  (routes [this] ["/grant" {:get ::grant}])
  (uri-context [this] "/oauth")

  Authorizer
  ;; Return the access-token, if you can!
  (authorized? [this req scope]
    (let [app-session-id (-> req cookies-request :cookies (get "app-session-id") :value)]
      (:access-token (get-session (:session-store this) app-session-id))))

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
        (merge {:store (atom {:expected-states #{}})
                :secret "sekfuhalskuehfalk"})
        (s/validate {:client-id s/Str
                     :secret s/Str
                     :store s/Any
                     :required-scopes #{s/Keyword}
                     })                 ; TODO
        map->Application)
   [:session-store]))

(defn authorize [app req]
  (let [original-uri (apply format "%s://%s%s" ((juxt (comp name :scheme) (comp #(get % "host") :headers) :uri) req))
        ;; We need a session to store the original uri
        session (create-session!
                 (:session-store app)
                 {:original-uri original-uri})
        state (str (java.util.UUID/randomUUID))
        ]
    (expect-state app state)
    (cookies-response
     {:status 302
      :headers {"Location"
                (format "http://localhost:8020/login/oauth/authorize?client_id=%s&state=%s&scope=%s"
                        (:client-id app)
                        state
                        "admin"
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

      (let [access-token (second (re-matches #"\Qtoken\E\s+(.*)" (get (:headers request) "authorization")))]

        ((:scopes (get-session (:access-token-store this) access-token)) scope))
      ;; Not a valid scope

      (throw (ex-info "Not a valid scope!" {:scope scope}))

      )))

(defn new-oauth2-access-token-authorizer [& {:as opts}]
  (component/using (->OAuth2AccessTokenAuthorizer) [:access-token-store :auth-server])
)
