(ns cylon.oauth.impl.oauth-client
  (require [com.stuartsierra.component :as component]
           [clojure.tools.logging :refer :all]
           [schema.core :as s]
           [modular.bidi :refer (WebService)]
           [cylon.authorization :refer (Authorizer)]
           [cylon.session :refer (get-session assoc-session! create-session!)]
           [ring.middleware.cookies :refer (wrap-cookies cookies-request cookies-response)]
           [ring.util.codec :refer (url-encode)]
           [ring.middleware.params :refer (wrap-params)]
           [org.httpkit.client :refer (request) :rename {request http-request}]
           [cheshire.core :refer (encode decode-stream)]
           [cylon.oauth.application-registry :refer (register-application+)]
           [clojure.java.io :as io]
           [clj-jwt.core :refer (to-str jwt sign str->jwt verify encoded-claims)]
           ))

;; --------

(defprotocol TempState
  (expect-state [_ state])
  (expecting-state? [this state]))

(defrecord OAuthClient [store access-token-uri]
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

(defn new-oauth-client
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
        map->OAuthClient)
   [:session-store :application-registry]))

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
