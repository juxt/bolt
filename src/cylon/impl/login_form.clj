;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.login-form
  (:require
   [com.stuartsierra.component :as component]
   [bidi.bidi :refer (path-for ->WrapMiddleware)]
   [hiccup.core :refer (html)]
   [schema.core :as s]
   [ring.middleware.cookies :refer (wrap-cookies)]
   [cylon.user :refer (UserAuthenticator authenticate-user)]
   [cylon.session :refer ( HttpSessionStore  start-session! end-session!)]
   [ring.middleware.params :refer (wrap-params)]
   [modular.bidi :refer (WebService)]))

(defn new-login-get-handler [handlers-p & {:keys [boilerplate] :as opts}]
  (fn [{{{requested-uri :value} "requested-uri"} :cookies
        routes :modular.bidi/routes}]
    (let [form
          [:form {:method "POST" :style "border: 1px dotted #555"
                  :action (path-for routes (get @handlers-p :process-login))}
           (when (not-empty requested-uri)
             [:input {:type "hidden" :name :requested-uri :value requested-uri}])
           [:div
            [:label {:for "username"} "Username"]
            [:input {:id "username" :name "username" :type "input"}]]
           [:div
            [:label {:for "password"} "Password"]
            [:input {:id "password" :name "password" :type "password"}]]
           [:input {:type "submit" :value "Login"}]
           ]]
      {:status 200
       :body (if boilerplate (boilerplate (html form)) (html [:body form]))})))

(defn new-login-post-handler [handlers-p & {:keys [user-authenticator http-session-store] :as opts}]
  (s/validate {:user-authenticator (s/protocol UserAuthenticator)
               :http-session-store (s/protocol HttpSessionStore)}
              opts)
  (fn [{{username "username" password "password" requested-uri "requested-uri"} :form-params
        routes :modular.bidi/routes}]

    (if (and username
             (not-empty username)
             (authenticate-user user-authenticator (.trim username) password))

      {:status 302
       :headers {"Location" (or requested-uri "/")} ; "/" can be parameterized (TODO)
       :cookies {"session" (start-session! http-session-store username)
                 "requested-uri" ""}}

      ;; Return back to login form
      {:status 302
       :headers {"Location" (path-for routes (get @handlers-p :login))}})))

(defn new-logout-handler [http-session-store]
  (fn [{:keys [cookies]}]
    (end-session!
     http-session-store
     (:value (get cookies "session")))
    {:status 302 :headers {"Location" "/"}}))

(defn make-login-handlers [opts]
  (let [p (promise)]
    @(deliver p
              {:login (apply new-login-get-handler p (apply concat (seq (select-keys opts [:boilerplate]))))
               :process-login (->
                               (apply new-login-post-handler
                                      p (apply concat (seq (select-keys opts [:user-authenticator :http-session-store]))))
                               wrap-params)
               :logout (new-logout-handler (:http-session-store opts))})))

(defrecord LoginForm [uri-context boilerplate]
  component/Lifecycle
  (start [this]
    (let [handlers (make-login-handlers (select-keys this [:user-authenticator :http-session-store :boilerplate]))]
      (assoc this
        :handlers handlers
        :routes
        ["" (->WrapMiddleware
             [["/login" {:get (:login handlers)
                     :post (:process-login handlers)}]
              ["/logout" {:get (:logout handlers)}]]
             wrap-cookies)])))
  (stop [this] this)

  WebService
  (ring-handler-map [this] (:handlers this))
  (routes [this] (:routes this))
  (uri-context [this] uri-context))

(def new-login-form-schema
  {(s/optional-key :context) s/Str
   (s/optional-key :boilerplate) (s/=> 1)})

(defn new-login-form [& {:as opts}]
  (let [{:keys [context boilerplate]}
        (->> opts
             (merge {:context ""
                     :boilerplate #(html [:body %])})
             (s/validate new-login-form-schema))]
    (component/using (->LoginForm context boilerplate) [:user-authenticator :http-session-store])))
