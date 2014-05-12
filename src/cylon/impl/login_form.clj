;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.login-form
  (:require
   [com.stuartsierra.component :as component]
   [bidi.bidi :refer (path-for ->WrapMiddleware)]
   [hiccup.core :refer (html)]
   [schema.core :as s]
   [clojure.tools.logging :refer :all]
   [ring.middleware.cookies :refer (wrap-cookies)]
   [cylon.user :refer (UserDomain verify-user)]
   [cylon.session :refer (SessionStore start-session! end-session!)]
   [ring.middleware.params :refer (wrap-params)]
   [modular.bidi :refer (WebService)]))

(defn new-login-get-handler [& {:keys [boilerplate] :as opts}]
  (fn [{{{requested-uri :value} "requested-uri"} :cookies
        routes :modular.bidi/routes}]
    (let [form
          [:form {:method "POST" :style "border: 1px dotted #555"
                  :action (path-for routes ::process-login)}
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

(defn new-login-post-handler [& {:keys [user-domain session-store] :as opts}]
  (s/validate {:user-domain (s/protocol UserDomain)
               :session-store (s/protocol SessionStore)}
              opts)
  (fn [{{username "username" password "password" requested-uri "requested-uri"} :form-params
        routes :modular.bidi/routes}]

    ;; Check password
    (debugf "Checking username: %s" username)
    (debugf "Checking password: %s" password)
    (debugf "user-domain is %s" user-domain)

    (if (and username
             (not-empty username)
             (verify-user user-domain (.trim username) password))

      {:status 302
       :headers {"Location" (or requested-uri "/")} ; "/" can be parameterized (TODO)
       :cookies {"session" (start-session! session-store username)
                 "requested-uri" ""}}

      ;; Return back to login form
      {:status 302
       :headers {"Location" (path-for routes ::login)}})))


(defn new-logout-handler [session-store]
  (fn [{:keys [cookies]}]
    (end-session!
     session-store
     (:value (get cookies "session")))
    {:status 302 :headers {"Location" "/"}}))

(defrecord LoginForm [uri-context boilerplate]
  WebService
  (ring-handler-map [this]
    {::login (-> (apply new-login-get-handler (apply concat (seq (select-keys this [:boilerplate]))))
                 wrap-cookies)
     ::process-login (-> (apply new-login-post-handler
                                (apply concat (seq (select-keys this [:user-domain :session-store]))))
                         wrap-params wrap-cookies)
     ::logout (-> (new-logout-handler (:session-store this))
                  wrap-cookies)})
  (routes [this]
    ["" { "/login" {:get ::login :post ::process-login}
          "/logout" {:get ::logout}}])

  (uri-context [this] uri-context))

(def new-login-form-schema
  {(s/optional-key :uri-context) s/Str
   (s/optional-key :boilerplate) (s/=> 1)})

(defn new-login-form [& {:as opts}]
  (component/using
   (->> opts
        (merge {:uri-context ""
                :boilerplate #(html [:body %])})
        (s/validate new-login-form-schema)
        map->LoginForm)
   [:user-domain :session-store]))
