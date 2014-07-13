;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.login-form
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [schema.core :as s]
   [ring.middleware.cookies :refer (wrap-cookies)]
   [ring.middleware.params :refer (wrap-params)]
   [hiccup.core :refer (html)]
   [bidi.bidi :refer (path-for ->WrapMiddleware)]
   [modular.bidi :refer (WebService)]
   [cylon.user :refer (UserDomain verify-user)]
   [cylon.session :refer (SessionStore create-session! purge-session! ->cookie)]))

(defprotocol LoginFormRenderer
  (render-login-form [_ request attrs]))

(defrecord PlainLoginFormRenderer []
  LoginFormRenderer
  (render-login-form [_ request {:keys [requested-uri action login-status fields]}]
    (html
     [:div
      [:form {:method "POST"
              :style "border: 1px dotted #555; padding: 10pt"
              :action action}

       [:h2 "Please sign in"]

       (when login-status
         [:div
          [:p
           (case login-status
             :failed [:span [:strong "Failed: "] "Please check login credentials and try again or " [:a.alert-link {:href "#"} "reset your password"] "."])]])

       (for [{:keys [id label name type value placeholder required autofocus]} fields]
         [:div
          [:label {:for id} label]
          [:input (merge
                   {:name name :type type :value value}
                   (when placeholder {:placeholder placeholder})
                   (when required {:required required})
                   (when autofocus {:autofocus autofocus}))]])

       (when (not-empty requested-uri)
         [:input {:type "hidden" :name :requested-uri :value requested-uri}])

       [:input {:type "submit" :value "Sign in"}]

       [:p
        [:a {:href "#"} "Reset password"]]
       ]])))

(defn new-plain-login-form-renderer []
  (->PlainLoginFormRenderer))

;; TODO Because we're using email, not username - need to make this configurable.

(defn new-login-post-handler [& {:keys [user-domain session-store identity-field] :as opts}]
  (s/validate {:user-domain (s/protocol UserDomain)
               :session-store (s/protocol SessionStore)
               :identity-field s/Str}
              opts)
  (fn [{params :form-params
        routes :modular.bidi/routes}]

    (let [identity (get params identity-field)
          password (get params "password")]

      (if (and identity
               (not-empty identity)
               (verify-user user-domain (.trim identity) password))

        (do
          (println (->cookie (create-session! session-store {:cylon/identity identity})))

          {:status 302
           :headers {"Location" (or (get params "requested-uri") "/")} ; "/" can be parameterized (TODO)
           :cookies {"session-id" (->cookie (create-session! session-store {:cylon/identity identity}))
                     "requested-uri" ""}})

        ;; Return back to login form
        {:status 302
         :headers {"Location" (path-for routes :login)}
         :cookies (merge {"login-status" "failed"}
                         (when identity {identity-field identity}))}))))

(defn new-logout-handler [session-store]
  (fn [{:keys [cookies]}]
    (purge-session! session-store (:value (get cookies "session-id")))
    {:status 302 :headers {"Location" "/"}}))

(defrecord LoginForm [uri-context renderer middleware fields identity-field]
  WebService
  (request-handlers [this]
    {:login
     (let [f (fn [{{{requested-uri :value} "requested-uri"
                    {login-status :value} "login-status"
                    {identity-value :value} "identity"} :cookies
                    routes :modular.bidi/routes :as request}]
               {:status 200
                :body (render-login-form
                       renderer
                       request
                       (merge
                        {:action (path-for routes :process-login)
                         :fields (if identity-value
                                   (->> fields
                                        (map #(if (= (:name %) identity-field) (assoc % :value identity-value) %))
                                        (map #(if (= (:name %) "password") (assoc % :autofocus true) %)))
                                   (->> fields
                                        (map #(if (= (:name %) identity-field) (assoc % :autofocus true) %))))}
                        (when (not-empty requested-uri) {:requested-uri requested-uri})
                        (when (not-empty login-status) {:login-status (keyword login-status)})))
                :cookies {"login-status" ""
                          "identity" ""}})]
       (wrap-cookies (if middleware (middleware f) f)))

     :process-login
     (-> (apply new-login-post-handler
                (apply concat (seq (select-keys this [:user-domain :session-store :identity-field]))))
         wrap-params wrap-cookies)

     :logout
     (-> (new-logout-handler (:session-store this))
         wrap-cookies)})

  (routes [this]
    ["" {"/login" {:get :login, :post :process-login}
         "/logout" {:get :logout}}])

  (uri-context [this] uri-context))

(def new-login-form-schema
  {(s/optional-key :uri-context) s/Str
   (s/optional-key :renderer) (s/protocol LoginFormRenderer)
   (s/optional-key :middleware) (s/=> 1)
   (s/required-key :identity-field) s/Str
   (s/required-key :fields) [{(s/optional-key :id) s/Str
                              (s/required-key :name) s/Str
                              (s/required-key :type) s/Str
                              (s/optional-key :label) s/Str
                              (s/optional-key :placeholder) s/Str
                              (s/optional-key :required) s/Bool}]})

(defn new-login-form [& {:as opts}]
  (component/using
   (->> opts
        (merge {:uri-context ""
                ;; If you don't provide a renderer, one will be provided for you
                :renderer (->PlainLoginFormRenderer)
                :fields
                [{:id "username" :name "username" :type "input" :label "Username"}
                 {:id "password" :name "password" :type "password" :label "Password"}]
                :identity-field "username"})
        (s/validate new-login-form-schema)
        map->LoginForm)
   [:user-domain :session-store]))
