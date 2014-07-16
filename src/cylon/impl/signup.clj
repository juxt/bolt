(ns cylon.impl.signup
  (:require
   [com.stuartsierra.component :as component]
   [modular.bidi :refer (WebService)]
   [hiccup.core :refer (html)]
   [ring.middleware.params :refer (wrap-params)]
   [cylon.user :refer (add-user!)]
   [cylon.totp :as totp]
   [cylon.totp :refer (OneTimePasswordStore set-totp-secret)]
   [schema.core :as s ]))

(defrecord Signup [appname]
  WebService
  (request-handlers [this]
    {::signup-form
     (fn [req]
       {:status 200
        :body (html
               [:div
                [:h1 "Signup"]
                [:form {:method :post}
                 [:p
                  [:label {:for "user"} "User"]
                  [:input {:name "user" :id "user" :type "text"}]]
                 [:p
                  [:label {:for "name"} "Name"]
                  [:input {:name "name" :id "name" :type "text"}]]
                 [:p
                  [:label {:for "email"} "Email"]
                  [:input {:name "email" :id "email" :type "text"}]]
                 [:p
                  [:label {:for "password"} "Password"]
                  [:input {:name "password" :id "password" :type "password"}]]
                 [:p [:input {:type "submit"}]]

                 ]])})

     ::process-signup
     (->
      (fn [req]
        (let [identity (get (:form-params req) "user")
              password (get (:form-params req) "password")
              totp-secret (when (satisfies? OneTimePasswordStore (:user-domain this))
                            (totp/secret-key))]
          (add-user! (:user-domain this) identity password
                     {:name (get (:form-params req) "name")
                      :email (get (:form-params req) "email")})

          (when (satisfies? OneTimePasswordStore (:user-domain this))
            (set-totp-secret (:user-domain this) identity totp-secret password)
            )

          {:status 200 :body
           (html
            [:div
             [:p (format "Thank you for signing up %s!"  (get (:form-params req) "name"))]
             (when (satisfies? OneTimePasswordStore (:user-domain this))
               [:div
                [:p "Please scan this image into your 2-factor authentication application"]
                [:img {:src (totp/qr-code (format "%s@%s" identity appname) totp-secret)}]
                [:p "Alternatively, type in this secret into your authenticator application: " [:code totp-secret]]
                ])
             ]
            )}))

      wrap-params)})

  (routes [this]
    ["/signup" {:get ::signup-form
                :post ::process-signup}])

  (uri-context [this] ""))


(defn new-signup [& {:as opts}]
  (component/using
   (->> opts
        (merge {:appname "cylon"})
        (s/validate {:appname s/Str})
        map->Signup)
   [:user-domain]))
