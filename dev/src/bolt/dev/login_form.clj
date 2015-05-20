(ns bolt.dev.login-form
  (:require
   [bolt.user.protocols :refer (LoginFormRenderer)]
   [bolt.dev.view :refer (page-body)]
   [modular.template :refer (template-model)]
   [hiccup.core :refer (html)]
   [modular.bidi :refer (path-for)]
   [com.stuartsierra.component :refer (using)]
   [modular.component.co-dependency :refer (co-using)]))

(defrecord LoginForm [templater *template-model *router]
  LoginFormRenderer
  (render-login-form [component req model]
    (page-body
     templater "templates/example1/dialog.html.mustache"
     (merge (template-model @*template-model req)
            {:title (:title model)
             :form
             (html
              (when (:login-failed? model)
                [:div.alert.alert-danger.alert-dismissible
                 {:role "alert"}
                 [:button.close {:type "button" :data-dismiss "alert" :aria-label "Close"}
                  [:span {:aria-hidden "true"} "&times;"]
                  ]
                 "You have entered an unrecognised email address or incorrect password."]
                )
              [:form {:action (-> model :form :action)
                      :method (-> model :form :method)}
               (when-let [redirect (:post-login-redirect model)]
                 [:input {:type :hidden :name "post_login_redirect" :value redirect}]
                 )
               [:div
                [:label {:for "email"} "Email"]
                ;; We must have
                [:input#email {:type :text :name "user"}]]
               [:div
                [:label {:for "password"} "Password"]
                [:input#password {:type :password :name "password"}]
                (when-let [href nil]
                  [:a {:href href} "Forgot password"])]
               [:div
                [:input.submit {:type "submit" :value "Sign in"}]
                ;; If we can't find a path to the signup form, we deduce
                ;; that no signup functionality exists. This is the
                ;; feature toggle.
                (when-let [signup (path-for @*router :bolt.user.signup/GET-signup-form)]
                  [:a {:href signup } "Sign up"])]

               ])})))
  )

(defn new-login-form [& {:as args}]
  (->
   (->> args
        (merge {})
        map->LoginForm)
   (using [:templater])
   (co-using [:template-model :router])))
