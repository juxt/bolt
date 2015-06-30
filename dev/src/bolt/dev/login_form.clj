(ns bolt.dev.login-form
  (:require
   [bolt.dev.view :refer (page-body)]
   [modular.template :refer (template-model)]
   [hiccup.core :refer (html)]
   [modular.bidi :refer (path-for)]
   [bidi.bidi :refer (RouteProvider tag)]
   [com.stuartsierra.component :refer (using)]
   [modular.component.co-dependency :refer (co-using)]
   [yada.yada :refer (yada)]))

(defrecord LoginForm [templater *router]
  RouteProvider
  (routes [_]
    ["/"
     {"login"
      (-> (page-body
           templater "templates/example1/dialog.html.mustache"
           {:title "Login"
            :form
            (html
             #_(when (:login-failed? model)
                 [:div.alert.alert-danger.alert-dismissible
                  {:role "alert"}
                  [:button.close {:type "button" :data-dismiss "alert" :aria-label "Close"}
                   [:span {:aria-hidden "true"} "&times;"]
                   ]
                  "You have entered an unrecognised email address or incorrect password."]
                 )
             [:form {#_:action #_(-> model :form :action)
                     #_:method #_(-> model :form :method)}
              #_(when-let [redirect (:post-login-redirect model)]
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

              ])})
          yada (tag ::login-form))}])

  )

(defn new-login-form [& {:as args}]
  (->
   (->> args
        (merge {})
        map->LoginForm)
   (using [:templater])
   (co-using [:router])))
