(ns bolt.dev.example1
  (:require
   [clojure.pprint :refer (pprint)]
   [clojure.tools.logging :refer :all]
   [bidi.bidi :refer (RouteProvider tag)]
   [bidi.ring :refer (redirect)]
   [com.stuartsierra.component :refer (using Lifecycle)]
   [bolt.session :refer (session)]
   [bolt.session.protocols :refer (SessionData SessionLifecycle)]
   [modular.bidi :refer (as-request-handler path-for)]
   [modular.component.co-dependency :refer (co-using)]
   [modular.component.co-dependency.schema :refer (co-dep)]
   [modular.template :as template :refer (render-template template-model Templater TemplateModel)]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [schema.core :as s]
   [schema.utils :refer [class-schema]]
   [hiccup.core :refer (html)]
   [bolt.dev.view :refer (page-body page)]
   [yada.yada :refer [yada]])
  (:import [modular.bidi Router]))

(s/defrecord Example
    [title :- s/Str
     tag-ns :- s/Str
     templater :- (s/protocol Templater)
     session :- (s/both (s/protocol SessionData) (s/protocol SessionLifecycle))
     uri-context :- s/Str
     *router :- (co-dep Router)]

  RouteProvider
  (routes [_]
          [(str uri-context)
           {"/index.html"
            (-> (page "templates/example1/index.html.mustache"
                      templater {:title title
                                 ;; TODO: This link does NOT work because *router is not yet delivered
                                 :links {:login {:href (path-for @*router (keyword tag-ns "login-form"))}}}
                      *router session)
                (tag (keyword tag-ns "index")))

            "/login.html"
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
                yada
                (tag (keyword tag-ns "login-form")))

            "/signup.html"
            (-> (page "templates/dialog.html.mustache" templater {} *router session)
                (tag (keyword tag-ns "signup")))

            "" (redirect (keyword tag-ns "index"))
            "/" (redirect (keyword tag-ns "index"))}])

  #_(render-signup-form
     [component req model]
     (page-body
      templater "templates/dialog.html.mustache"
      (merge (template/template-model @*template-model req)
             {:title (:title model)
              :form
              (html
               [:form {:action (-> model :form :action)
                       :method (-> model :form :method)}
                ;; Hidden fields
                (for [{:keys [name value type]} (-> model :form :fields)
                      :when (= type "hidden")]
                  [:input {:type type :name name :value value}])
                [:div
                 [:label {:for "email"} "Email"]
                 [:input#email {:type :text :name "user"}]]
                [:div
                 [:label {:for "password"} "Password"]
                 [:input#password {:type :password :name "password"}]]
                [:div
                 [:input.submit {:type "submit" :value "Sign up"}]
                 ]])})))

  TemplateModel
  (template-model
   [component req]
   (let [login-href
         (when-let [path (path-for @*router (keyword tag-ns "login-form"))]
           (str path "?post_login_redirect=" (path-for @*router (keyword tag-ns "index"))))
         logout-href
         (when-let [path (path-for @*router (keyword tag-ns "logout"))]
           (str path "?post_logout_redirect=" (path-for @*router (keyword tag-ns "index"))))]

     (assert login-href "No href to login. Check system dependencies.")
     (assert logout-href "No href to logout. Check system dependencies.")

     {:title title
      :menu []
      :login-href login-href
      :logout-href logout-href
      :links [{:label "Home" :href (path-for @*router :bolt.dev.website/index)}
              {:label "User Guide" :href (path-for @*router :bolt.dev.user-guide/user-guide)}]


      })))

(defn new-example [& {:as args}]
  (->
   (map->Example (merge {} args))
   (using [:templater :session])
   (co-using [:router])))
