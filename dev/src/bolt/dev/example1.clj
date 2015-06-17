(ns bolt.dev.example1
  (:require
   [clojure.pprint :refer (pprint)]
   [clojure.tools.logging :refer :all]
   [bidi.bidi :refer (RouteProvider tag)]
   [bidi.ring :refer (redirect)]
   [com.stuartsierra.component :refer (using Lifecycle)]
   [bolt.user.protocols :refer (LoginFormRenderer UserFormRenderer)]
   [bolt.session :refer (session)]
   [bolt.session.protocols :refer (SessionStore)]
   [bolt.user.protocols :refer (UserStore UserPasswordHasher)]
   [bolt.user :refer (create-user! hash-password)]
   [modular.bidi :refer (as-request-handler path-for)]
   [modular.component.co-dependency :refer (co-using)]
   [modular.template :as template :refer (render-template template-model Templater TemplateModel)]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [schema.core :as s]
   [schema.utils :refer [class-schema]]
   [hiccup.core :refer (html)]
   [bolt.dev.view :refer (page-body page)]))

(s/defrecord Example
    [kns :- s/Str
     templater :- (s/protocol Templater)
     session-store :- (s/protocol SessionStore)
     user-store :- (s/protocol UserStore)
     password-hasher :- (s/protocol UserPasswordHasher)
     uri-context :- String

     ;; Co-dependencies
     *template-model
     *router]

  Lifecycle
  (start [component]
         (s/validate (class-schema (type component)) component)

         ;; Add some users
         (println "Create alice"
                  (create-user!
                   user-store {:email "alice@example.org"
                               :password (hash-password password-hasher "wonderland")
                               :roles #{:superuser}}))
         (println "Create bob"
                  (create-user!
                   user-store {:email "bob@example.org"
                               :password (hash-password password-hasher "bob")
                               :roles #{:user}}))
         component)

  (stop [component] component)

  RouteProvider
  (routes [_]
          [(str uri-context)
           {"/index.html"
            (-> (page "templates/example1/index.html.mustache" templater *template-model *router session-store)
                (tag (keyword kns "index")))
            "/protected.html"
            (-> (page "templates/example1/protected.html.mustache" templater *template-model *router session-store)
                (tag (keyword kns "protected")))
            "" (redirect (keyword kns "index"))
            "/" (redirect (keyword kns "index"))}])

  UserFormRenderer
  (render-signup-form
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
         (when-let [path (path-for @*router :bolt.user.login/login-form)]
           (str path "?post_login_redirect=" (path-for @*router (keyword kns "index"))))
         logout-href
         (when-let [path (path-for @*router :bolt.user.login/logout)]
           (str path "?post_logout_redirect=" (path-for @*router (keyword kns "index"))))]

     (assert login-href "No href to login. Check system dependencies.")
     (assert logout-href "No href to logout. Check system dependencies.")

     {:menu []
      :login-href login-href
      :logout-href logout-href
      })))

(defn new-example [& {:as args}]
  (->
   (->> args
        (merge {})
        (s/validate {:uri-context s/Str :kns s/Str})
        (map->Example))
   (using [:templater :session-store :user-store])
   (co-using [:router :template-model])))
