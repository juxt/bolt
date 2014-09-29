;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.authentication.login
  (:require
   [clojure.tools.logging :refer :all]
   [cylon.authentication.protocols :refer (AuthenticationInteraction)]
   [cylon.password :refer (verify-password)]
   [cylon.password.protocols :refer (PasswordVerifier)]
   [cylon.session :refer (session assoc-session-data! respond-with-new-session!)]
   [cylon.session.protocols :refer (SessionStore)]
   [cylon.util :refer (as-query-string uri-with-qs Request)]
   [modular.bidi :refer (WebService path-for)]
   [ring.util.response :refer (redirect redirect-after-post)]
   [ring.middleware.params :refer (params-request)]
   [plumbing.core :refer (<-)]
   [com.stuartsierra.component :refer (Lifecycle using)]
   [schema.core :as s])
  (:import (java.net URLEncoder))
  )

(defprotocol LoginFormRenderer
  (render-login-form [_ req model]))

(def field-schema
  {:name s/Str
   :label s/Str
   (s/optional-key :placeholder) s/Str
   (s/optional-key :password?) s/Bool})

(def new-login-schema {:fields [field-schema]})

(s/defn render-login-form+ :- s/Str
  [component :- (s/protocol LoginFormRenderer)
   req :- Request
   model :- {:form {:method s/Keyword
                    :action s/Str
                    (s/optional-key :signup-uri) s/Str
                    (s/optional-key :post-login-redirect) s/Str
                    :fields [field-schema]}}]
  (render-login-form component req model))

(defrecord Login [session-store renderer password-verifier fields]
  Lifecycle
  (start [component]
    (s/validate
     (merge new-login-schema
            {:session-store (s/protocol SessionStore)
             :renderer (s/protocol LoginFormRenderer)
             :password-verifier (s/protocol PasswordVerifier)
             }) component))
  (stop [component] component)

  AuthenticationInteraction
  (initiate-authentication-interaction [this req]
    (if-let [p (path-for req ::login-form)]
      (let [loc (str p (as-query-string {"post_login_redirect" (URLEncoder/encode (uri-with-qs req))} ))]
        (debugf "Redirecting to %s" loc)
        (redirect loc))
      (throw (ex-info "No path to login form" {}))))

  (get-outcome [this req]
    (session session-store req))

  WebService
  (request-handlers [this]
    {::login-form
     (fn [req]
       (let [qparams (-> req params-request :query-params)
             response
             {:status 200
              :body (render-login-form+
                     renderer req
                     {:form {:method :post
                             :action (path-for req ::process-login-attempt)
                             :signup-uri (path-for req :cylon.signup.signup/GET-signup-form)
                             :post-login-redirect (get qparams "post_login_redirect")
                             :fields fields}})}]
         response))

     ::process-login-attempt
     (fn [req]
       (let [params (-> req params-request :form-params)
             uid (get params "user")
             password (get params "password")
             session (session session-store req)]

         (debugf "Form params posted to login form are %s" params)

         (if (and uid (not-empty uid)
                  (verify-password password-verifier (.trim uid) password))

           ;; Login successful!
           (respond-with-new-session!
            session-store req
            {:cylon/subject-identifier uid}
            (if-let [post-login-redirect (get params "post_login_redirect")]
              (redirect-after-post post-login-redirect)
              {:status 200 :body "Login successful"}))

           ;; Login failed!
           (redirect (path-for req ::login-form)))))})

  (routes [this]
    ["" {"/login" {:get ::login-form
                   :post ::process-login-attempt}}])

  (uri-context [this] ""))



(defn new-login [& {:as opts}]
  (->> opts
       (merge {:fields [{:name "user" :label "User" :placeholder "id or email"}
                        {:name "password" :label "Password" :password? true :placeholder "password"}]})
       (s/validate new-login-schema)
       map->Login
       (<- (using [:password-verifier :session-store :renderer]))))
