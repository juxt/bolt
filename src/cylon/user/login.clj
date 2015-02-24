;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.user.login
  (:require
   [clojure.tools.logging :refer :all]
   [cylon.user.protocols :as p]
   [cylon.authentication.protocols :refer (RequestAuthenticator AuthenticationHandshake)]
   [cylon.password :refer (verify-password)]
   [cylon.password.protocols :refer (PasswordVerifier)]
   [cylon.session :refer (session assoc-session-data! respond-with-new-session!)]
   [cylon.session.protocols :refer (SessionStore)]
   [cylon.user :refer (get-user-by-email FormField render-login-form)]
   [cylon.util :refer (as-query-string uri-with-qs Request wrap-schema-validation)]
   [bidi.bidi :refer (path-for)]
   [modular.bidi :refer (WebService)]
   [ring.util.response :refer (redirect redirect-after-post)]
   [ring.middleware.params :refer (params-request)]
   [plumbing.core :refer (<-)]
   [com.stuartsierra.component :refer (Lifecycle using)]
   [schema.core :as s]

   [tangrammer.component.co-dependency :refer (co-using)])
  (:import (java.net URLEncoder))
  )

(defrecord Login [user-store session-store renderer password-verifier fields uri-context router]
  Lifecycle
  (start [component]
    (s/validate
     {:session-store (s/protocol SessionStore)
      :renderer (s/protocol p/LoginFormRenderer)
      :password-verifier (s/protocol PasswordVerifier)
      :user-store (s/protocol p/UserStore)
      :fields [FormField]
      :uri-context s/Str
      :router s/Any ;; you can't get specific protocol of a codependency in start time
      }
     component))
  (stop [component] component)

  AuthenticationHandshake
  (initiate-authentication-handshake [this req]
    (assert (:routes @router))
    (if-let [p (path-for (:routes @router) ::login-form)]
      (let [loc (str p (as-query-string {"post_login_redirect" (URLEncoder/encode (uri-with-qs req))}))]
        (debugf "Redirecting to %s" loc)
        (redirect loc))
      (throw (ex-info "No path to login form" {}))))

  RequestAuthenticator
  (authenticate [this req]
    (session session-store req))

  WebService
  (request-handlers [this]
    {::login-form
     (->
      (fn [req]
        (let [qparams (-> req params-request :query-params)
              response
              {:status 200
               :body (render-login-form
                      renderer req
                      {:form {:method :post
                              :action (path-for (:routes @router) ::process-login-attempt)
                              :fields (conj fields {:name "post_login_redirect" :value (get qparams "post_login_redirect") :type "hidden"})}
                       :login-failed? (Boolean/valueOf (get qparams "login_failed"))})}]
          response))
      wrap-schema-validation)

     ::process-login-attempt
     (->
      (fn [req]
        (let [params (-> req params-request :form-params)
              uid (get params "user")
              password (get params "password")
              session (session session-store req)
              post-login-redirect (get params "post_login_redirect")]

          (debugf "Form params posted to login form are %s" params)

          (if (and uid (not-empty uid))
            ;; checking uid email based
            (if-let [uid (or (and (.contains uid "@") (:uid (get-user-by-email user-store uid))) (.trim uid))]
              (if  (verify-password password-verifier uid password)
                ;; Login successful!
                (do
                  (debugf "Login successful!")
                  (respond-with-new-session!
                   session-store req
                   {:cylon/subject-identifier uid}
                   (if post-login-redirect
                     (redirect-after-post post-login-redirect)
                     {:status 200 :body "Login successful"})))

                ;; Login failed!
                (do
                  (debugf "Login failed!")

                  ;; TODO I think the best thing to do here is to create a
                  ;; session anyway - we have been posted after all. We can
                  ;; store in the session things like number of failed
                  ;; attempts (to attempt to prevent brute-force hacking
                  ;; attempts by limiting the number of sessions that can be
                  ;; used by each remote IP address). If we do this, then the
                  ;; post_login_redirect must be ascertained from the
                  ;; query-params, and then from the session.

                  (redirect-after-post
                   (str (path-for (:routes @router) ::login-form)
                        ;; We must be careful to add back the query string
                        (as-query-string
                         (merge
                          (when post-login-redirect
                            {"post_login_redirect" (URLEncoder/encode post-login-redirect)})
                          ;; Add a login_failed to help with indicating the failure to the user.
                          {"login_failed" true}
                          ))))))))))
      wrap-schema-validation)})


  (routes [this]
    ["" {"/login" {:get ::login-form
                   :post ::process-login-attempt}}])

  (uri-context [this] uri-context))

(defn new-login [& {:as opts}]
  (->> opts
       (merge {:fields [{:name "user" :label "User" :type "text" :placeholder "id or email"}
                        {:name "password" :label "Password" :type "password" :placeholder "password"}]
               :uri-context ""})
       (s/validate {:fields [FormField]
                    :uri-context s/Str})
       map->Login
       (<- (using [:password-verifier :session-store :renderer :user-store]))
       (<- (co-using [:router]))
       ))
