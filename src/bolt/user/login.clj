;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns bolt.user.login
  (:require
   [clojure.tools.logging :refer :all]
   [clojure.string :as string]
   [bolt.user.protocols :as p]
   [bolt.authentication.protocols :refer (RequestAuthenticator AuthenticationHandshake)]
   [bolt.session :refer (start-session! stop-session! session-data)]
   [bolt.session.protocols :refer (SessionLifecycle SessionData)]
   [bolt.user :refer (find-user authenticate-user)]
   [bolt.util :refer (as-query-string uri-with-qs Request wrap-schema-validation keywordize-form)]
   [bidi.bidi :refer (RouteProvider tag)]
   [modular.bidi :refer (path-for)]
   [ring.util.response :refer (redirect redirect-after-post)]
   [ring.middleware.params :refer (params-request)]
   [plumbing.core :refer (<-)]
   [com.stuartsierra.component :refer (Lifecycle using)]
   [schema.core :as s]
   [yada.yada :refer (yada)]
   [modular.component.co-dependency :refer (co-using)]
   [modular.component.co-dependency.schema :refer (co-dep)])
  (:import [java.net URLEncoder]
           [modular.bidi Router]))

(defn email? [s]
  (re-matches #".+@.+" s))

(s/defrecord Login
    [user-store :- (s/protocol p/UserStore)
     user-authenticator :- (s/protocol p/UserAuthenticator)
     session :- (s/both (s/protocol SessionData) (s/protocol SessionLifecycle))
     uri-context :- s/Str
     tag-ns :- s/Str
     *router :- (co-dep Router)]

  AuthenticationHandshake
  (initiate-authentication-handshake [component req]
                                     (assert (:routes @*router))
                                     (if-let [p (path-for @*router (keyword tag-ns "login-form"))]
                                       (let [loc (str p (as-query-string {"post_login_redirect" (URLEncoder/encode (uri-with-qs req))}))]
                                         (debugf "Redirecting to %s" loc)
                                         (redirect loc))
                                       (throw (ex-info "No path to login form" {}))))

  RequestAuthenticator
  (authenticate [component req]
                (session-data session req))

  RouteProvider
  (routes [component]
          [uri-context
           {"/login"
            {#_:get
             #_(->
                (fn [req]
                  (let [qparams (-> req params-request :query-params)
                        post-login-redirect (get qparams "post_login_redirect")]

                    {:status 200
                     :body (render-login-form
                            renderer req
                            (merge
                             {:form (merge {:method :post
                                            :action (path-for @*router (keyword tag-ns "process-login-attempt"))})
                              :login-failed? (Boolean/valueOf (get qparams "login_failed"))}
                             (when post-login-redirect {:post-login-redirect post-login-redirect})))}))
                wrap-schema-validation
                (tag (keyword tag-ns "login-form")))

             :post
             (->
              (yada nil
                    :parameters {:post {:query {(s/optional-key :redirect) s/Str}
                                        :form {(s/required-key :identity) s/Str
                                               (s/required-key :password) s/Str
                                               s/Keyword s/Str}}}
                    :post! (fn [{{:keys [redirect identity password] :as parameters} :parameters
                                :as ctx}]
                             (let [user (find-user user-store identity)
                                   authentication (when user (authenticate-user user-authenticator user {:password password}))]
                               (if (and user authentication)
                                 (start-session!
                                  session
                                  (if redirect
                                    (redirect-after-post redirect)
                                    {:status 200 :body "Login successful"})
                                  {:bolt/user user
                                   ;; It might be useful to store the results of the
                                   ;; authentication (which could be signed)
                                   :bolt/authentication authentication})))))


              #_(fn [req]
                  (let [form (-> req params-request :form-params)
                        _ (infof "Form is %s" form)
                        id (some-> (get form "identity") string/trim)
                        _ (infof "id is %s" id)
                        _ (when (nil? id) (throw (ex-info "Form must contain 'identity'" {})))
                        password (get form :password)
                        post-login-redirect (get form :post-login-redirect)

                        ;;session (session-data session req)
                        user (find-user user-store id)
                        authentication (when user (authenticate-user user-authenticator user {:password password}))]

                    (if (and user authentication)
                      ;; Login successful!
                      (do
                        (debugf "Login successful!")
                        (start-session!
                         session
                         (if post-login-redirect
                           (redirect-after-post post-login-redirect)
                           {:status 200 :body "Login successful"})
                         {:bolt/user user
                          ;; It might be useful to store the results of the
                          ;; authentication (which could be signed)
                          :bolt/authentication authentication}
                         ))

                      ;; Login failed!
                      (redirect-after-post
                       (str (path-for @*router (keyword tag-ns "login-form"))
                            ;; We must be careful to add back the query string
                            (as-query-string
                             (merge
                              (when post-login-redirect
                                {"post_login_redirect" (URLEncoder/encode post-login-redirect)})
                              ;; Add a login_failed to help with indicating the failure to the user.
                              {"login_failed" true}
                              )))))))
              wrap-schema-validation
              (tag (keyword tag-ns "login"))
              )}

            "/logout"
            {:post

             (->
              (yada nil
                    :parameters {:post {:query {(s/optional-key :redirect) s/Str}}}

                    :post! (fn [{{:keys [redirect] :as parameters} :parameters
                                req :request
                                :as ctx}]
                             (let [response (if redirect
                                              (redirect-after-post redirect)
                                              {:status 200 :body "Logout successful"})]
                               (stop-session! session response (session-data session req)))))

              wrap-schema-validation
              (tag (keyword tag-ns "logout"))
              )}
            }]))

(defn new-login [& {:as opts}]
  (->> opts
       (merge {:uri-context ""
               :tag-ns "bolt.user.login"})
       map->Login
       (<- (using [:user-store :user-authenticator :session]))
       (<- (co-using [:router]))))
