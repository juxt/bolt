;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns bolt.user.login
  (:require
   [clojure.tools.logging :refer :all]
   [clojure.string :as string]
   [bolt.user.protocols :as p]
   [bolt.authentication.protocols :refer (RequestAuthenticator AuthenticationHandshake)]
   ;;[bolt.session :refer (session assoc-session-data! respond-with-new-session! respond-close-session!)]
   [bolt.session :refer (start-session! stop-session! session-data)]
   ;;[bolt.session.protocols :refer (SessionStore)]
   [bolt.session.protocols :refer (SessionLifecycle SessionData)]
   [bolt.user :refer (find-user render-login-form authenticate-user)]
   [bolt.util :refer (as-query-string uri-with-qs Request wrap-schema-validation keywordize-form)]
   [bidi.bidi :refer (RouteProvider tag)]
   [modular.bidi :refer (path-for)]
   [ring.util.response :refer (redirect redirect-after-post)]
   [ring.middleware.params :refer (params-request)]
   [plumbing.core :refer (<-)]
   [com.stuartsierra.component :refer (Lifecycle using)]
   [schema.core :as s]
   bolt.schema
   [modular.component.co-dependency :refer (co-using)])
  (:import [java.net URLEncoder]
           [modular.bidi Router]))

(defn email? [s]
  (re-matches #".+@.+" s))

(s/defrecord Login
    [user-store :- (s/protocol p/UserStore)
     user-authenticator :- (s/protocol p/UserAuthenticator)
     session :- (s/both (s/protocol SessionData) (s/protocol SessionLifecycle))
     renderer :- (s/protocol p/LoginFormRenderer)
     uri-context :- s/Str
     tag-ns :- s/Str
     *router :- (bolt.schema/co-dep Router)]

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
     ;; Author's note: In retrospect perhaps it is better for Bolt NOT
     ;; to provide a login-form + pluggable renderer and instead insist
     ;; the user provide one. The user can provide one that posts to the
     ;; POST handler, which is the primary purpose of this
     ;; component. TODO: Break up this design.
     {"/login"
      {:get
       (->
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
        (tag (keyword tag-ns "login-form"))
        )

       :post
       (->
        (fn [req]
          (let [form (-> req params-request :form-params keywordize-form)
                _ (infof "Form is %s" form)
                id (some-> (get form :user) string/trim)
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
        (tag (keyword tag-ns "process-login-attempt"))
        )}

      "/logout"
      {:get
       (->
        (fn [req]
          (let [qparams (-> req params-request :query-params)
                post-logout-redirect (get qparams "post_logout_redirect")]
            (stop-session! session (redirect post-logout-redirect) (session-data session req))))
        wrap-schema-validation
        (tag (keyword tag-ns "logout"))
        )}
      }]))

(defn new-login [& {:as opts}]
  (->> opts
       (merge {:uri-context ""
               :tag-ns (str *ns*)})
       map->Login
       (<- (using [:user-store :user-authenticator :session :renderer]))
       (<- (co-using [:router]))))
