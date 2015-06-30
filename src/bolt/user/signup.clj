;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns bolt.user.signup
  (:require
   [bidi.bidi :refer (RouteProvider tag)]
   [clojure.tools.logging :refer :all]
   [bolt.util :refer (absolute-prefix as-query-string wrap-schema-validation keywordize-form)]
   [bolt.session :refer (session-data start-session!)]
   [bolt.session.protocols :refer (SessionData SessionLifecycle)]
   [bolt.token-store :refer (create-token! get-token-by-id)]
   [bolt.token-store.protocols :refer (TokenStore)]
   [com.stuartsierra.component :as component :refer (Lifecycle using)]
   [modular.bidi :refer (path-for)]
   [hiccup.core :refer (html)]
   [ring.middleware.params :refer (params-request)]
   [ring.middleware.cookies :refer (cookies-response wrap-cookies)]
   [ring.util.response :refer (response redirect redirect-after-post)]
   [bolt.user :refer (create-user! verify-email! hash-password)]
   [bolt.user.protocols :refer (UserStore UserPasswordHasher UserAuthenticator)]
   [schema.core :as s]
   [plumbing.core :refer (<-)]
   [modular.component.co-dependency :refer (co-using)]
   [modular.component.co-dependency.schema :refer (co-dep)]
   [yada.yada :refer (yada)])
  (:import [clojure.lang ExceptionInfo]
           [modular.bidi Router]))

(defn make-verification-link [req code email *router]
  (let [values ((juxt (comp name :scheme) :server-name :server-port) req)
        verify-user-email-path (path-for @*router ::verify-user-email)]
    (apply format "%s://%s:%d%s?code=%s&email=%s" (conj values verify-user-email-path code email))))

;; TODO: Ensure this can't be hijacked, see section on 'Preventing
;; redirect attacks' here:
;; http://rundis.github.io/blog/2015/buddy_auth_part2.html

(s/defrecord Signup
    [user-store :- (s/protocol UserStore)
     user-password-hasher :- (s/protocol UserPasswordHasher)
     session :- (s/both (s/protocol SessionData) (s/protocol SessionLifecycle))
     verification-code-store :- (s/protocol TokenStore)
     uri-context :- s/Str
     *router :- (co-dep Router)]

  RouteProvider
  (routes [component]
          [uri-context
           {"signup"
            {#_:get
             #_(->
              (fn [req]
                (let [resp (response "TODO" #_(render-signup-form
                                               renderer req
                                               {:title "Sign up"
                                                :form {:method :post
                                                       :action (path-for @*router ::POST-signup-form)}}))]

                  (if-not (session-data session-store req)
                    ;; We create an empty session. This is because the POST
                    ;; handler requires that a session exists within which it can
                    ;; store the identity on a successful login
                    ;; (revisit: the comment above is wrong, the POST handler can
                    ;; create the session)
                    (start-session! session req {} resp)
                    resp)))
              (tag ::GET-signup-form))

             :post
             (->
              (fn [req]

                (let [form (-> req params-request :form-params)
                      ;;uid (get form "user-id")
                      password (get form "password")

                      ;;name (get form "name")

                      ;; We remove the plain-text password to avoid sending it
                      ;; through the API
                      user (-> form (dissoc "password") keywordize-form)

                      ;; Create the user
                      ;; TODO: Watch out, create-user! can return a manifold deferred
                      user (create-user! user-store
                                         (assoc user :password-hash (hash-password user-password-hasher password)))
                      ]

                  (when (:error user) (throw (ex-info "Failed to create user" user)))


                  ;; TODO: Check the password meets policy constraints (length, etc.)

                  ;; Check the user can be created. E.g. uid and/or email
                  ;; doesn't already exist, otherwise render an error page,
                  ;; all required fields in correct format, etc.
                  ;; (create-user-error? user-store user)

                  ;; Send the email to the user now!
                  #_(when emailer
                    (let [code (str (java.util.UUID/randomUUID))]
                      (create-token!
                       verification-code-store code
                       {:bolt/user user})

                      (when-let [email (:email user)]
                        #_(send-email!
                           emailer
                           (merge {:to email}
                                  (render-welcome-email-message
                                   renderer
                                   {:email-verification-link
                                    (str
                                     (absolute-prefix req)
                                     (path-for @*router ::verify-user-email)
                                     (as-query-string {"code" code}))})))
                        (throw (ex-info "TODO: send email action, call a function perhaps" {})))))

                  ;; Create a session that contains the secret-key
                  ;; (assoc-session-data! session-store req {:bolt/subject-identifier uid :name name})

                  (start-session!
                   session
                   (if-let [loc (or (get form "post_signup_redirect")
                                    (:post-signup-redirect component))]
                     (redirect-after-post loc)
                     (response (format "Thank you, %s, for signing up" user)))
                   user                 ; keep logged in after signup
                   )))

              wrap-schema-validation
              (tag ::POST-signup-form)
              )}

            "verify-email"
            {:get        ; this is a post, it's not safe, nor idempotent
             (->
              (fn [req]
                (let [params (-> req params-request :params)]
                  (let [token-id (get params "code")
                        token (get-token-by-id (:verification-code-store component) token-id)]
                    (if-let [uid (:bolt/subject-identifier token)]
                      (do
                        (verify-email! user-store uid)
                        (response "TODO: redirect to info screen, telling user their email has changed" #_(render-email-verified renderer req token)))
                      {:status 400 :body (format "No known verification code: %s" token-id)}))))
              wrap-schema-validation
              (tag ::verify-user-email))}
            }]))

(defn new-signup [& {:as opts}]
  (-> (map->Signup (merge {:uri-context "/"} opts))
      (using [:user-store
              :user-password-hasher
              :session-store
              :verification-code-store
              :emailer])
      (co-using [:router])))
