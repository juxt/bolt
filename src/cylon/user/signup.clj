;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.user.signup
  (:require
   [bidi.bidi :refer (RouteProvider tag)]
   [cylon.user.protocols :refer (UserFormRenderer ErrorRenderer)]
   [modular.email :refer (send-email!)]
   [modular.email.protocols :refer (Emailer)]
   [clojure.tools.logging :refer :all]
   [cylon.util :refer (absolute-prefix as-query-string wrap-schema-validation keywordize-form)]
   [cylon.session :refer (session respond-with-new-session! assoc-session-data!)]
   [cylon.session.protocols :refer (SessionStore)]
   [cylon.token-store :refer (create-token! get-token-by-id)]
   [cylon.token-store.protocols :refer (TokenStore)]
   [cylon.password.protocols :refer (PasswordVerifier make-password-hash)]
   [com.stuartsierra.component :as component :refer (Lifecycle using)]
   [modular.bidi :refer (path-for)]
   [hiccup.core :refer (html)]
   [ring.middleware.params :refer (params-request)]
   [ring.middleware.cookies :refer (cookies-response wrap-cookies)]
   [ring.util.response :refer (response redirect redirect-after-post)]
   [cylon.user :refer (create-user-error? create-user! verify-email! render-signup-form render-welcome-email-message render-email-verified render-error)]
   [cylon.user.protocols :refer (UserStore)]
   [schema.core :as s]
   [plumbing.core :refer (<-)]
   [modular.component.co-dependency :refer (co-using)]
   )
  (:import (clojure.lang ExceptionInfo)))

(defn make-verification-link [req code email *router]
  (let [values ((juxt (comp name :scheme) :server-name :server-port) req)
        verify-user-email-path (path-for @*router ::verify-user-email)]
    (apply format "%s://%s:%d%s?code=%s&email=%s" (conj values verify-user-email-path code email))))

(def new-signup-schema
  {:fields [{:name s/Str
             :label s/Str
             (s/optional-key :placeholder) s/Str
             (s/optional-key :password?) s/Bool}]
   :uri-context s/Str
   (s/optional-key :post-signup-redirect) s/Str})

(defn wrap-error-rendering [h renderer]
  (if (satisfies? ErrorRenderer renderer)
    (fn [req]
      (try
        (h req)
        (catch ExceptionInfo e
          (errorf e "User signup error")
          (let [{error-type :error-type :as data} (ex-data e)]
            {:status (case error-type
                       :user-already-exists 422
                       422)
             :body (render-error renderer req data)}))))
    h))

(defrecord Signup [renderer session-store user-store password-verifier verification-code-store emailer fields uri-context events *router]
  Lifecycle
  (start [component]
    (s/validate (merge
                 new-signup-schema
                 {:user-store (s/protocol UserStore)
                  :session-store (s/protocol SessionStore)
                  :password-verifier (s/protocol PasswordVerifier)
                  :verification-code-store (s/protocol TokenStore)
                  :events (s/maybe (s/protocol EventPublisher))
                  :renderer (s/protocol UserFormRenderer)
                  (s/optional-key :emailer) (s/protocol Emailer)
                  :*router s/Any ;; you can't get specific protocol of a codependency in start time
                  })
                component))
  (stop [component] component)

  RouteProvider
  (routes [component]
    [uri-context
     {"signup"
      {:get
       (->
        (fn [req]
          (let [resp (response (render-signup-form
                                renderer req
                                {:title "Sign up"
                                 :form {:method :post
                                        :action (path-for @*router ::POST-signup-form)
                                        :fields fields}}))]
            (if-not (session session-store req)
              ;; We create an empty session. This is because the POST
              ;; handler requires that a session exists within which it can
              ;; store the identity on a successful login
              ;; (revisit: the comment above is wrong, the POST handler can
              ;; create the session)
              (respond-with-new-session! session-store req {} resp)
              resp)))
        (tag ::GET-signup-form))

       :post
       (->
        (fn [req]
          (debugf "Processing signup")

          (let [form (-> req params-request :form-params)
                ;;uid (get form "user-id")
                password (get form "password")
                ;;email (get form "email")
                ;;name (get form "name")

                ;; We remove the plain-text password to avoid sending it
                ;; through the API
                user (-> (dissoc "password") keywordize-form)
                ]

            ;; TODO: Check the password meets policy constraints (length, etc.)

            ;; Check the user can be created. E.g. uid and/or email
            ;; doesn't already exist, otherwise render an error page,
            ;; all required fields in correct format, etc.
            ;; (create-user-error? user-store user)

            ;; Create the user
            (create-user! user-store (assoc user :password (make-password-hash password-verifier password)))

            ;; Send the email to the user now!
            (when emailer
              (let [code (str (java.util.UUID/randomUUID))]
                (create-token!
                 verification-code-store code
                 {:cylon/user user})

                (send-email!
                 emailer
                 (merge {:to email}
                        (render-welcome-email-message
                         renderer
                         {:email-verification-link
                          (str
                           (absolute-prefix req)
                           (path-for @*router ::verify-user-email)
                           (as-query-string {"code" code}))})))))

            ;; Create a session that contains the secret-key
            ;; (assoc-session-data! session-store req {:cylon/subject-identifier uid :name name})

            (respond-with-new-session!
             session-store req
             {:cylon/subject-identifier uid} ; keep logged in after signup
             (if-let [loc (or (get form "post_signup_redirect")
                              (:post-signup-redirect component))]
               (redirect-after-post loc)
               (response (format "Thank you, %s, for signing up" name))))))

        wrap-schema-validation
        (wrap-error-rendering renderer)
        (tag ::POST-signup-form)
        )}

      "verify-email"
      {:get
       (->
        (fn [req]
          (let [params (-> req params-request :params)]
            (let [token-id (get params "code")
                  token (get-token-by-id (:verification-code-store component) token-id)]
              (if-let [uid (:cylon/subject-identifier token)]
                (do
                  (verify-email! user-store uid)
                  (response (render-email-verified renderer req token)))
                {:status 400 :body (format "No known verification code: %s" token-id)}))))
        wrap-schema-validation
        (tag ::verify-user-email))}
      }]))

(defn new-signup [& {:as opts}]
  (->> opts
       (merge {:fields
               [{:name "user-id" :label "User" :placeholder "id"}
                {:name "password" :label "Password" :password? true :placeholder "password"}
                {:name "name" :label "Name" :placeholder "name"}
                {:name "email" :label "Email" :placeholder "email"}]
               :uri-context "/"
               })
       (s/validate new-signup-schema)
       map->Signup
       (<- (using [:user-store
                   :password-verifier
                   :session-store
                   :renderer
                   :verification-code-store
                   :emailer]))
       (<- (co-using [:router]))))
