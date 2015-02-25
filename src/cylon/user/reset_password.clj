;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.user.reset-password
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component :refer (using)]
   [cylon.password.protocols :refer (make-password-hash)]
   [cylon.session.protocols :refer (session assoc-session-data! respond-with-new-session!)]
   [cylon.user.protocols :refer (Emailer LoginFormRenderer UserFormRenderer)]
   [cylon.user.totp :refer (OneTimePasswordStore set-totp-secret get-totp-secret totp-token secret-key)]

   [cylon.user :refer (render-reset-password-request-form get-user-by-email send-email! render-reset-password-email-message render-reset-password-link-sent-response render-password-reset-form set-user-password-hash! render-password-changed-response FormField)]

   [cylon.token-store :refer (create-token! get-token-by-id purge-token!)]
   [cylon.util :refer (absolute-uri absolute-prefix as-query-string wrap-schema-validation)]
   [hiccup.core :refer (html)]
   [bidi.bidi :refer (RouteProvider handler)]
   [modular.bidi :refer (path-for)]
   [ring.middleware.params :refer (params-request)]
   [ring.util.response :refer (response redirect)]
   [schema.core :as s]
   [plumbing.core :refer (<-)]
   [tangrammer.component.co-dependency :refer (co-using)]
   ))

(defrecord ResetPassword [emailer renderer session-store user-store verification-code-store fields-reset fields-confirm-password password-verifier uri-context router]
  RouteProvider
  (routes [this]
    [uri-context
     {"/request-reset-password"
      {
       ;; GET: show the find by user form to reset the password
       :get
       (handler ::request-reset-password-form
                (->
                 (fn [req]
                   {:status 200
                    :body (render-reset-password-request-form
                           renderer req
                           {:form {:method :post
                                   :action (path-for @router ::process-reset-password-request)
                                   :fields fields-reset}})})
                 wrap-schema-validation))

       ;; POST: find a user by email and send email with reset-password-link
       :post
       (handler ::process-reset-password-request
                (->
                 (fn [req]
                   (let [form (-> req params-request :form-params)
                         email (get form "email")]
                     (if-let [user (get-user-by-email user-store email)]
                       (let [code (str (java.util.UUID/randomUUID))]
                         (debugf "Found user: %s" user)
                         (create-token! verification-code-store code user)
                         (send-email!
                          emailer (merge
                                   {:to email}
                                   (render-reset-password-email-message
                                    renderer
                                    {:link (str
                                            (absolute-prefix req)
                                            (path-for @router ::reset-password-form)
                                            (as-query-string {"code" code}))})))
                         (->>
                          (response
                           (render-reset-password-link-sent-response
                            renderer req {:email email}))
                          (respond-with-new-session! session-store req {})))

                       ;; TODO Add email-failed? as query parameter
                       (redirect (path-for @router ::request-reset-password-form)))))
                 wrap-schema-validation))}

      "/reset-password"
      {:get
       (handler
        ::reset-password-form
        (->
         (fn [req]
           (let [params (-> req params-request :params)]
             (let [code (get params "code")
                   token (get-token-by-id (:verification-code-store this) code)]
               (if token
                 {:status 200
                  :body (render-password-reset-form
                         renderer req
                         (merge
                          {:form {:method :post
                                  :action (path-for @router ::process-password-reset)
                                  ;; add hidden field
                                  :fields (conj fields-confirm-password
                                                {:name "code" :type "hidden" :value code})}}
                          token))}
                 ;; TODO: This is unhelpful - render a 400 error message instead.
                 {:status 404 :body "Not found"}
                 ))))
         wrap-schema-validation))

       :post
       (handler
        ::process-password-reset
        (->
         (fn [req]
           (let [form (-> req params-request :form-params)
                 token-id (get form "code")
                 token (get-token-by-id (:verification-code-store this) token-id)
                 pw (get form "new_pw")]

             (if token
               (do
                 (infof "Reseting password for user %s" (:uid token))
                 (set-user-password-hash!
                  user-store
                  (:uid token)
                  (make-password-hash password-verifier pw))
                 (purge-token! (:verification-code-store this) token-id)
                 (response (render-password-changed-response renderer req {})))

               ;; TODO: Here's where we must display an error, via calling a protocol
               {:status 400 :body (format "ERROR: no such token for code: %s" token-id)})))
         wrap-schema-validation
         ))}}]))

(def new-reset-password-schema
  {:fields-reset
   [FormField]
   :fields-confirm-password
   [FormField]
   :uri-context s/Str})

(defn new-reset-password [& {:as opts}]
  (->> opts
       (merge
        {:fields-reset
         [{:name "email"
           :type "text"
           :label "Email"
           :placeholder "email"}]
         :fields-confirm-password
         [{:name "new_pw"
           :type "password"
           :label "New Password"
           :placeholder "new password"}]
         :uri-context "/"
         })
       (s/validate new-reset-password-schema)
       map->ResetPassword
       (<- (using [:user-store :session-store :renderer
                   :verification-code-store :password-verifier :emailer]))
       (<- (co-using [:router]))))
