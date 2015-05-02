; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.user.reset-password
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component :refer (using)]
   [cylon.session.protocols :refer (session assoc-session-data! respond-with-new-session!)]
   [cylon.user.protocols :refer (LoginFormRenderer UserFormRenderer)]
   [cylon.user :refer (render-reset-password-request-form render-reset-password-email-message render-reset-password-link-sent-response render-password-reset-form render-password-changed-response hash-password)]
   [cylon.token-store :refer (create-token! get-token-by-id purge-token!)]
   [cylon.util :refer (absolute-uri absolute-prefix as-query-string wrap-schema-validation)]
   [hiccup.core :refer (html)]
   [bidi.bidi :refer (RouteProvider tag)]
   [modular.bidi :refer (path-for)]
   [ring.middleware.params :refer (params-request)]
   [ring.util.response :refer (response redirect)]
   [schema.core :as s]
   [plumbing.core :refer (<-)]
   [modular.email :refer (send-email!)]
   [modular.component.co-dependency :refer (co-using)]
   ))

(defrecord ResetPassword [emailer renderer session-store user-store verification-code-store fields-reset fields-confirm-password password-verifier uri-context *router]
  RouteProvider
  (routes [this]
    [uri-context
     {"request-reset-password"
      {
       ;; GET: show the find by user form to reset the password
       :get
       (->
        (fn [req]
          {:status 200
           :body (render-reset-password-request-form
                  renderer req
                  {:form {:method :post
                          :action (path-for @*router ::process-reset-password-request)
                          :fields fields-reset}})})

        wrap-schema-validation
        (tag ::request-reset-password-form))

       ;; POST: find a user by email and send email with reset-password-link
       :post
       (->
        (fn [req]
          (let [form (-> req params-request :form-params)
                email (get form "email")]
            ;; TODO: We need to look up the user by email, rather than any
            ;; other id. This poses a challenge, because we don't have a
            ;; protocol for doing this yet
            (if-let [user (throw (ex-info "TODO" {})) #_(get-user-by-email user-store email)]
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
                                   (path-for @*router ::reset-password-form)
                                   (as-query-string {"code" code}))})))
                (->>
                 (response
                  (render-reset-password-link-sent-response
                   renderer req {:email email}))
                 (respond-with-new-session! session-store req {})))

              (redirect (format "%s?unknown-email=%s"
                                (path-for @*router ::request-reset-password-form)
                                email)))))
        wrap-schema-validation
        (tag ::process-reset-password-request)
        )}

      "reset-password"
      {:get
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
                                 :action (path-for @*router ::process-password-reset)
                                 ;; add hidden field
                                 :fields (conj fields-confirm-password
                                               {:name "code" :type "hidden" :value code})}}
                         token))}
                ;; TODO: This is unhelpful - render a 400 error message instead.
                {:status 404 :body "Not found"}
                ))))
        wrap-schema-validation
        (tag ::reset-password-form))

       :post
       (->
        (fn [req]
          (let [form (-> req params-request :form-params)
                token-id (get form "code")
                token (get-token-by-id (:verification-code-store this) token-id)
                pw (get form "new_pw")]

            (if token
              (do
                (infof "Reseting password for user %s" (:uid token))
                ;; TODO How to update the user password here?
                (throw (ex-info "TODO"))
                #_(set-user-password-hash!
                 user-store
                 (:uid token)
                 (hash-password user-password-hasher pw))
                (purge-token! (:verification-code-store this) token-id)
                (response (render-password-changed-response renderer req {})))

              ;; TODO: Here's where we must display an error, via calling a protocol
              {:status 400 :body (format "ERROR: no such token for code: %s" token-id)})))
        wrap-schema-validation
        (tag ::process-password-reset)
        )}}]))

(def new-reset-password-schema
  {:uri-context s/Str})

(defn new-reset-password [& {:as opts}]
  (->> opts
       (merge
        {:uri-context "/"})
       (s/validate new-reset-password-schema)
       map->ResetPassword
       (<- (using [:user-store :session-store :renderer
                   :verification-code-store :password-verifier :emailer]))
       (<- (co-using [:router]))))
