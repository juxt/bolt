(ns cylon.authentication.reset-password
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [cylon.password.protocols :refer (make-password-hash)]
   [cylon.session.protocols :refer (session assoc-session-data! respond-with-new-session!)]
   [cylon.signup.protocols :refer ( send-email!   Emailer  render-request-reset-password-form render-simple-message)]
   [cylon.token-store :refer (create-token! get-token-by-id purge-token!)]
   [cylon.totp :refer (OneTimePasswordStore set-totp-secret get-totp-secret totp-token secret-key)]
   [cylon.user.protocols :refer (get-user-by-email set-user-password-hash!)]
   [cylon.util :refer (absolute-uri)]
   [cylon.verify-mail :refer (make-verification-link)]
   [hiccup.core :refer (html)]
   [modular.bidi :refer (WebService path-for)]
   [modular.bootstrap :refer (wrap-content-in-boilerplate)]
   [ring.middleware.params :refer (params-request)]
   [ring.util.response :refer (response redirect)]
   [schema.core :as s ]
   ))
;(remove-ns 'cylon.authentication.reset-password)
(defrecord ResetPassword [emailer renderer session-store user-store verification-code-store fields-reset fields-confirm-password password-verifier]
  WebService
  (request-handlers [this]
    {
     ;;GET: show the find by user form to reset the password
     ::request-reset-password-form
     (fn [req]
       {:status 200
        :body (render-request-reset-password-form
               renderer req
               {:form {:method :post
                       :action (path-for req ::process-reset-password-request)
                       :fields fields-reset}})})


     ;;POST:  find a user by email and send email with reset-password-link
     ::process-reset-password-request
     (fn [req]
       (let [form (-> req params-request :form-params)
             email (get form "email")]
         (if-let [user-by-mail (get-user-by-email user-store email)]
           (let [code (str (java.util.UUID/randomUUID))]
             (create-token! verification-code-store code {:email email :name (:name user-by-mail)})

             (send-email! emailer email
                          "Reset password confirmation step"
                          (format "Please click on this link to reset your password account: %s"
                                  (make-verification-link req ::reset-password-form code email))
                          "text/plain")

             (->>
              (response
               (render-simple-message
                renderer req
                "Reset password"
                (format "We've found your details and sent a password reset link to %s." email)
                ))
              (respond-with-new-session! session-store req {})
              ))
           {:status 200
            :body (render-request-reset-password-form
                   renderer req
                   {:form {:method :post
                           :action (path-for req ::process-password-reset)
                           :fields fields-reset}
                    :reset-status (format "No user with this mail %s in our db. Try again" email)})})))
     ;; GET : if the code for reseting password is on get request and is active we ofer the form to include new password
     ::reset-password-form
     (fn [req ]
       (let [
             params (-> req params-request :params)
             body
             (if-let [[email code] [ (get params "email") (get params "code")]]
               (if-let [store (get-token-by-id (:verification-code-store this) code)]
                 (if (= email (:email store))
                   (do
                     ;; TODO: should we check if user has an active session????
                     ;; TODO: we should to check about expiry time of this code

                     ;; theoretically we reach to this step from login page so we have a server-session
                     (assoc-session-data! session-store req {:reset-code-identity (:name store) :verification-code code})
                     {:status 200
                      :body (render-request-reset-password-form
                             renderer req
                             {:form {:method :post
                                     :action (path-for req ::process-password-reset)
                                     :fields fields-confirm-password}})})
                   (format "Sorry but your session associated with this email '%s' seems to not be logic" email))
                 (format "Sorry but your session associated with this email '%s' seems to not be valid" email))

               (format "Sorry but there were problems trying to retrieve your data related with your mail '%s' " (get params "email")))]

         (if (nil? (:status body))
           (response (render-simple-message renderer req "Reset Password Process" body))
           body)))

     ;;POST: save the new password having an active session and the post parameter new-password
     ::process-password-reset
     (fn [req]
       (if-let [identity (:reset-code-identity (session session-store req))]

         (let [form (-> req params-request :form-params)
               pw (get form "new_pw")]

           (purge-token! (:verification-code-store this) (:verification-code (session session-store req)))
           (set-user-password-hash! user-store identity (make-password-hash password-verifier pw))
           (response (render-simple-message renderer req  "Congratulations :)"
                                            "Your password has been successfuly changed")))
         {:status 200
          :body "you shouldn't be here! :(  "}
         )
       )
     })

  (routes [this]
    ["/" {"request-reset-password" {:get ::request-reset-password-form
                                    :post ::process-reset-password-request}
          "reset-password" {:get ::reset-password-form
                            :post ::process-password-reset}}])

  (uri-context [this] ""))

(def new-reset-password-schema
  {:fields-reset [{:name s/Str
                   :label s/Str
                   (s/optional-key :placeholder) s/Str
                   (s/optional-key :password?) s/Bool}]
   :fields-confirm-password [{:name s/Str
                   :label s/Str
                   (s/optional-key :placeholder) s/Str
                   (s/optional-key :password?) s/Bool}]
   (s/optional-key :emailer) (s/protocol Emailer)})

(defn new-reset-password [& {:as opts}]
  (component/using
   (->> opts
        (merge {:fields-reset
                [{:name "email" :label "Email" :placeholder "email"}]
                :fields-confirm-password
                [{:name "new_pw" :label "New Password" :password? true :placeholder "new password"}]}
               )
        (s/validate new-reset-password-schema)
        map->ResetPassword)
   [:user-store :session-store :renderer :verification-code-store :password-verifier]))
