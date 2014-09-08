(ns cylon.impl.signup
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [modular.bidi :refer (WebService path-for)]
   [hiccup.core :refer (html)]
   [ring.middleware.params :refer (wrap-params)]
   [ring.middleware.cookies :refer (cookies-response wrap-cookies)]
   [cylon.session :refer (create-session! get-session)]
   [cylon.user :refer (add-user! user-email-verified!)]
   [cylon.totp :as totp]
   [cylon.totp :refer (OneTimePasswordStore set-totp-secret)]
   [cylon.impl.authentication :refer (MFA-AUTH-COOKIE)]
   [cylon.session :refer (get-session-from-cookie create-session! cookies-response-with-session)]
   [cylon.totp :refer (OneTimePasswordStore get-totp-secret totp-token)]
   [schema.core :as s ]))

(defprotocol SignupFormRenderer
  (render-signup-form [_ req model]))

(defprotocol WelcomeRenderer
  (render-welcome [_ req model]))

(defprotocol EmailVerifiedRenderer
  (render-email-verified [_ req model]))

(defprotocol ResetPasswordRenderer
  (render-reset-password [_ req model]))


;; One simple component that does signup, reset password, login form. etc.
;; Mostly you want something simple that works which you can tweak later - you can provide your own implementation based on the reference implementation

(defprotocol Emailer
  (send-email [_ email body]))

(defn make-verification-link [req code email]
  (let [values  ((juxt (comp name :scheme) :server-name :server-port) req)
        verify-user-email-path (path-for req ::verify-user-email)]
    (apply format "%s://%s:%d%s?code=%s&email=%s" (conj values verify-user-email-path code email))))

(defrecord SignupWithTotp [appname renderer fields session-store user-domain  verification-code-store emailer fields-reset]
  WebService
  (request-handlers [this]
    {::signup-form
     (fn [req]
       {:status 200
        :body (render-signup-form
               renderer req
               {:form {:method :post
                       :action (path-for req ::process-signup)
                       :fields fields}})})

     ::process-signup
     (->
      (fn [req]
        (debugf "Processing signup")
        (let [identity (get (:form-params req) "user")
              password (get (:form-params req) "password")
              email (get (:form-params req) "email")
              name (get (:form-params req) "name")
              totp-secret (when (satisfies? OneTimePasswordStore user-domain)
                            (totp/secret-key))
              verification-session (create-session! verification-code-store {:email email :name name})
              ;; TODO Possibly we should encrypt and decrypt the verification-code (symmetric)
              verification-code (:cylon.session/key verification-session)]

          ;; Add the user
          (add-user! user-domain identity password
                     {:name name
                      :email email})

          ;; Add on the totp-secret
          (when (satisfies? OneTimePasswordStore user-domain)
            (set-totp-secret user-domain identity totp-secret))

          ;; TODO: Send the email to the user now!
          (when emailer
            (send-email emailer email
                        (format "Thanks for signing up with %s. Please click on this link to verify your account: %s"
                                appname (make-verification-link req verification-code email))))

          ;; Create a session that contains the secret-key
          (let [session (create-session! session-store
                                         {:name name ; duplicate code!
                                          :totp-secret totp-secret})
                loc (path-for req ::welcome-new-user)]
            (debugf "Redirecting to welcome page at %s" loc)
            (cookies-response-with-session
             {:status 302
              :headers {"Location" loc}}
             MFA-AUTH-COOKIE
             session))))
      wrap-params)

     ::welcome-new-user
     (fn [req]
       ;; TODO remember our (optional) email validation step
       (let [session (get-session-from-cookie req MFA-AUTH-COOKIE session-store)]
         {:status 200
          :body
          (html
           [:div
            [:p (format "Thank you for signing up %s!"  (:name session))]
            (when (satisfies? OneTimePasswordStore user-domain)
              (let [totp-secret (:totp-secret session)]
                [:div
                 [:p "Please scan this image into your 2-factor authentication application"]
                 [:img {:src (totp/qr-code (format "%s@%s" identity appname) totp-secret) }]
                 [:p "Alternatively, type in this secret into your authenticator application: " [:code totp-secret]]

                 ]))
            [:p "Please check your email and click on the verification link"]
            ;; We can keep this person 'logged in' now, as soon as their
            ;; email is verified, we can request an access code for
            ;; them. A user can be already authenticated with the
            ;; authorization service when the client application
            ;; requests an access code to use on that user's behalf.

            ;; One of the conditions for granting scopes to a client app
            ;; could be that the user's email has been verified. If not,
            ;; the user can continue, just can't do certain things such
            ;; as create topics (or anything we might need to know the
            ;; user's email address for).

            ;; I think the TOTP functionality could be made optional,
            ;; but yes, we probably could do a similar component without
            ;; it. Strike the balance between unreasonable conditional logic and
            ;; code duplication.
            ])}))

     ::verify-user-email
     (-> (fn [req]
           (let [body (if-let [[email code] [ (get (:params req) "email") (get (:params req) "code")]]
                        (if-let [session (get-session (:verification-code-store this) code)]
                          (if (= email (:email session))
                            (do (user-email-verified! (:user-domain this) (:name session))
                                (format "Thanks, Your email '%s'  has been verified correctly " email ))
                          (format "Sorry but your session associated with this email '%s' seems to not be logic" email))
                          (format "Sorry but your session associated with this email '%s' seems to not be valid" email))

                        (format "Sorry but there were problems trying to retrieve your data related with your mail '%s' " (get (:params req) "email"))
                        )]
             {:status 200
              :body (render-email-verified
                renderer req
                {:message body})}))
         wrap-params)

     ::reset-password-form
     (fn [req]
       {:status 200
        :body (render-reset-password
               renderer req
               {:form {:method :post
                       :action (path-for req ::process-reset-password)
                       :fields fields-reset}})})

     ::process-reset-password
     (-> (fn [req] {:status 200 :body (format "Thanks for reseting pw. Old pw: %s. New pw: %s"
                                             (get (:form-params req) "old_pw")
                                             (get (:form-params req) "new_pw"))})
         wrap-params)
     })

  (routes [this]
    ["/" {"signup" {:get ::signup-form
                    :post ::process-signup}
          "welcome" {:get ::welcome-new-user}
          "verify-email" {:get ::verify-user-email}
          "reset-password" {:get ::reset-password-form
                            :post ::process-reset-password}
          }])

  (uri-context [this] ""))

(defn new-signup-with-totp [& {:as opts}]
  (component/using
   (->> opts
        (merge {:appname "cylon"
                :fields [{:name "user" :label "User" :placeholder "userid"}
                         {:name "password" :label "Password" :password? true :placeholder "password"}
                         {:name "name" :label "Name" :placeholder "name"}
                         {:name "email" :label "Email" :placeholder "email"}]
                :fields-reset [
                               {:name "old_pw" :label "Old Password" :password? true :placeholder "old password"}
                               {:name "new_pw" :label "New Password" :password? true :placeholder "new password"}
                               {:name "new_pw_bis" :label "Repeat New Password" :password? true :placeholder "repeat new password"}]
                })
        (s/validate {:appname s/Str
                     :fields [{:name s/Str
                               :label s/Str
                               (s/optional-key :placeholder) s/Str
                               (s/optional-key :password?) s/Bool}]
                     :fields-reset [{:name s/Str
                                     :label s/Str
                                     (s/optional-key :placeholder) s/Str
                                     (s/optional-key :password?) s/Bool}]
                     (s/optional-key :emailer) (s/protocol Emailer)})
        map->SignupWithTotp)
   [:user-domain :session-store :renderer :verification-code-store ]))
