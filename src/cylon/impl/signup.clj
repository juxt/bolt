(ns cylon.impl.signup
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [modular.bidi :refer (WebService path-for)]
   [hiccup.core :refer (html)]
   [ring.middleware.params :refer (wrap-params)]
   [ring.middleware.cookies :refer (cookies-response wrap-cookies)]
   [cylon.session :refer (create-session!)]
   [cylon.user :refer (add-user!)]
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

#_(html
 [:div
  [:h1 "Signup"]
  [:form {:method :post}
   [:p
    [:label {:for "user"} "User"]
    [:input {:name "user" :id "user" :type "text"}]]
   [:p
    [:label {:for "name"} "Name"]
    [:input {:name "name" :id "name" :type "text"}]]
   [:p
    [:label {:for "email"} "Email"]
    [:input {:name "email" :id "email" :type "text"}]]
   [:p
    [:label {:for "password"} "Password"]
    [:input {:name "password" :id "password" :type "password"}]]
   [:p [:input {:type "submit"}]]

   ]])

;; One simple component that does signup, reset password, login form. etc.
;; Mostly you want something simple that works which you can tweak later - you can provide your own implementation based on the reference implementation

(defprotocol Emailer
  (send-email [_ email body]))

(defn make-verification-link [code]
  (throw (ex-info "TODO" {:code code}))
  )

(defrecord SignupWithTotp [appname renderer fields session-store user-domain emailer verification-code-store]
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
              totp-secret (when (satisfies? OneTimePasswordStore user-domain)
                            (totp/secret-key))
              verification-session (create-session! verification-code-store {:email email})
              ;; TODO Possibly we should encrypt and decrypt the verification-code (symmetric)
              verification-code (:cylon.session/key verification-session)]

          ;; Add the user
          (add-user! user-domain identity password
                     {:name (get (:form-params req) "name")
                      :email email})

          ;; Add on the totp-secret
          (when (satisfies? OneTimePasswordStore user-domain)
            (set-totp-secret user-domain identity totp-secret))

          ;; TODO: Send the email to the user now!
          (when emailer
            (assert (satisfies? Emailer emailer))
            (send-email emailer email
                        (format "Thanks for signing up with %s. Please click on this link to verify your account: %s"
                                appname (make-verification-link verification-code))))

          ;; Create a session that contains the secret-key
          (let [session (create-session! session-store
                                         {:name (get (:form-params req) "name") ; duplicate code!
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
     ;; TODO
     (fn [req]
       {:status 200
        :body "Thanks"}
       )

     ::reset-password
     (fn [req] {:status 200 :body "Thanks"})
     })

  (routes [this]
    ["/" {"signup" {:get ::signup-form
                    :post ::process-signup}
          "welcome" {:get ::welcome-new-user}
          "verify-email" {:get ::verify-user-email}}])

  (uri-context [this] ""))

(defn new-signup-with-totp [& {:as opts}]
  (component/using
   (->> opts
        (merge {:appname "cylon"
                :fields [{:name "user" :label "User" :placeholder "userid"}
                         {:name "password" :label "Password" :password? true :placeholder "password"}
                         {:name "name" :label "Name" :placeholder "name"}
                         {:name "email" :label "Email" :placeholder "email"}]
                })
        (s/validate {:appname s/Str
                     :fields [{:name s/Str
                               :label s/Str
                               (s/optional-key :placeholder) s/Str
                               (s/optional-key :password?) s/Bool}]})
        map->SignupWithTotp)
   [:user-domain :session-store :renderer :verification-code-store]))
