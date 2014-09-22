;; One simple component that does signup, reset password, login form. etc.
;; Mostly you want something simple that works which you can tweak later - you can provide your own implementation based on the reference implementation

(ns cylon.signup.signup
  (:require
   [cylon.signup.protocols :refer (render-signup-form send-email render-email-verified render-reset-password Emailer render-welcome)]
   [clojure.tools.logging :refer :all]
   [cylon.authentication :refer (InteractionStep get-location step-required?)]
   [cylon.session :refer (session respond-with-new-session! assoc-session-data!)]
   [cylon.token-store :refer (create-token! get-token-by-id)]
   [cylon.oauth.client-registry :refer (lookup-client+)]
   [com.stuartsierra.component :as component]
   [modular.bidi :refer (WebService path-for)]
   [hiccup.core :refer (html)]
   [ring.middleware.params :refer (params-request)]
   [ring.middleware.cookies :refer (cookies-response wrap-cookies)]
   [ring.util.response :refer (response redirect)]
   [cylon.user :refer (add-user! user-email-verified! find-user-by-email reset-password!)]
   [cylon.totp :as totp]
   [cylon.totp :refer (OneTimePasswordStore set-totp-secret)]
   [cylon.totp :refer (OneTimePasswordStore get-totp-secret totp-token)]
   [schema.core :as s ]))

(defn make-verification-link [req target code email]
  (let [values  ((juxt (comp name :scheme) :server-name :server-port) req)
        verify-user-email-path (path-for req target)]
    (apply format "%s://%s:%d%s?code=%s&email=%s" (conj values verify-user-email-path code email))))

(defn- post-signup-handler-fn  [{:keys [user-domain emailer verification-code-store session-store renderer]} req post-signup-session-update]
       (debugf "Processing signup")
       (let [form (-> req params-request :form-params)
             user-id (get form "user-id")
             password (get form "password")
             email (get form "email")
             name (get form "name")
             totp-secret (when (satisfies? OneTimePasswordStore user-domain)
                           (totp/secret-key))]

         ;; Add the user
         (add-user! user-domain user-id password {:name name :email email})

         ;; Add the totp-secret
         (when (satisfies? OneTimePasswordStore user-domain)
           (set-totp-secret user-domain user-id totp-secret))

         ;; Send the email to the user now!
         (when emailer
           ;; TODO Possibly we should encrypt and decrypt the verification-code (symmetric)
           (let [code (str (java.util.UUID/randomUUID))]
             (create-token! verification-code-store code {:email email :name name})

             (send-email emailer email
                         "Please give me access to beta"
                         (format "Thanks for signing up. Please click on this link to verify your account: %s"
                                 (make-verification-link req ::verify-user-email code email)))))

         ;; Create a session that contains the secret-key
         (let [data (merge {:cylon/subject-identifier user-id
                            :name name}
                           (when (satisfies? OneTimePasswordStore user-domain)
                             {:totp-secret totp-secret})
                           (when true ; authenticate on
                             {:cylon/authenticated? true}))]

           (post-signup-session-update data session-store req renderer)

           )))


;; I think the TOTP functionality could be made optional,
;; but yes, we probably could do a similar component without
;; it. Strike the balance between unreasonable conditional logic and
;; code duplication.

(defrecord SignupWithTotp [renderer session-store user-domain verification-code-store emailer fields fields-reset fields-confirm-password]
  WebService
  (request-handlers [this]
    {::GET-signup-form
     (fn [req]
       (let [resp (response (render-signup-form
                             renderer req
                             {:form {:method :post
                                     :action (path-for req ::POST-signup-form)
                                     :fields fields}}))]
         (if-not (session session-store req)
           ;; We create an empty session. This is because the POST
           ;; handler requires that a session exists within which it can
           ;; store the identity on a successful login
           (respond-with-new-session! session-store req {} resp)
           resp)))

     ::POST-signup-form
     (fn [req]
       (post-signup-handler-fn this req
        (fn  [data session-store req renderer]
          (let [session (session session-store req)
                form (-> req params-request :form-params)]
            (assoc-session-data! session-store req data)
            (response (render-welcome
                       renderer req
                       (merge
                         {:session session
                          :redirection-uri "http://localhost:8010/devices"
                          ;;(:redirection-uri (->> (:client-id session) (lookup-client+ (:client-registry this))))
                          } form data)))))))

     ::POST-signup-form-directly
     (fn [req]
       (post-signup-handler-fn this req
        (fn  [data session-store req renderer]
          (let [
                form (-> req params-request :form-params)
                response (response (render-welcome
                       renderer req
                       (merge
                         {:session (session session-store req)
                          :redirection-uri "http://localhost:8010/devices"
                          ;;(:redirection-uri (->> (:client-id session) (lookup-client+ (:client-registry this))))
                          } form data)))]

            (respond-with-new-session! session-store req data response)))))

     ::verify-user-email
     (fn [req]
       (let [params (-> req params-request :params)
             body
             (if-let [[email code] [ (get params "email") (get params "code")]]
               (if-let [store (get-token-by-id (:verification-code-store this) code)]
                 (if (= email (:email store))
                   (do (user-email-verified! (:user-domain this) (:name store))
                       (format "Thanks, Your email '%s'  has been verified correctly " email))
                   (format "Sorry but your session associated with this email '%s' seems to not be logic" email))
                 (format "Sorry but your session associated with this email '%s' seems to not be valid" email))

               (format "Sorry but there were problems trying to retrieve your data related with your mail '%s' " (get params "email")))]

         (response (render-email-verified renderer req {:message body :header "Verify user email"}))))

     ::verify-user-email-reset-password
     (fn [req]
       (let [params (-> req params-request :params)
             body
             (if-let [[email code] [ (get params "email") (get params "code")]]
               (if-let [store (get-token-by-id (:verification-code-store this) code)]
                 (if (= email (:email store))
                   (do
                     ;; TODO: should we check if user has an active session????
                     ;; TODO: we should to check about expiry time of this code

                     ;; theoretically we reach to this step from login page so we have a server-session
                     (assoc-session-data! session-store req {:reset-code-identity (:name store)})
                       {:status 200
                        :body (render-reset-password
                               renderer req
                               {:form {:method :post
                                       :action (path-for req ::confirm-password)
                                       :fields fields-confirm-password}})})
                   (format "Sorry but your session associated with this email '%s' seems to not be logic" email))
                 (format "Sorry but your session associated with this email '%s' seems to not be valid" email))

               (format "Sorry but there were problems trying to retrieve your data related with your mail '%s' " (get params "email")))]

         (if (nil? (:status body))
           (response (render-email-verified renderer req {:message body :header "Reset Password Process"} ))
           body)))


     ::reset-password-form
     (fn [req]
       {:status 200
        :body (render-reset-password
               renderer req
               {:form {:method :post
                       :action (path-for req ::process-reset-password)
                       :fields fields-reset}})})

     ::process-reset-password
     (fn [req]
       (let [form (-> req params-request :form-params)
             email (get form "email")]
         (if-let [user-by-mail (find-user-by-email user-domain email)]
           (do
             (let [code (str (java.util.UUID/randomUUID))]
             (create-token! verification-code-store code {:email email :name (:user user-by-mail)})

             (send-email emailer email
                         "Reset password confirmation step"
                         (format "Please click on this link to reset your password account: %s"
                                 (make-verification-link req ::verify-user-email-reset-password code email)))

             (response
              (render-email-verified
               renderer req
               {:message (format "We've found in our db, thanks for reseting for this mail: %s.
 You'll recieve an email with confirmation link" email)
                :header "Reset Password Process"} ))))
           {:status 200
            :body (render-reset-password
                   renderer req
                   {:form {:method :post
                           :action (path-for req ::process-reset-password)
                           :fields fields-reset}
                    :reset-status (format "No user with this mail %s in our db. Try again" email)})})))

     ::confirm-password
     (fn [req]
       (if-let [identity (:reset-code-identity (session session-store req))]
        ;;TODO:  remove token from store??
         (let [form (-> req params-request :form-params)
               pw (get form "new_pw")
               pw-bis (get form "new_pw_bis")]
           (if (= pw pw-bis)
             (do
               (reset-password! user-domain identity pw)
               (response (render-email-verified renderer req {:message "You are like a hero, successful result"
                                                              :header "Reset Password Process"} )))
             {:status 200
              :body (render-reset-password
                   renderer req
                   {:form {:method :post
                           :action (path-for req ::confirm-password)
                           :fields fields-confirm-password}
                    :reset-status "Your passwords aren't the same :( . Try again"})})
           )
         {:status 200
          :body "you shouldn't be here! :(  "}
         )
       )

     })

  (routes [this]
    ["/" {"signup" {:get ::GET-signup-form
                    :post ::POST-signup-form-directly}
          "signup_post" {:post ::POST-signup-form}
          "verify-email" {:get ::verify-user-email}
          "verify-email-reset-pw" {:get ::verify-user-email-reset-password
                                   :post ::confirm-password}

          "reset-password" {:get ::reset-password-form
                            :post ::process-reset-password}
          }])

  (uri-context [this] "")

  InteractionStep
  (get-location [this req]
    (path-for req ::GET-signup-form))
  (step-required? [this req] true))

(def new-signup-with-totp-schema
  {:fields [{:name s/Str
             :label s/Str
             (s/optional-key :placeholder) s/Str
             (s/optional-key :password?) s/Bool}]
   :fields-reset [{:name s/Str
                   :label s/Str
                   (s/optional-key :placeholder) s/Str
                   (s/optional-key :password?) s/Bool}]
   :fields-confirm-password [{:name s/Str
                   :label s/Str
                   (s/optional-key :placeholder) s/Str
                   (s/optional-key :password?) s/Bool}]


   (s/optional-key :emailer) (s/protocol Emailer)})

(defn new-signup-with-totp [& {:as opts}]
  (component/using
   (->> opts
        (merge {:fields
                [{:name "user-id" :label "User" :placeholder "id"}
                 {:name "password" :label "Password" :password? true :placeholder "password"}
                 {:name "name" :label "Name" :placeholder "name"}
                 {:name "email" :label "Email" :placeholder "email"}]
                :fields-reset
                [{:name "email" :label "Email" :placeholder "email"}]
                :fields-confirm-password
                [{:name "new_pw" :label "New Password" :password? true :placeholder "new password"}
                 {:name "new_pw_bis" :label "Repeat New Password" :password? true :placeholder "repeat new password"}]

                })
        (s/validate new-signup-with-totp-schema)
        map->SignupWithTotp)
   [:user-domain :session-store :renderer :verification-code-store]))
