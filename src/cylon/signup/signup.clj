(ns cylon.signup.signup
  (:require
   [cylon.signup.protocols :refer (render-signup-form send-email render-email-verified Emailer SignupFormRenderer)]
   [clojure.tools.logging :refer :all]
   [cylon.session :refer (session respond-with-new-session! assoc-session-data!)]
   [cylon.session.protocols :refer (SessionStore)]
   [cylon.token-store :refer (create-token! get-token-by-id)]
   [cylon.token-store.protocols :refer (TokenStore)]
   [cylon.password.protocols :refer (PasswordVerifier make-password-hash)]
   [com.stuartsierra.component :as component :refer (Lifecycle)]
   [modular.bidi :refer (WebService path-for)]
   [hiccup.core :refer (html)]
   [ring.middleware.params :refer (params-request)]
   [ring.middleware.cookies :refer (cookies-response wrap-cookies)]
   [ring.util.response :refer (response redirect redirect-after-post)]
   [cylon.user :refer (create-user! verify-email!)]
   [cylon.user.protocols :refer (UserStore)]
   [cylon.totp :as totp]
   [cylon.totp :refer (OneTimePasswordStore get-totp-secret set-totp-secret totp-token)]
   [schema.core :as s ]))

(defn make-verification-link [req code email]
  (let [values  ((juxt (comp name :scheme) :server-name :server-port) req)
        verify-user-email-path (path-for req ::verify-user-email)]
    (apply format "%s://%s:%d%s?code=%s&email=%s" (conj values verify-user-email-path code email))))

(def new-signup-with-totp-schema
  {:fields [{:name s/Str
             :label s/Str
             (s/optional-key :placeholder) s/Str
             (s/optional-key :password?) s/Bool}]
   (s/optional-key :post-signup-redirect) s/Str})

(defrecord SignupWithTotp [renderer session-store user-store password-verifier verification-code-store emailer fields]
  Lifecycle
  (start [component]
    (s/validate (merge
                 new-signup-with-totp-schema
                 {:user-store (s/protocol UserStore)
                  :session-store (s/protocol SessionStore)
                  :password-verifier (s/protocol PasswordVerifier)
                  :verification-code-store (s/protocol TokenStore)
                  :renderer s/Any
                  (s/optional-key :emailer) (s/protocol Emailer)})
                component))
  (stop [component] component)
  WebService
  (request-handlers [component]
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
           ;; (revisit: the comment above is wrong, the POST handler can
           ;; create the session)
           (respond-with-new-session! session-store req {} resp)
           resp)))

     ::POST-signup-form
     (fn [req]
       (debugf "Processing signup")
       (let [form (-> req params-request :form-params)
             uid (get form "user-id")
             password (get form "password")
             email (get form "email")
             name (get form "name")
             totp-secret (when (satisfies? OneTimePasswordStore user-store)
                           (totp/secret-key))]

         ;; Add the user
         (create-user! user-store uid (make-password-hash password-verifier password)
                       email
                       {:name name})

         ;; Add the totp-secret
         (when (satisfies? OneTimePasswordStore user-store)
           (set-totp-secret user-store uid totp-secret))

         ;; Send the email to the user now!
         (when emailer
           ;; TODO Possibly we should encrypt and decrypt the verification-code (symmetric)
           (let [code (str (java.util.UUID/randomUUID))]
             (create-token! verification-code-store
                            code
                            {:email email :id uid})

             (send-email emailer email
                         "Please verify your email address"
                         (format "Thanks for signing up. Please click on this link to verify your account: %s"
                                 (make-verification-link req code email)))))

         ;; Create a session that contains the secret-key
         (let [data (merge {:cylon/subject-identifier uid :name name}
                           (when (satisfies? OneTimePasswordStore user-store)
                             {:totp-secret totp-secret}))]
           (assoc-session-data! session-store req data)

           (respond-with-new-session!
            session-store req
            {:cylon/subject-identifier uid}
            (if-let [loc (or (get form "post_signup_redirect")
                             (:post-signup-redirect component))]
              (redirect-after-post loc)
              (response (format "Thank you, %s, for signing up" name)))))))

     ::verify-user-email
     (fn [req]
       (let [params (-> req params-request :params)
             body
             (if-let [[email code] [ (get params "email") (get params "code")]]
               (if-let [store (get-token-by-id (:verification-code-store component) code)]
                 (if (= email (:email store))
                   (do (verify-email! user-store (:name store))
                       (format "Thanks, Your email '%s'  has been verified correctly " email))
                   (format "Sorry but your session associated with this email '%s' seems to not be logic" email))
                 (format "Sorry but your session associated with this email '%s' seems to not be valid" email))

               (format "Sorry but there were problems trying to retrieve your data related with your mail '%s' " (get params "email")))]

         (response (render-email-verified renderer req {:message body}))))

     })

  (routes [_]
    ["/" {"signup" {:get ::GET-signup-form
                    :post ::POST-signup-form}
          "verify-email" {:get ::verify-user-email}
          }])

  (uri-context [_] ""))

(defn new-signup-with-totp [& {:as opts}]
  (component/using
   (->> opts
        (merge {:fields
                [{:name "user-id" :label "User" :placeholder "id"}
                 {:name "password" :label "Password" :password? true :placeholder "password"}
                 {:name "name" :label "Name" :placeholder "name"}
                 {:name "email" :label "Email" :placeholder "email"}]
                })
        (s/validate new-signup-with-totp-schema)
        map->SignupWithTotp)
   [:user-store
    :password-verifier
    :session-store
    :renderer
    :verification-code-store
    :emailer]))
