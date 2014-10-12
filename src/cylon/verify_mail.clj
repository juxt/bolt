(ns cylon.verify-mail
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [cylon.signup.protocols :refer (render-simple-message send-email! Emailer)]
   [cylon.token-store :refer (create-token! get-token-by-id purge-token!)]
   [cylon.totp :refer (OneTimePasswordStore set-totp-secret get-totp-secret totp-token secret-key)]

   [cylon.user.protocols :refer (create-user! user-email-verified!  )]
   [cylon.util :refer (absolute-uri)]

   [hiccup.core :refer (html)]
   [modular.bidi :refer (WebService path-for)]
   [ring.middleware.cookies :refer (cookies-response wrap-cookies)]
   [ring.middleware.params :refer (params-request)]
   [ring.util.response :refer (response redirect)]
   [schema.core :as s ]
   ))

(defn make-verification-link [req target code email]
  (let [values  ((juxt (comp name :scheme) :server-name :server-port) req)
        verify-user-email-path (path-for req target)]
    (apply format "%s://%s:%d%s?code=%s&email=%s" (conj values verify-user-email-path code email))))

(defrecord EmailVerifierCode [emailer renderer user-domain verification-code-store]

  WebService
  (request-handlers [this]
    {
     ;; GET: obtain code from get request to verificate email
     ::verify-user-email
     (fn [req]
       (let [params (-> req params-request :params)
             body
             (if-let [[email code] [ (get params "email") (get params "code")]]
               (if-let [store (get-token-by-id verification-code-store  code)]
                 (if (= email (:email store))
                   (do
                     (purge-token! (:verification-code-store this) code)
                     (user-email-verified! (:user-domain this) (:name store))
                     (format "Thanks, Your email '%s'  has been verified correctly " email))
                   (format "Sorry but your session associated with this email '%s' seems to not be logic" email))
                 (format "Sorry but your session associated with this email '%s' seems to not be valid" email))

               (format "Sorry but there were problems trying to retrieve your data related with your mail '%s' " (get params "email")))]

         (response (render-simple-message renderer req "Verify user email" body ))))


     })

  (routes [this]
    ["/" {"verify-email" {:get ::verify-user-email}}])

  (uri-context [this] "")

  #_EmailVerifier
  #_(send-verification [this req user-data]
    ;; TODO Possibly we should encrypt and decrypt the verification-code (symmetric)
    (let [code (str (java.util.UUID/randomUUID))]
      (create-token! verification-code-store code (select-keys user-data [:email :name]))

      (send-email! emailer (:email user-data)
                  "Please give me access to beta"
                  (format "Thanks for signing up. Please click on this link to verify your account: %s"
                          (make-verification-link req ::verify-user-email code (:email user-data)))
                  "text/plain"))))

(def new-email-verifier-schema
  {(s/optional-key :emailer) (s/protocol Emailer)})

(defn new-email-verifier-code [& {:as opts}]
  (component/using
   (->> opts
        (merge {})
        (s/validate new-email-verifier-schema)
        map->EmailVerifierCode)
   [:user-domain  :renderer :verification-code-store]))
