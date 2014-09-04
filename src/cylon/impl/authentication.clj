;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.authentication
  (:require
   [com.stuartsierra.component :as component]
   [cylon.authentication :refer (Authenticator authenticate AuthenticationInteraction InteractionStep get-location step-required?)]
   [clojure.tools.logging :refer :all]
   [cylon.user :refer (UserStore verify-user)]
   [schema.core :as s]
   [plumbing.core :refer (<-)]
   [ring.middleware.cookies :refer (cookies-response wrap-cookies)]
   [ring.util.response :refer (redirect-after-post)]
   [ring.middleware.params :refer (wrap-params)]
   [modular.bidi :refer (WebService request-handlers routes uri-context path-for)]
   [cylon.session :refer (->cookie create-session! get-session get-session-id assoc-session! cookies-response-with-session get-session-from-cookie get-session-value purge-session!)]
   [hiccup.core :refer (html)]
   [cylon.totp :refer (OneTimePasswordStore get-totp-secret totp-token)])
  (:import
   (javax.xml.bind DatatypeConverter)))

(defrecord StaticAuthenticator [user]
  Authenticator
  (authenticate [this request]
    {:cylon/user user}))

(defn new-static-authenticator [& {:as opts}]
  (->> opts
       (s/validate {:user s/Str})
       map->StaticAuthenticator))

(defrecord HttpBasicAuthenticator []
  Authenticator
  (authenticate [this request]
    (when-let [header (get-in request [:headers "authorization"])]
      (when-let [basic-creds (second (re-matches #"\QBasic\E\s+(.*)" header))]
        (let [[user password] (->> (String. (DatatypeConverter/parseBase64Binary basic-creds) "UTF-8")
                                   (re-matches #"(.*):(.*)")
                                   rest)]
          (when (verify-user (:user-domain this) user password)
            {:cylon/user user
             :cylon/authentication-method :http-basic}))))))


(defn new-http-basic-authenticator [& {:as opts}]
  (component/using
   (->> opts
        map->HttpBasicAuthenticator)
   [:user-domain]))

;; A request authenticator that tries multiple authenticators in
;; turn. Disjunctive means that a positive result from any given
;; authenticator is sufficient.
(defrecord CompositeDisjunctiveAuthenticator []
  Authenticator
  (authenticate [this request]
    (->> this vals
         (filter (partial satisfies? Authenticator))
         (some #(authenticate % request) ))))

(defn new-composite-disjunctive-authenticator [& deps]
  (component/using
   (->CompositeDisjunctiveAuthenticator)
   (vec deps)))

(def MFA-AUTH-COOKIE "mfa-auth-session-id")
;; (If you're looking for CookieAuthenticator, it's in cylon.impl.session)


;; -----------------------------------------------------------------------

(defn unchunk [s]
  (when (seq s)
    (lazy-seq
      (cons (first s)
            (unchunk (next s))))))

(defn link-up [s]
  (take-while second
              (drop 1 (iterate (comp (juxt first next) second)
                               [nil s]))))

;; Again, rename to MultiFactorAuthenticator as above
(defrecord MultiFactorAuthenticationInteraction [steps]
  AuthenticationInteraction
  (initiate-authentication-interaction [this req initial-session-state]
    (let [steps ((apply juxt steps) this)
          ;; (Note: It's possible that the user has already got a
          ;; session, because they might have just signed up, etc. In
          ;; which case, we should retrieve the session and treat it has
          ;; the initial-session-state)
          session (create-session!
                   (:session-store this)
                   (merge initial-session-state
                          {:cylon/original-uri (str (:uri req) (when-let [qs (:query-string req)] (when (not-empty qs) (str "?" qs ))))}))
          loc (get-location (first steps) req)]

      (debugf "Initiating multi-factor authentication, redirecting to first step %s" loc)
      (cookies-response-with-session
       {:status 302
        :headers {"Location" loc}}
       MFA-AUTH-COOKIE
       session)))
  (get-result [this req]
    (get-session-from-cookie req MFA-AUTH-COOKIE (:session-store this)))
  (clean-resources! [this req]
    (purge-session! (:session-store this) (get-session-id req "mfa-auth-session-id")))

  ;; We proxy onto the dependencies which satisfy WebService in order to
  ;; change their behaviour.

  WebService
  (request-handlers [this]
    (debugf "Merging steps %s" steps)
    (apply merge
           (for [[step next-steps] (link-up ((apply juxt steps) this))]
             (reduce-kv
              (fn [acc k h]
                (assoc acc k
                       (fn [req]
                         (let [session-id (get-session-id req "mfa-auth-session-id")
                               session (get-session (:session-store this) session-id)
                               res (h req)
                               ]
                           (if (= (:request-method req) :get)
                             res
                             ;; if not GET then change the response
                             (case (:status res)
                               ;; step-required? may be expensive, let's unchunk so as to not call it unnecessarily
                               200 (if-let [next-step (first (filter #(step-required? % req) (unchunk next-steps)))]
                                     {:status 302
                                      :headers {"Location" (get-location next-step req)}
                                      :body "Authenticator: Move to the next step"}

                                     ;; No more steps, we're done. Redirect to the initiator.
                                     (do
                                       (assoc-session! (:session-store this) session-id :cylon/authenticated? true)
                                       ;; TODO What's this original uri? Can it also include the query string?
                                       (debugf "Successful authentication, redirecting to original uri of %s" (:cylon/original-uri session))
                                       (redirect-after-post (:cylon/original-uri session))
                                       ))
                               ;; It is the default policy of this
                               ;; authenticator to allow the user to
                               ;; retry entering her credentials
                               403 (redirect-after-post (get-location step req))
                               )
                             ))))
                )
              {}
              (request-handlers step)))))

  (routes [this]
    ["" (vec (for [step ((apply juxt steps) this)]
               [(uri-context step) [(routes step)]]))])

  (uri-context [this] ""))

(defn new-multi-factor-authentication-interaction [& {:as opts}]
  (component/using
   (->> opts
        (s/validate {:steps [s/Keyword]})
        map->MultiFactorAuthenticationInteraction)
   (conj (:steps opts) :session-store)))

(defprotocol LoginFormRenderer
  (render-login-form [_ req model]))


;; This is a simple login form that is meant to be part of a
;; AuthenticationInteraction which indicates policies, such as allowing
;; the user to retry credentials, how many times, etc.
;;
;; As such, it is important that the login form POST only returns
;; 200 (OK) or 403 (Login failure).
;;
;; TODO Obviously we should also deal with errors, such as 500
(defrecord LoginForm [cookie-id fields]
  WebService
  (request-handlers [this]
    {::GET-login-form
     (fn [req]
       (debugf "Rendering basic login form")
       (->
        {:status 200
         :body (render-login-form
                (:renderer this) req
                {:form {:method :post
                        :action (path-for req ::POST-login-form)
                        :fields fields}})}
        ;; Conditional response post-processing
        (cond->
         ;; In the absence of a session...
         (not (get-session-from-cookie req cookie-id (:session-store this)))
         ;; We create an empty one. This is because the POST handler
         ;; requires that a session exists within which it can store the
         ;; identity on a successful login
         (cookies-response-with-session cookie-id (create-session! (:session-store this) {})))))

     ::POST-login-form
     (->
      (fn [req]
        (let [params (-> req :form-params)
              identity (get params "user")
              password (get params "password")
              session (get-session (:session-store this) (get-session-id req cookie-id))]
          (assert session)

          (if (and identity
                   (not-empty identity)
                   (verify-user (:user-domain this) (.trim identity) password))
            (do
              (assoc-session! (:session-store this) (get-session-id req cookie-id) :cylon/identity identity)
              {:status 200
               :body "Thank you! - you gave the correct information!"})

            {:status 403
             :body "Bad guess!!! Please try again :)"}
            )))
      wrap-params wrap-cookies)})

  (routes [_] ["/" {"login" {:get ::GET-login-form
                             :post ::POST-login-form}}])
  (uri-context [_] "/basic")

  InteractionStep
  (get-location [this req]
    (path-for req ::GET-login-form))
  (step-required? [this req] true))

(defn new-authentication-login-form [& {:as opts}]
  (->> opts
       (merge {:cookie-id MFA-AUTH-COOKIE
               :fields [{:name "user" :label "User" :placeholder "userid"}
                        {:name "password" :label "Password" :password? true :placeholder "password"}]})
       (s/validate {:cookie-id s/Str
                    :fields [{:name s/Str
                              :label s/Str
                              (s/optional-key :placeholder) s/Str
                              (s/optional-key :password?) s/Bool}]})
       map->LoginForm
       (<- (component/using [:user-domain :session-store :renderer]))))

(defrecord TimeBasedOneTimePasswordForm [cookie-id]
  WebService
  (request-handlers [this]
    {::GET-totp-form
     (fn [req]
       ;; TODO this "let .. secret " is only for showing the helper message to the developer
       ;; TODO  remove in production
       (let [identity (get-session-value req cookie-id (:session-store this) :cylon/identity)
             secret (get-totp-secret (:user-domain this) identity)]
         (if secret
           {:status 200
            :body (html
                   [:body
                    [:h1 "TOTP Form"]
                    [:form {:method :post
                            :action (path-for req ::POST-totp-form)}
                     [:p
                      [:label {:for "totp-code"} "Code"]
                      [:input {:name "totp-code" :id "totp-code" :type "text"}]]
                     [:p [:input {:type "submit"}]]
                     (when secret [:p "(Hint, maybe it's something like... this ? " (totp-token secret) ")"])
                     ]])}
           ;; skip interaction step with flag => :status 999
           {:status 403}))
       )

     ::POST-totp-form
     (->
      (fn [req]
        (let [params (-> req :form-params)
              totp-code (get params "totp-code")
              identity (get-session-value req  cookie-id (:session-store this) :cylon/identity)
              secret (get-totp-secret (:user-domain this) identity)
              ]
          (if
              (= totp-code (totp-token secret))

            {:status 200
             :body "Thank you! That was the correct code"
             ;; How do we signal to the dependant that we want to move to the next.
             }

            {:status 403
             :body "Bad guess!!! Please try again :)"}

            )))
      wrap-params wrap-cookies)})

  (routes [_] ["/" {"login" {:get ::GET-totp-form
                             :post ::POST-totp-form}}])
  (uri-context [_] "/totp-form")

  InteractionStep
  (get-location [this req]
    (path-for req ::GET-totp-form)
    )
  (step-required? [this req]
    (let [identity (get-session-value req cookie-id (:session-store this) :cylon/identity)]
      (not (nil? (get-totp-secret (:user-domain this) identity))))))

(defn new-authentication-totp-form [& {:as opts}]
  (->>
   opts
   (merge {:cookie-id MFA-AUTH-COOKIE})
   (s/validate {(s/required-key :cookie-id) s/Str})
   map->TimeBasedOneTimePasswordForm
   (<- (component/using [:session-store :user-domain]))))
