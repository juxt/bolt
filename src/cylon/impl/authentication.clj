;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.authentication
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [cylon.authentication :refer (Authenticator authenticate AuthenticationInteraction InteractionStep get-location step-required?)]
   [cylon.session :refer (session assoc-session-data! respond-with-new-session!)]
   [cylon.password :refer (verify-password)]
   [cylon.totp :refer (OneTimePasswordStore get-totp-secret totp-token)]
   [hiccup.core :refer (html)]
   [modular.bidi :refer (WebService request-handlers routes uri-context path-for)]
   [plumbing.core :refer (<-)]
   [ring.middleware.cookies :refer (cookies-response wrap-cookies)]
   [ring.middleware.params :refer (wrap-params)]
   [ring.util.response :refer (redirect redirect-after-post)]
   [schema.core :as s])
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

(defrecord HttpBasicAuthenticator [password-verifier]
  Authenticator
  (authenticate [this request]
    (when-let [header (get-in request [:headers "authorization"])]
      (when-let [basic-creds (second (re-matches #"\QBasic\E\s+(.*)" header))]
        (let [[user password] (->> (String. (DatatypeConverter/parseBase64Binary basic-creds) "UTF-8")
                                   (re-matches #"(.*):(.*)")
                                   rest)]
          (when (verify-password password-verifier user password)
            {:cylon/user user
             :cylon/authentication-method :http-basic}))))))

(defn new-http-basic-authenticator [& {:as opts}]
  (component/using
   (->> opts
        map->HttpBasicAuthenticator)
   [:password-verifier]))

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

(defn get-original-uri [req]
  (str (:uri req)
       (when-let [qs (:query-string req)] (when (not-empty qs) (str "?" qs )))))

;; Again, rename to MultiFactorAuthenticator as above
(defrecord MultiFactorAuthenticationInteraction [steps session-store]
  AuthenticationInteraction
  (initiate-authentication-interaction [this req initial-session-state]
    (let [steps ((apply juxt steps) this)
          first-step (get-location (first steps) req)
          ;; I think it's DONE
          ;; (Note: It's possible that the user has already got a
          ;; session, because they might have just signed up, etc. In
          ;; which case, we should retrieve the session and treat it has
          ;; the initial-session-state)
          ]

      ;; We ALWAYS start a new session when initiating a new authentication interaction.
      (debugf "Initiating multi-factor authentication, creating new session and redirecting to first step %s" first-step)
      (respond-with-new-session!
       session-store req
       (merge initial-session-state {:cylon/original-uri (get-original-uri req)})
       (redirect first-step))))

  (get-outcome [this req]
    (session session-store req))

  ;; We proxy onto the dependencies which satisfy WebService in order to
  ;; change their behaviour.

  WebService
  (request-handlers [this]
    (debugf "Merging steps %s" steps)
    (apply merge
           (for [[step next-steps] (link-up ((apply juxt steps) this))]
             ;; The point of this is to wire together the steps.
             ;; POSTS which return 200 (OK) are 'mutated' return a 302 to the next step
             (reduce-kv
              (fn [acc k h]
                (debugf (name k) h)
                (assoc acc k
                       (fn [req]
                         (let [res (h req)]
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
                                       (assoc-session-data! (:session-store this) req {:cylon/authenticated? true})
                                       ;; TODO What's this original uri? Can it also include the query string?
                                       (let [original-uri (:cylon/original-uri (session session-store req))]
                                         (debugf "Successful authentication, redirecting to original uri of %s" original-uri)
                                         (redirect-after-post original-uri))))
                               ;; It is the default policy of this
                               ;; authenticator to allow the user to
                               ;; retry entering her credentials
                               403 (redirect-after-post (get-location step req))))))))
              {}
              (request-handlers step)))))

  (routes [this]
    ["" (vec (for [step ((apply juxt steps) this)]
               [(uri-context step) [(routes step)]]))])

  (uri-context [this] ""))

(defrecord AuthBug []
  WebService
  (request-handlers [this]
    {::GET-other
     (fn [req]
       {:status 200
        :body "bug"})
     }
    )
  (routes [_] ["/" {"bug" {:get ::GET-other}}])
  (uri-context [_] "/other")

  InteractionStep
  (get-location [this req]
    (path-for req ::GET-other)
    )
  (step-required? [this req]
    false))

(defn new-auth-bug [& {:as opts}]
  (->>
   opts
   map->AuthBug))

(defn new-multi-factor-authentication-interaction [& {:as opts}]
  (component/using
   (->> opts
        (s/validate {:steps [s/Keyword]})
        map->MultiFactorAuthenticationInteraction)
   (conj (:steps opts) :session-store)))

;; TODO Move to cylon.authentication.protocols
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
(defrecord LoginForm [fields session-store password-verifier renderer]
  WebService
  (request-handlers [this]
    {::GET-login-form
     (fn [req]
       (debugf "Rendering basic login form")
       (let [response
             {:status 200
              :body (render-login-form
                     renderer req
                     {:form {:method :post
                             :action (path-for req ::POST-login-form)
                             :signup-uri (path-for req :cylon.signup.signup/GET-signup-form)
                             :fields fields}})}]
        ;; Conditional response post-processing
        (if
         ;; In the absence of a session...
            (not (session session-store req))
         ;; We create an empty one. This is because the POST handler
         ;; requires that a session exists within which it can store the
         ;; identity on a successful login
         (respond-with-new-session! session-store req response {})
         response)))

     ::POST-login-form
     (->
      (fn [req]
        (let [params (:form-params req)
              uid (get params "user")
              password (get params "password")
              session (session session-store req)]

          (if (and uid
                   (not-empty uid)
                   (verify-password password-verifier (.trim uid) password))
            (do
              (assoc-session-data! session-store req {:cylon/subject-identifier uid})
              {:status 200
               :body "Thank you! - you gave the correct information!"})

            {:status 403
             :body "Bad guess!!! Please try again :)"}
            )))
      wrap-params wrap-cookies)})

  (routes [_] ["/" {"login" {:get ::GET-login-form
                             :post ::POST-login-form}}])
  (uri-context [_] "")

  InteractionStep
  (get-location [this req]
    (path-for req ::GET-login-form))
  (step-required? [this req] true)
  )

(defn new-authentication-login-form [& {:as opts}]
  (->> opts
       (merge {:fields [{:name "user" :label "User" :placeholder "id or email"}
                        {:name "password" :label "Password" :password? true :placeholder "password"}]})
       (s/validate {:fields [{:name s/Str
                              :label s/Str
                              (s/optional-key :placeholder) s/Str
                              (s/optional-key :password?) s/Bool}]})
       map->LoginForm
       (<- (component/using [:password-verifier :session-store :renderer]))))

(defrecord TimeBasedOneTimePasswordForm [totp-store session-store]
  WebService
  (request-handlers [this]
    {::GET-totp-form
     (fn [req]
       ;; TODO this "let .. secret " is only for showing the helper message to the developer
       ;; TODO  remove in production
       (let [uid (:cylon/subject-identifier (session session-store req))
             secret (get-totp-secret totp-store uid)]
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
        (let [params (:form-params req)
              totp-code (get params "totp-code")
              uid (:cylon/subject-identifier (session session-store req))
              secret (get-totp-secret totp-store uid)]
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

  (routes [_] ["/" {"totp-challenge"
                    {:get ::GET-totp-form
                     :post ::POST-totp-form}}])
  (uri-context [_] "")

  InteractionStep
  (get-location [this req]
    (path-for req ::GET-totp-form)
    )
  (step-required? [this req]
    false
    #_(let [uid (get-data session-store req  :cylon/subject-identifier)]
        (not (nil? (get-totp-secret totp-store uid))))))

(defn new-authentication-totp-form [& {:as opts}]
  (->>
   opts
   (merge {})
   map->TimeBasedOneTimePasswordForm
   (<- (component/using [:session-store :totp-store]))))
