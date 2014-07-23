;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.authentication
  (:require
   [com.stuartsierra.component :as component]
   [cylon.authentication :refer (Authenticator authenticate AuthenticationInteraction InteractionStep get-location)]
   [clojure.tools.logging :refer :all]
   [cylon.user :refer (UserStore verify-user)]
   [schema.core :as s]
   [ring.middleware.cookies :refer (cookies-response wrap-cookies)]
   [bidi.bidi :refer (path-for)]
   [ring.util.response :refer (redirect-after-post)]
   [ring.middleware.params :refer (wrap-params)]
   [modular.bidi :refer (WebService request-handlers routes uri-context)]
   [cylon.session :refer (->cookie create-session! get-session get-session-id assoc-session! cookies-response-with-session get-session-from-cookie)]
   [hiccup.core :refer (html)])
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

;; (If you're looking for CookieAuthenticator, it's in cylon.impl.session)


;; -----------------------------------------------------------------------

;; Again, rename to MultiFactorAuthenticator as above
(defrecord MultiFactorAuthenticationInteraction [steps]
  AuthenticationInteraction
  (initiate-authentication-interaction [this req initial-session-state]
    (let [steps ((apply juxt steps) this)
          session (create-session!
                   (:session-store this)
                   (merge initial-session-state
                          {:cylon/original-uri (:uri req)}))]

      (cookies-response-with-session
       {:status 302
        :headers {"Location" (get-location (first steps) req)}}
       "mfa-auth-session-id"
       session)))
  (get-result [this req]
    (get-session-from-cookie  req "mfa-auth-session-id" (:session-store this)))

  ;; We proxy onto the dependencies which satisfy WebService in order to
  ;; change their behaviour.
  WebService
  (request-handlers [this]
    (apply merge
           (for [[step next-step] (partition 2 1 nil ((apply juxt steps) this))]
             (reduce-kv
              (fn [acc k h]
                (assoc acc k
                       (fn [req]
                         (if (not= (:request-method req) :post)
                           (h req)
                           (let [res (h req)
                                 session-id (get-session-id req "mfa-auth-session-id")
                                 session (get-session (:session-store this) session-id)]
                             (case (:status res)
                               200 (if next-step
                                     {:status 302
                                      :headers {"Location" (get-location next-step req)}
                                      :body "Authenticator: Move to the next step"}

                                     ;; No more steps, we're done. Redirect to the initiator.
                                     (do
                                       (assoc-session! (:session-store this) session-id :cylon/authenticated? true)
                                       (redirect-after-post (:cylon/original-uri session))
                                       ))
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

(defn new-multi-factor-authentication-interaction [& {:as opts}]
  (component/using
   (->> opts
        (s/validate {:steps [s/Keyword]})
        map->MultiFactorAuthenticationInteraction)
   (conj (:steps opts) :session-store)))

(defrecord LoginForm []
  WebService
  (request-handlers [this]
    {:GET-login-form
     (fn [req]
       (println "GET session id is " (get-session-id req "mfa-auth-session-id"))
       {:status 200
        :body (html
               [:body
                [:h1 "Login Form"]
                [:form {:method :post
                        :action (path-for (:modular.bidi/routes req) ::POST-login-form)}
                 [:p
                  [:label {:for "user"} "User"]
                  [:input {:name "user" :id "user" :type "text"}]]
                 [:p
                  [:label {:for "password"} "Password"]
                  [:input {:name "password" :id "password" :type "password"}]]
                 [:p [:input {:type "submit"}]]
                 ]])})
     :POST-login-form
     (->
      (fn [req]
        (let [params (-> req :form-params)
              identity (get params "user")
              password (get params "password")
              _ (assert (:session-store this))
              _ (println "session id is " (get-session-id req "mfa-auth-session-id"))
              session (get-session (:session-store this) (get-session-id req "mfa-auth-session-id"))]
          (assert session)
          (if (and identity
                   (not-empty identity)
                   (verify-user (:user-domain this) (.trim identity) password))
            (do
              (println "Existing session: " session)
              (assoc-session! (:session-store this) (get-session-id req "mfa-auth-session-id") :cylon/identity identity)
              (println "New session: " (get-session (:session-store this) (get-session-id req "mfa-auth-session-id")))
              {:status 200
               :body "Thank you! - you gave the correct information!"})
            {:status 403
             :body "Bad guess!!! Please try again :)"}
            )))
      wrap-params wrap-cookies)})

  (routes [_] ["/" {"login" {:get :GET-login-form
                             :post :POST-login-form}}])
  (uri-context [_] "/login-form")

  InteractionStep
  (get-location [this req]
    (path-for (:modular.bidi/routes req) :GET-login-form)
    ))


(defn new-authentication-login-form [& {:as opts}]
  (component/using (->LoginForm) [:user-domain :session-store]))


(defrecord TimeBasedOneTimePasswordForm []
  WebService
  (request-handlers [this]
    {:GET-totp-form
     (fn [req]
       {:status 200
        :body (html
               [:body
                [:h1 "TOTP Form"]
                [:form {:method :post
                        :action (path-for (:modular.bidi/routes req) ::POST-totp-form)}
                 [:p
                  [:label {:for "totp-code"} "Code"]
                  [:input {:name "totp-code" :id "totp-code" :type "text"}]]
                 [:p [:input {:type "submit"}]]
                 ]])})

     :POST-totp-form
     (->
      (fn [req]
        (let [params (-> req :form-params)
              totp-code (get params "totp-code")
              session (get-session (:session-store this) (get-session-id req "mfa-auth-session-id"))]
          (println ">>> session is " session)
          (if
              true ; assume it's the correct code for now

            {:status 200
             :body "Thank you! That was the correct code"
             ;; How do we signal to the dependant that we want to move to the next.
             }

            {:status 403
             :body "Bad guess!!! Please try again :)"}

            )))
      wrap-params wrap-cookies)})

  (routes [_] ["/" {"login" {:get :GET-totp-form
                             :post :POST-totp-form}}])
  (uri-context [_] "/totp-form")

  InteractionStep
  (get-location [this req]
    (path-for (:modular.bidi/routes req) :GET-totp-form)
    ))

(defn new-authentication-totp-form [& {:as opts}]
  (->TimeBasedOneTimePasswordForm))
