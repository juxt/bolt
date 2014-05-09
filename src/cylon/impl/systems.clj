;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.systems
  (:require
   [cylon.user :refer (UserAuthenticator)]
   [cylon.impl.login-form :refer (new-login-form)]
   [cylon.impl.session-atom :refer (new-atom-backed-session-store)]
   [cylon.password :refer (new-user-domain new-password-file NewUserCreator add-user!)]
   [schema.core :as s]
   [modular.bidi :refer (WebService ring-handler-map routes uri-context)]
   [com.stuartsierra.component :as component]))

(defrecord ProtectionSystem [user-authenticator]
  component/Lifecycle
  (start [this] (component/start-system this (keys this)))
  (stop [this] (component/stop-system this (keys this)))
  ;; In this implementation, we export any routes provided by
  ;; sub-components. These are the routes that provide login forms and
  ;; so on, nothing to do with the routes that are protected by this
  ;; protection system.

  WebService
  (ring-handler-map [this] (apply merge (keep #(when (satisfies? WebService %) (ring-handler-map %)) (vals this))))
  (routes [this] ["" (vec (keep #(when (satisfies? WebService %) (routes %)) (vals this)))])
  (uri-context [this] (or
                   (first (keep #(when (satisfies? WebService %) (uri-context %))
                                ((juxt :login-form :user-authenticator :http-session-store) this)))
                   ""))

  ;; Replace this with a more general 'restrict-handler' (to roles) which implies authentication - policies to be determined by sub-component
  #_BidiRoutesProtector
  #_(protect-bidi-routes [this routes]
    (add-bidi-protection-wrapper
     routes
     :http-request-authenticator (new-session-based-request-authenticator :http-session-store http-session-store :user-roles user-roles)
     :failed-authentication-handler (->BidiFailedAuthenticationRedirect (get-in (:login-form this) [:handlers :login]))))

  NewUserCreator
  (add-user! [_ uid pw]
    (if (satisfies? NewUserCreator user-authenticator)
      (add-user! user-authenticator uid pw)
      (throw (ex-info "This protection system implementation does not support the creation of new users" {})))))

;; Now we have all the parts to  build a protection system, composed of a login form, user
;; authenticator and session store. Different constructors can build this
;; component in different ways.

(def new-default-protection-system-schema
  {:password-file s/Any
   (s/optional-key :session-timeout-in-seconds) s/Int
   (s/optional-key :boilerplate) (s/=> 1)
   })

(defn new-default-protection-system [& {:as opts}]
  (s/validate new-default-protection-system-schema opts)
  (map->ProtectionSystem
   {:login-form (if-let [boilerplate (:boilerplate opts)]
                  (new-login-form :boilerplate boilerplate)
                  (new-login-form))
    :user-authenticator (component/using (new-user-domain) [:password-store])

    :password-store (new-password-file (:password-file opts))
    :http-session-store (new-atom-backed-session-store
                         (or (:session-timeout-in-seconds opts)
                             (* 60 60)  ; one hour by default
                             ))
    }))
