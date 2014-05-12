;; Copyright © 2014 JUXT LTD.

(ns cylon.impl.request
  (:require
   [com.stuartsierra.component :as component]
   [modular.ring :refer (RingBinding)]
   [cylon.session :refer (get-session)]
   [ring.middleware.cookies :refer (cookies-request)]
   [cylon.authentication :refer (Authenticator authenticate)]
   [cylon.authorization :refer (Authorizer validate)]
   [schema.core :as s])
  )

;; Difficult to know what to call this because it does both authentication and authorization

(defrecord AuthenticatingRequestBinding []
  RingBinding
  (ring-binding [this req]
    (when-let [authenticator (:authenticator this)]
      (let [authentication (authenticate authenticator req)
            authorizer (:authorizer this)]
        ;; The policy of this component is to merge the authentication
        ;; map with the authorization one. The request given to the
        ;; authorizer includes the entries determined by the
        ;; authentication, such as :cylon/user.
        (merge authentication (validate authorizer (merge req authenticator)))))))

(defn new-auth-request-binding [& {:as opts}]
  (component/using
   (->> opts
        map->AuthenticatingRequestBinding)
   [:authenticator :authorizer]))
