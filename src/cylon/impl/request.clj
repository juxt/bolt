;; Copyright © 2014 JUXT LTD.

(ns cylon.impl.request
  (:require
   [com.stuartsierra.component :as component]
   [modular.ring :refer (RingBinding)]
   [cylon.session :refer (get-session)]
   [ring.middleware.cookies :refer (cookies-request)]
   [cylon.authentication :refer (Authenticator authenticate)]
   [schema.core :as s]))

(defrecord AuthenticatingRequestBinding []
  RingBinding
  (ring-binding [this req]
    (when-let [authenticator (:authenticator this)]
      (authenticate authenticator req))))

(defn new-auth-request-binding [& {:as opts}]
  (component/using
   (->> opts
        map->AuthenticatingRequestBinding)
   [:authenticator]))
