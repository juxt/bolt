;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.authorization
  (:require
   [cylon.authorization :refer (Authorizer restrict-handler)]
   [modular.ring :refer (RingBinding)]))

(defn restrict-handler-map
  "Restrict all the values in the given map according to the given
  authorizer."
  [m authorizer rejectfn]
  (reduce-kv (fn [acc k v] (assoc acc k (restrict-handler v authorizer rejectfn))) {} m))

(defrecord UserBasedAuthorizer []
  Authorizer
  (validate [this req] nil)

  (satisfies-requirement? [this request user]
    (= user (:cylon/user request))))

(defn new-user-based-authorizer [& {:as opts}]
  (->> opts
       map->UserBasedAuthorizer))

(defrecord RoleBasedAuthorizer []
  Authorizer
  (validate [this req]
    {:cylon/roles #{:user}})

  (satisfies-requirement? [this request requirement]
    (when-let [roles (:cylon/roles request)]
      (println "roles: " roles ", requirement" requirement)
      (roles requirement))))

(defn new-role-based-authorizer [& {:as opts}]
  (->> opts
       map->RoleBasedAuthorizer))
