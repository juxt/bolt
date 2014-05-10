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

(defrecord RoleBasedRequestAuthorizer []
  RingBinding
  (ring-binding [this req]
    ;; TODO Look in (:session req) for roles
    {::user-roles #{:user}})

  Authorizer
  (validate [this req]
    (assoc req ::user-roles #{:user}))

  (satisfies-requirement? [this request requirement]
    (when-let [user-roles (::user-roles request)]
      (user-roles requirement))))

(defn new-role-based-request-authorizer [& {:as opts}]
  (->> opts
       map->RoleBasedRequestAuthorizer))
