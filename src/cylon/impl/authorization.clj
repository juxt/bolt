;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.authorization
  (:require
   [clojure.set :refer (union)]
   [clojure.tools.logging :refer :all]
   [cylon.role :refer (user-in-role?)]
   [cylon.authorization :refer (Authorizer restrict-handler)]
   [modular.ring :refer (RingBinding)]
   [schema.core :as s]))

(defn restrict-handler-map
  "Restrict all the values in the given map according to the given
  authorizer."
  [m authorizer rejectfn]
  (reduce-kv (fn [acc k v] (assoc acc k (restrict-handler v authorizer rejectfn))) {} m))

(defrecord LoggedInAuthorizer []
  Authorizer
  (authorized? [this request _]
    (:cylon/user request)))

(defn new-logged-in-authorizer []
  (->LoggedInAuthorizer))

(defrecord StaticUserAuthorizer []
  Authorizer
  (authorized? [this request user]
    (= user (:cylon/user request))))

(defn new-static-user-authorizer [& {:as opts}]
  (->> opts
       map->StaticUserAuthorizer))

(defrecord RoleBasedAuthorizer [user-role-mappings]
  Authorizer
  (authorized? [this request requirement]
    (when-let [roles (:cylon/roles request)]
      (user-in-role? user-role-mappings (:cylon/user request) requirement))))

(defn new-role-based-authorizer [& {:as opts}]
  (->> opts
       (s/validate {:user-role-mappings s/Any})
       map->RoleBasedAuthorizer))
