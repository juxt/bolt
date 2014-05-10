;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.role
  (:require [clojure.set :as set]))

(defprotocol RoleQualifier
  (matches-role? [_ role]))

(extend-protocol RoleQualifier
  clojure.lang.Keyword
  (matches-role? [this roles]
    (roles this))

  clojure.lang.PersistentHashSet
  (matches-role? [this roles]
    (let [res (set/intersection this roles)]
      (when (not-empty res) res)))

  clojure.lang.PersistentVector
  (matches-role? [this roles]
    (when (every? #(matches-role? % roles) this)
      this))

  Boolean
  (matches-role? [this roles] this))

(defprotocol UserRoles
  (user-in-role? [_ user role]))

(extend-protocol UserRoles
  clojure.lang.PersistentArrayMap
  (user-in-role? [this user role]
    (when-let [roles (get this user)]
      (matches-role? role roles)))

  clojure.lang.PersistentHashMap
  (user-in-role? [this user role]
    (when-let [roles (get this user)]
      (matches-role? role roles)))

  clojure.lang.Fn
  (user-in-role? [this user role]
    (this user role))

  nil
  (user-in-role? [this user role]
    nil))
