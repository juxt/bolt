(ns cylon.roles-test
  (:require
   [clojure.test :refer :all]
   [clojure.set :as set]))

;; A protection system can depend on a UserRoles component, which is assoc'd into each the request with the username.

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
      this)))

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
    (this user role)))

(deftest user-roles
  (testing "map"
    (let [roles {"alice" #{:accountant :clerk}
                 "bob" #{:clerk}}]
      (are [user roleq _ result] (is (= (user-in-role? roles user roleq) result))
           "alice" :accountant => :accountant
           "alice" :clerk => :clerk
           "alice" #{:accountant :superuser} => #{:accountant}
           "bob" #{:accountant :superuser} => nil
           "bob" :accountant => nil
           "bob" #{:accountant :clerk} => #{:clerk}
           "alice" [:accountant :clerk] => [:accountant :clerk]
           "bob" [:accountant :clerk] => nil
           )))
  (testing "fn"
    (let [roles (fn [user role] (= user "alice"))]
      (are [user roleq _ result] (is (= (user-in-role? roles user roleq) result))
           "alice" :accountant => true
           "alice" :clerk => true
           "bob" :clerk => false
           ))))
