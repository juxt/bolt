(ns cylon.roles-test
  (:require
   [cylon.core :refer :all]
   [clojure.test :refer :all]
   [clojure.set :as set]))

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
           ;; Booleans are useful for testing
           "alice" true => true
           "bob" false => false
           )))
  (testing "fn"
    (let [roles (fn [user role] (= user "alice"))]
      (are [user roleq _ result] (is (= (user-in-role? roles user roleq) result))
           "alice" :accountant => true
           "alice" :clerk => true
           "bob" :clerk => false
           )))
  ;; Nil needs to be supported in cases where no user roles have been established.
  (testing "nil"
    (let [roles nil]
      (are [user roleq _ result] (is (= (user-in-role? roles user roleq) result))
           "alice" :accountant => nil
           "alice" :clerk => nil
           "bob" :clerk => nil
           ))))
