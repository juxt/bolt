;; Copyright © 2015, JUXT LTD. All Rights Reserved.

(ns bolt.user.email-user-store-test
  (:require
   [clojure.test :refer :all]
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [bolt.test-utils :refer (with-system-fixture *system* new-test-system)]
   [bolt.user.email-user-store :refer (new-email-user-store)]
   [bolt.user :refer (create-user!)]
   ))

(use-fixtures
  :each (with-system-fixture
          #(new-test-system {:store (new-email-user-store)
                             :storage (atom {})})))

(deftest create-users
  (let [user-store (:store *system*)
        storage (-> user-store :storage :ref)]

    (is (= (count @storage) 0))
    (create-user! user-store
                  "alice@example.org"
                  {:email "alice@example.org" :roles #{:superuser}})

    (is (= (count @storage) 1))

    (create-user! user-store
                  "bob@example.org"
                  {:email "bob@example.org" :roles #{:user}})
    (is (= (count @storage) 2))

))
