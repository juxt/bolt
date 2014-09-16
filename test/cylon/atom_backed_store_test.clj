(ns cylon.atom-backed-store-test
  (:require
   [clojure.test :refer :all]
   [cylon.store.atom-backed-store :refer :all]
   [cylon.store :refer :all]
   [schema.core :as s]))

(defn atom-fixture [f]
  (s/with-fn-validation
    (f)))

(use-fixtures :each atom-fixture)

;; We must only run these tests when the code it is testing
;; changes. It's OK to use time based tests to be really sure of the
;; behaviour.

(deftest non-expiry-tests
  (testing "create token"
    (let [tokens (atom {})
          component (->AtomBackedTokenStore nil tokens)]
      (create-token! component 123 {:a "A"})
      (is (= {:a "A"} (get-token-by-id component 123)))))

  (testing "renew token should return the new token"
    (let [tokens (atom {})
          component (->AtomBackedTokenStore nil tokens)]
      (create-token! component 123 {:a "A"})
      (is (= {:a "A"} (get-token-by-id component 123)))
      (let [token (renew-token! component 123)]
        (is (= {:a "A"} token))))))

(deftest expiry-tests
  (testing "create token"
    (let [ttl 1
          tokens (atom {})
          component (->AtomBackedTokenStore 1 tokens)]
      (create-token! component 123 {:a "A"})
      (is (= {:a "A"} (select-keys (get-token-by-id component 123) [:a])))
      (is (contains? (get-token-by-id component 123) :cylon/expiry))))

  (testing "expiry"
    (let [ttl 1
          tokens (atom {})
          component (->AtomBackedTokenStore 1 tokens)]
      (create-token! component 123 {:a "A"})
      (is (not (nil? (get-token-by-id component 123))))
      (Thread/sleep 1000)
      (is (nil? (get-token-by-id component 123)))))

  (testing "renewal on get"
    (let [ttl 1
          tokens (atom {})
          component (->AtomBackedTokenStore 1 tokens)]
      (create-token! component 123 {:a "A"})
      (is (not (nil? (get-token-by-id component 123))))
      (Thread/sleep 500)
      (is (not (nil? (get-token-by-id component 123))))
      (Thread/sleep 750)
      (is (not (nil? (get-token-by-id component 123))))
      (Thread/sleep 1000)
      (is (nil? (get-token-by-id component 123))))))
