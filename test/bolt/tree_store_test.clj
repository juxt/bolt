(ns bolt.tree-store-test
  (:require
   [clojure.test :refer :all]
   [bolt.storage :as st])
  )

(deftest basic-test []
  (let [a (atom {})]
    (st/assoc-in a [:a :b :c] 1)
    (st/update-in a [:a :b :c] inc)
    (is (= (st/get-in a [:a :b :c]) 2))))
