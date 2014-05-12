;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.password
  (:import
   (javax.xml.bind DatatypeConverter)))

(defprotocol PasswordHashAlgorithm
  (make-hash [_ password salt]))

(defn make-salt
  "Make a base64 string representing a salt. Pass in a SecureRandom."
  [rng]
  (let [ba (byte-array 32)]
    (.nextBytes rng ba)
    (DatatypeConverter/printBase64Binary ba)))

(defn create-hash [algo rng password]
  (let [salt (make-salt rng)
        hash (make-hash algo password salt)]
    {:salt salt :hash hash}))

(defn verify-password [algo password {:keys [hash salt]}]
  (= (make-hash algo password salt) hash))
