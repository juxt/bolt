;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.pbkdf2
  (:require
   [cylon.password :refer (PasswordHashAlgorithm)])
  (:import
   (javax.crypto SecretKeyFactory)
   (javax.crypto.spec PBEKeySpec)))

(def PASSWORD_HASH_ALGO "PBKDF2WithHmacSHA1")

(defn pbkdf2
  "Get a hash for the given string and optional salt. From
http://adambard.com/blog/3-wrong-ways-to-store-a-password/"
  ([password salt]
     (assert password "No password!")
     (assert salt "No salt!")
     (let [k (PBEKeySpec. (.toCharArray password) (.getBytes salt) 1000 192)
           f (SecretKeyFactory/getInstance PASSWORD_HASH_ALGO)]
       (format "%x"
               (java.math.BigInteger. (.getEncoded (.generateSecret f k)))))))

(defrecord Pbkdf2PasswordHash []
  PasswordHashAlgorithm
  (make-hash [_ password salt]
    (pbkdf2 password salt)))

(defn new-pbkdf2-password-hash [& {:as opts}]
  (->> opts map->Pbkdf2PasswordHash))
