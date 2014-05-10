;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.password)

(defprotocol PasswordStore
  ;; Returns a map of :hash and :salt
  (get-hash-for-uid [_ uid])
  (store-user-hash! [_ uid hash]))

(defprotocol NewUserCreator
  (add-user! [_ uid pw]))

(defprotocol PasswordHashAlgorithm
  (make-hash [_ password salt]))
