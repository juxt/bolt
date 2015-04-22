;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.password
  (:require
   [cylon.password.protocols :refer (make-hash check PasswordPolicy) :as p]
   [cylon.user :refer (get-user get-user-password-hash PasswordHashWithSalt)]
   [schema.core :as s]
   [plumbing.core :refer (<-)]
   [com.stuartsierra.component :refer (Lifecycle using)])
  (:import
   (javax.xml.bind DatatypeConverter)
   (java.security SecureRandom)))

(defn make-salt
  "Make a base64 string representing a salt. Pass in a SecureRandom."
  [rng]
  (let [ba (byte-array 32)]
    (.nextBytes rng ba)
    (DatatypeConverter/printBase64Binary ba)))

(defn ->hashed-password [algo rng password]
  (let [salt (make-salt rng)]
    {:salt salt :hash (make-hash algo password salt)}))

;; PasswordPolicy API

(s/defn check-password-for-validity :- (s/maybe {:reason s/Str})
  [component :- (s/protocol PasswordPolicy)
   password :- s/Str]
  (p/check-password-for-validity component password))

(defrecord SimplePasswordPolicy []
  p/PasswordPolicy
  (check-password-for-validity [_ password]
    (when (< 6 (count password))
      {:reason "Password too short"})))

;; Password verification

(s/defn verify-password :- s/Any
  [component :- (s/protocol p/PasswordVerifier)
   user :- s/Str
   password :- s/Str]
  (p/verify-password component user password))

(s/defn make-password-hash :- PasswordHashWithSalt
  [component :- (s/protocol p/PasswordVerifier)
   password :- s/Str]
  (p/make-password-hash component password))

(defrecord UserStorePasswordVerifier [user-store password-hash-algo]
  Lifecycle
  (start [this] (assoc this :rng (SecureRandom.)))
  (stop [this] this)
  p/PasswordVerifier
  (verify-password [_ uid password]
    (when-let [{:keys [salt hash]} (get-user-password-hash user-store uid)]
      (check password-hash-algo password salt hash)))
  (make-password-hash [component password]
    (->hashed-password password-hash-algo (:rng component) password)))

(defn new-user-store-password-verifier [& {:as opts}]
  (->> opts
       (merge {})
       map->UserStorePasswordVerifier
       (<- (using [:user-store :password-hash-algo]))))

;; For backward compatibility
;; TODO: DEPRECATED, should delete
(def new-durable-password-verifier new-user-store-password-verifier)
