;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.password
  (:require
   [clojure.java.io :as io]
   [clojure.pprint :refer (pprint)]
   [com.stuartsierra.component :as component]
   [cylon.user :refer (UserAuthenticator)]
   [cylon.password :refer (PasswordStore store-user-hash! get-hash-for-uid NewUserCreator PasswordHashAlgorithm make-hash)])
  (:import
   (java.security SecureRandom)
   (javax.xml.bind DatatypeConverter)))

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

(defrecord PasswordFile [f]
  component/Lifecycle
  (start [this]
    (assoc this
      :ref (ref (if (.exists f) (read-string (slurp f)) {}))
      :agent (agent f)))
  (stop [this] this)

  PasswordStore
  (get-hash-for-uid [this uid] (get @(:ref this) uid))
  (store-user-hash! [this uid hash]
    (dosync
     (alter (:ref this) assoc uid hash)
     (send-off (:agent this) (fn [f]
                               (spit f (with-out-str (pprint @(:ref this))))
                               f))
     (get @(:ref this) uid))))

(defn new-password-file [& {f :password-file}]
  (let [f (io/file f)]
    (assert (.exists (.getParentFile f))
            (format "Please create the directory structure which should contain the password file: %s" f))
    (->PasswordFile f)))

(defrecord UserDomain []
  component/Lifecycle
  (start [this] (assoc this :rng (SecureRandom.)))
  (stop [this] this)

  UserAuthenticator
  (authenticate-user [this uid pw]
    (when-let [hash (get-hash-for-uid (:password-store this) uid)]
      (verify-password pw hash)
      ;; TODO There is a slight security concern here. If no uid is
      ;; found, then the system will return slightly faster and this can
      ;; be measured by an attacker to discover usernames. I don't know
      ;; what the current advice is regarding this problem. I have
      ;; consdiered priming the user store with a 'nobody' password to
      ;; use.
      ))

  NewUserCreator
  (add-user! [this uid pw]
    (store-user-hash! (:password-store this) uid (create-hash (:rng this) pw))))

(defn new-user-domain []
  (component/using (->UserDomain) [:password-store]))
