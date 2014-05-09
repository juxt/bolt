;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.password
  (:require
   [clojure.java.io :as io]
   [com.stuartsierra.component :as component]
   [cylon.user :refer (UserAuthenticator)]
   [clojure.pprint :refer (pprint)])
  (:import javax.crypto.SecretKeyFactory
           javax.crypto.spec.PBEKeySpec
           java.security.SecureRandom))


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

(defn make-salt
  "Make a base64 string representing a salt. Pass in a SecureRandom."
  [rng]
  (let [ba (byte-array 32)]
    (.nextBytes rng ba)
    (javax.xml.bind.DatatypeConverter/printBase64Binary ba)))

(defn create-hash [rng password]
  (let [salt (make-salt rng)
        hash (pbkdf2 password salt)]
    {:salt salt
     :hash hash}))

(defn verify-password [password {:keys [hash salt]}]
  (= (pbkdf2 password salt) hash))


(defprotocol PasswordStore
  ;; Returns a map of :hash and :salt
  (get-hash-for-uid [_ uid])
  (store-user-hash! [_ uid hash]))

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

(defn new-password-file [f]
  (let [f (io/file f)]
    (assert (.exists (.getParentFile f))
            (format "Please create the directory structure which should contain the password file: %s" f))
    (->PasswordFile f)))

(defprotocol NewUserCreator
  (add-user! [_ uid pw]))

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
