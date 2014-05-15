;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.user
  (:require
   ;;[cylon.password :refer (get-hash-for-user store-user-hash! verify-password)]
   ;;[cylon.impl.password :refer (create-hash)]
   [clojure.java.io :as io]
   [clojure.pprint :refer (pprint)]
   [com.stuartsierra.component :as component]
   [cylon.user :refer (UserStore get-user store-user! UserDomain)]
   [cylon.password :refer (create-hash verify-password)])
  (:import
   (java.security SecureRandom)))

(defrecord UserFile [f]
  component/Lifecycle
  (start [this]
    (assoc this
      :ref (ref (if (.exists f) (read-string (slurp f)) {}))
      :agent (agent f)))
  (stop [this] this)

  UserStore
  (get-user [this uid] (get @(:ref this) uid))
  (store-user! [this uid user]
    (dosync
     (alter (:ref this) assoc uid user)
     (send-off (:agent this)
               (fn [f]
                 (spit f (with-out-str (pprint @(:ref this))))
                 f))
     (get @(:ref this) uid))))

(defn new-user-file [& {f :file}]
  (let [f (io/file f)]
    (assert (.exists (.getParentFile (.getCanonicalFile f)))
            (format "Please create the directory structure which should contain the file: %s" f))
    (->UserFile f)))

(defrecord DefaultUserDomain []
  component/Lifecycle
  (start [this] (assoc this :rng (SecureRandom.)))
  (stop [this] this)

  UserDomain
  (verify-user [this uid password]
    (verify-password (:password-hash-algo this)
                     password
                     (get-user (:user-store this) uid)))
  (add-user! [this uid password user]
    (store-user! (:user-store this) uid
                 (assoc user ::salt-hash (create-hash (:password-hash-algo this)
                                                      (:rng this) password)))))

(defn new-default-user-domain [& {:as opts}]
  (component/using
   (->> opts
        map->DefaultUserDomain)
   [:user-store :password-hash-algo]))
