;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.user
  (:require
   ;;[cylon.password :refer (get-hash-for-user store-user-hash! verify-password)]
   ;;[cylon.impl.password :refer (create-hash)]
   [clojure.java.io :as io]
   [clojure.pprint :refer (pprint)]
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [cylon.user :refer (UserStore get-user store-user! UserDomain add-user!)]
   [cylon.password :refer (create-hash verify-password)]
   [schema.core :as s]
   [plumbing.core :refer (<-)])
  (:import
   (java.security SecureRandom)))

(defrecord UserFile []
  component/Lifecycle
  (start [this]
    (let [f (:file this)]
      (assoc this
        :ref (ref (if (.exists f) (read-string (slurp f)) {}))
        :agent (agent f))))
  (stop [this] this)

  UserStore
  (get-user [this identity] (get @(:ref this) identity))
  (store-user! [this identity user]
    (dosync
     (alter (:ref this) assoc identity user)
     (send-off (:agent this)
               (fn [f]
                 (spit f (with-out-str (pprint @(:ref this))))
                 (:file this)))
     (get @(:ref this) identity))))

(defn check-file-parent [{f :file :as opts}]
  (assert (.exists (.getParentFile (.getCanonicalFile f)))
          (format "Please create the directory structure which should contain the file: %s" f))
  opts)

(defn new-user-file [& {:as opts}]
  (->> opts
       (s/validate {:file s/Any})
       (#(update-in % [:file] io/file))
       check-file-parent
       map->UserFile))

(defrecord DefaultUserDomain []
  component/Lifecycle
  (start [this] (assoc this :rng (SecureRandom.)))
  (stop [this] this)

  UserDomain
  (verify-user [this identity password]
    (debugf "Lookup user by identity %s" identity)
    (if-let [user (get-user (:user-store this) identity)]
      (do
        (debugf "Lookup user by id %s, get-user returned %s" identity user)
        (let [res
              (verify-password (:password-hash-algo this)
                               password
                               (::salt-hash user))]
          (debugf "Verify of password for user %s: %s" identity res)
          res))
      (debugf "No user found in store for identity %s" identity)))

  (add-user! [this identity password user]
    (store-user! (:user-store this) identity
                 (assoc user ::salt-hash (create-hash (:password-hash-algo this)
                                                      (:rng this) password)))))

(defn new-default-user-domain [& {:as opts}]
  (component/using
   (->> opts
        map->DefaultUserDomain)
   [:user-store :password-hash-algo]))

;; Seeder (only to be used in dev systems)

(defrecord UserDomainSeeder [users]
  component/Lifecycle
  (start [component]
    (doseq [{:keys [id password]} users]
      (do
        (println (format "Adding user '%s' with password: %s" id password))
        (add-user! (:cylon/user-domain component) id password {:name "Development user"})))
    component)
  (stop [component] component))

(defn new-user-domain-seeder [& {:as opts}]
  (->> opts
       (s/validate {:users [{:id s/Str :password s/Str}]})
       map->UserDomainSeeder
       (<- (component/using [:cylon/user-domain]))))
