(ns bolt.user.buddy-user-authenticator
  (:require
   [buddy.hashers :as hs]
   [bolt.user.protocols :refer (UserAuthenticator UserPasswordHasher)]))



(defrecord BuddyUserAuthenticator []
  UserAuthenticator
  (authenticate-user [_ user evidence]
    (throw (ex-info "TODO" {})))
  UserPasswordHasher
  (hash-password [_ password]
    (hs/encrypt password)))

(defn new-buddy-user-authenticator [& {:as opts}]
  (->> opts
       (merge {})
       map->BuddyUserAuthenticator))
