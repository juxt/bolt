;; Copyright © 2015, JUXT LTD. All Rights Reserved.

(ns bolt.user.email-user-store
  (:require
   [clojure.tools.logging :refer :all]
   [bolt.user :refer (check-create-user)]
   [bolt.user.protocols :refer (UserStore)]
   [bolt.storage.protocols :refer (find-object store-object!)]
   [com.stuartsierra.component :refer (Lifecycle using)]
   [clojure.pprint :refer (pprint)]
   [clojure.java.io :as io]
   [clojure.tools.logging :refer :all]
   [schema.core :as s]
   [plumbing.core :refer (<-)]
   ))

;; This user store only looks for :email as the only identifier and
;; uniquely differentiating factor of a user.
(defrecord EmailUserStore [storage]

  UserStore
  (check-create-user [component user]
    (let [user (select-keys user [:email])
          existing (find-object storage user)]
      (infof "check-create-user user %s existing %s" user existing)
      (when existing
        {:error :user-exists
         :user user})))

  (create-user! [component user]
    (infof "create user %s %s" (into {} component) user)
    (or
     (check-create-user component user)
     (do
       (store-object! storage user)
       user)))

  (find-user [component id]
    (find-object storage {:email id}))

  (update-user! [component id user]
    (throw (ex-info "TODO" {})))

  (delete-user! [_ id]
    (throw (ex-info "TODO" {})))

  (verify-email! [_ email]
    (throw (ex-info "TODO" {}))))

(defn new-email-user-store [& {:as opts}]
  (->> opts
       map->EmailUserStore
       (<- (using [:storage]))))
