;; Copyright © 2015, JUXT LTD. All Rights Reserved.

(ns cylon.user.email-user-store
  (:require
   [clojure.tools.logging :refer :all]
   [cylon.user :refer (check-create-user)]
   [cylon.user.protocols :refer (UserStore)]
   [cylon.storage.protocols :refer (find-object store-object!)]
   [com.stuartsierra.component :refer (Lifecycle using)]
   [clojure.pprint :refer (pprint)]
   [clojure.java.io :as io]
   [schema.core :as s]
   [plumbing.core :refer (<-)]
   ))

;; This user store only looks for :email as the only identifier and
;; uniquely differentiating factor of a user.
(defrecord EmailUserStore [storage]

  UserStore
  (check-create-user [component user]
    (let [user (select-keys user [:user])
          existing (find-object storage user)]
      (when existing
        {:error :user-exists
         :user user})))

  (create-user! [component user]
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
