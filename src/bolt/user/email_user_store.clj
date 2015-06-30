;; Copyright © 2015, JUXT LTD. All Rights Reserved.

(ns bolt.user.email-user-store
  (:require
   [clojure.tools.logging :refer :all]
   [bolt.user :refer (check-create-user)]
   [bolt.user.protocols :refer (UserStore UserStoreAdmin)]
   [bolt.storage.protocols :refer (Storage find-objects store-object!)]
   [com.stuartsierra.component :refer (Lifecycle using)]
   [clojure.pprint :refer (pprint)]
   [clojure.java.io :as io]
   [clojure.tools.logging :refer :all]
   [schema.core :as s]
   [plumbing.core :refer (<-)]
   ))

;; This user store only looks for :email as the only identifier and
;; uniquely differentiating factor of a user.
(s/defrecord EmailUserStore [storage :- (s/protocol Storage)]

  UserStore
  (check-create-user [component user]
    (let [user (select-keys user [:email])
          existing (first (find-objects storage user))]
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
             (first (find-objects storage {:email id})))

  (update-user! [component id user]
    (throw (ex-info "TODO" {})))

  (delete-user! [_ id]
    (throw (ex-info "TODO" {})))

  (verify-email! [_ email]
    (throw (ex-info "TODO" {})))

  UserStoreAdmin
  (list-users [component]
    (find-objects storage {}))

  )

(defn new-email-user-store [& {:as opts}]
  (->> opts
       map->EmailUserStore
       (<- (using [:storage]))))
