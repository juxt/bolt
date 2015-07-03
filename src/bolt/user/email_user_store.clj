;; Copyright © 2015, JUXT LTD. All Rights Reserved.

(ns bolt.user.email-user-store
  (:require
   [clojure.tools.logging :refer :all]
   [bolt.user.protocols :refer (UserStore UserStoreAdmin)]
   [bolt.storage.protocols :refer (TreeStore)]
   [bolt.storage :as st]
   [com.stuartsierra.component :refer (Lifecycle using)]
   [clojure.pprint :refer (pprint)]
   [clojure.java.io :as io]
   [clojure.tools.logging :refer :all]
   [schema.core :as s]
   ))

;; This user store only looks for :email as the only identifier and
;; uniquely differentiating factor of a user.
(s/defrecord EmailUserStore [storage :- (s/protocol TreeStore)]

  UserStore
  (create-user!
   [component email user]
   (st/update-in storage [:users email]
                 (fn [olduser]
                   (if olduser
                     (throw (ex-info "User already exists with given email" {:email email}))
                     user))))

  (find-user
   [component email]
   (st/get-in storage [:users email]))

  (update-user!
   [component email user]
   (st/update-in storage [:users email] (fn [u] (if u user (throw (ex-info "No user found" {:email email}))))))

  (delete-user!
   [_ email]
   (st/update-in storage [:users] (fn [u] (dissoc u email))))

  (verify-email!
   [component email]
   (st/update-in storage [:users email] (fn [u] (if u (assoc u :email-verified (java.util.Date.)) (throw (ex-info "No user found" {:email email}))))))

  UserStoreAdmin
  (list-users [component] (st/get-in storage [:users])))

(defn new-email-user-store [& {:as opts}]
  (->
   (map->EmailUserStore opts)
   (using [:storage])))
