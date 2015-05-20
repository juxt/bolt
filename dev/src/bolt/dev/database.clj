;; Copyright © 2015, JUXT LTD.

(ns bolt.dev.database
  (:require
   [com.stuartsierra.component :refer (Lifecycle)]
   [buddy.hashers :as hs]
   [schema.core :as s]))

;; A user database

(defn seed-database [db]
  (reset! (:atom db)
          {:user "alice@example.org" :password (hs/encrypt "wonderland")})
  db)

(defrecord Database []
  Lifecycle
  (start [component]
    (seed-database (assoc component :atom (atom {}))))
  (stop [component] component))

(def new-database-schema {})

(defn new-database [& {:as opts}]
  (->> opts
    (merge {})
    (s/validate new-database-schema)
    map->Database))
