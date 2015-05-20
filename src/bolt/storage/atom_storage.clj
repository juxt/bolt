;; Copyright © 2015, JUXT LTD. All Rights Reserved.

(ns bolt.storage.atom-storage
  (:require
   [com.stuartsierra.component :refer (Lifecycle using)]
   [bolt.storage.protocols :refer (Storage)]
   [clojure.java.io :as io]
   [clojure.pprint :refer (pprint)]
   [schema.core :as s]
   [schema.utils :refer [class-schema]]))

(defn selector [qualifier]
  (let [ks (keys qualifier)]
    #(when (= (select-keys % ks) qualifier) %)))

(defn remove-object [ds qualifier seed]
  (into seed (remove (selector qualifier) ds)))

(s/defschema Seed
  (s/either (s/eq #{}) (s/eq [])))

(s/defrecord AtomStorage
    [ref :- (s/pred (partial instance? clojure.lang.Ref))
     seed :- Seed]

  Lifecycle
  (start [component] (s/validate (class-schema (type component)) component))
  (stop [component] component)

  Storage
  (find-object [component qualifier]
               (let [ks (keys qualifier)]
                 (some (selector qualifier) @ref)))

  (store-object! [component object]
                 (dosync
                  (alter ref conj object)))

  (delete-object! [component qualifier]
                  (dosync
                   (alter ref remove-object qualifier seed))))

(defn new-atom-storage [& {:as opts}]
  (let [seed #{}]
    (->> opts
         (merge {:seed seed :ref (ref seed)})
         map->AtomStorage)))
