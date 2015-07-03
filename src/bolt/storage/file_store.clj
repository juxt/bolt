;; Copyright © 2015, JUXT LTD. All Rights Reserved.

(ns ^{:doc "This implementation is merely for example purposes to help
  with getting started examples and remove the need to set up and
  configure databases. For serious purposes, replace this implementation
  with one using a proper data store."}
  bolt.storage.file-store
  (:refer-clojure :exclude [get-in assoc-in update-in])
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :refer (Lifecycle using)]
   [bolt.storage.protocols :refer (TreeStore)]
   [bolt.storage :as st]
   [clojure.java.io :as io]
   [clojure.pprint :refer (pprint)]
   [schema.core :as s]))

(defn- save-file
  "Save the state of the component's ref to a file, via an agent."
  [{:keys [file _ref _agent]}]
  (send-off
   _agent
   (fn [f]
     (spit f (with-out-str (pprint @_ref)))
     f)))

(s/defrecord FileStore [file _ref _agent]
  TreeStore
  (get-in [_ ks] (st/get-in _ref ks))
  (assoc-in [component ks v]
            (dosync
             (st/assoc-in _ref ks v)
             (save-file component)))
  (update-in [component ks f args]
             (dosync
              (apply st/update-in _ref ks f args)
              (save-file component))))

(defn- check-file-parent [{f :file :as opts}]
  (assert
   (.exists (.getParentFile (.getCanonicalFile f)))
   (format "Please create the directory structure which should contain the file: %s" f))
  opts)

(defn add-ref-agent [{f :file :as m}]
  (assoc m
         :_ref (ref
               (if (.exists f)
                 (read-string (slurp f))
                 {}))
         :_agent (agent f)))

(defn new-file-store [& {:as opts}]
  (infof "new-file-store: %s" opts)
  (->> opts
       (#(clojure.core/update-in % [:file] io/file))
       check-file-parent
       add-ref-agent
       map->FileStore))
