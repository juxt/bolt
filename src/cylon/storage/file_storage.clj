;; Copyright © 2015, JUXT LTD. All Rights Reserved.

(ns ^{:doc "This implementation is merely for example purposes to help
  with getting started examples and remove the need to set up and
  configure databases. For serious purposes, replace this implementation
  with one using a proper data store."}
  cylon.storage.file-storage
  (:require
   [com.stuartsierra.component :refer (Lifecycle using)]
   [cylon.storage.protocols :refer (Storage)]
   [clojure.java.io :as io]
   [clojure.pprint :refer (pprint)]
   [schema.core :as s]))

(defn- save-file
  "Save the state of the component's ref to a file, via an agent."
  [{:keys [agent ref file]}]
  (send-off
   agent
   (fn [f]
     (spit f (with-out-str (pprint @ref)))
     file)))

(defn selector [qualifier]
  (let [ks (keys qualifier)]
    #(when (= (select-keys % ks) qualifier) %)))

(defn remove-object [ds qualifier seed]
  (into seed (remove (selector qualifier) ds)))

(defrecord FileStorage [file seed ref]
  Storage
  (find-object [component qualifier]
    (let [ks (keys qualifier)]
      (some (selector qualifier) @ref)))

  (store-object! [component object]
    (dosync
     (alter ref conj object)
     (save-file component)))

  (delete-object! [component qualifier]
    (let [ks (keys qualifier)]
      (dosync
       (alter ref remove-object qualifier seed)
       (save-file component)))))

(defn- check-file-parent [{f :file :as opts}]
  (assert
   (.exists (.getParentFile (.getCanonicalFile f)))
   (format "Please create the directory structure which should contain the file: %s" f))
  opts)

(defn add-ref-agent [{f :file seed :seed :as m}]
  (assoc m
         :seed seed
         :ref (ref
               (if (.exists f)
                 (read-string (slurp f))
                 seed))
         :agent (agent f)))

(defn new-file-storage [& {:as opts}]
  (->> opts
       (merge {:seed #{}})
       (s/validate {:file (s/either s/Str (s/pred (partial instance? java.io.File)))
                    :seed (s/either (s/eq #{}) (s/eq []))})
       (#(update-in % [:file] io/file))
       check-file-parent
       add-ref-agent
       map->FileStorage))
