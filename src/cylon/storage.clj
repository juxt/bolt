;; Copyright © 2015, JUXT LTD. All Rights Reserved.

(ns cylon.storage
  (:require
   [schema.core :as s]
   [cylon.storage.protocols :as p]))

;; Storage API

(s/defschema Obj {s/Keyword s/Str})

(s/defn find-object :- Obj
  [component :- (s/protocol p/Storage)
   qualifier :- s/Any]
  (p/find-object component qualifier))

(s/defn store-object! :- nil
  [component :- (s/protocol p/Storage)
   obj :- Obj]
  (p/store-object! component obj))

(s/defn delete-object! :- Obj
  [component :- (s/protocol p/Storage)
   qualifier :- s/Any]
  (p/delete-object! component qualifier))
