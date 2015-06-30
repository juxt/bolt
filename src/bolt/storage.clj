;; Copyright © 2015, JUXT LTD. All Rights Reserved.

(ns bolt.storage
  (:require
   [schema.core :as s]
   [bolt.storage.protocols :as p]))

;; Storage API

;; The storage API is a temporary abstraction over a k/v database
;; awaiting a graph-based abstraction that can be used with a graphQL
;; query. The fact is that a number of bolt features (users, passwords,
;; tokens, codes, etc.) need durable storage. The graph abstraction will
;; probably be datomic or datascript backed, but perhaps with a tree/edn
;; alternative.

(s/defschema Obj {s/Keyword s/Str})

(s/defn find-objects :- [Obj]
  [component :- (s/protocol p/Storage)
   qualifier :- s/Any]
  (p/find-objects component qualifier))

(s/defn store-object! :- nil
  [component :- (s/protocol p/Storage)
   obj :- Obj]
  (p/store-object! component obj))

(s/defn delete-object! :- Obj
  [component :- (s/protocol p/Storage)
   qualifier :- s/Any]
  (p/delete-object! component qualifier))
