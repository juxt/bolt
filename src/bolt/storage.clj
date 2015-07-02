;; Copyright © 2015, JUXT LTD. All Rights Reserved.

(ns bolt.storage
  (:refer-clojure :exclude [get-in assoc-in update-in])
  (:require
   [schema.core :as s]
   [bolt.storage.protocols :as p]))

(s/defn get-in [component :- (s/protocol p/TreeStore)
                ks :- [(s/either s/Keyword s/Str)]]
  (p/get-in component ks))

(s/defn assoc-in [component :- (s/protocol p/TreeStore)
                  ks :- [(s/either s/Keyword s/Str)]
                  v]
  (p/assoc-in component ks v))

(s/defn update-in [component :- (s/protocol p/TreeStore)
                  ks :- [(s/either s/Keyword s/Str)]
                  f & args]
  (p/update-in component ks f args))

;; Storage API - deprecated

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
