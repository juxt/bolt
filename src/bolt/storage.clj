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
