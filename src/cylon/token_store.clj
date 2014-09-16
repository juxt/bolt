;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.token-store
  (:require
   [cylon.token-store.protocols :as p]
   [schema.core :as s]))

(s/defschema Date "A Java date"
  (s/pred #(instance? java.util.Date %) "date"))

(s/defschema Token "A token"
  {(s/optional-key :cylon/expiry) Date
   s/Keyword s/Any})

(s/defn create-token! :- Token
  [component :- (s/protocol p/TokenStore)
   id :- s/Str
   m :- {s/Keyword s/Any}]
  (p/create-token! component id m))

(s/defn get-token-by-id :- (s/maybe Token)
  [component :- (s/protocol p/TokenStore)
   id :- s/Str]
  (p/get-token-by-id component id))

(s/defn purge-token! :- nil
  [component :- (s/protocol p/TokenStore)
   id :- s/Str]
  (p/purge-token! component id))

(s/defn renew-token! :- (s/maybe Token)
  [component :- (s/protocol p/TokenStore)
   id :- s/Str]
  (p/renew-token! component id))

(s/defn merge-token! :- (s/maybe Token)
  [component :- (s/protocol p/TokenStore)
   id :- s/Str
   m :- {s/Keyword s/Any}]
  (p/merge-token! component id m))

(s/defn dissoc-token! :- (s/maybe Token)
  [component :- (s/protocol p/TokenStore)
   id :- s/Str
   ks :- #{s/Keyword}]
  (p/dissoc-token! component id ks))
