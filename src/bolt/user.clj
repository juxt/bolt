;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns bolt.user
  (:require
   [bolt.user.protocols :as p]
   [bolt.util :refer (Request)]
   [schema.core :as s]
   [modular.email :refer (EmailAddress EmailMessage)]
   ))

;; UserStore API

(s/defschema User "A user"
  {s/Keyword s/Any})

(s/defn check-create-user
  [component :- (s/protocol p/UserStore)
   user :- User]
  (p/check-create-user component user))

(s/defn create-user!
  [component :- (s/protocol p/UserStore)
   user :- User]
  (p/create-user! component user))

(s/defn find-user :- (s/maybe User)
  [component :- (s/protocol p/UserStore)
   id :- s/Str]
  (p/find-user component id))

(s/defn update-user! :- nil
  [component :- (s/protocol p/UserStore)
   id :- s/Str
   user :- User]
  (p/update-user! component id user))

(s/defn delete-user! :- nil
  [component :- (s/protocol p/UserStore)
   id :- s/Str]
  (p/delete-user! component id))

(s/defn verify-email! :- nil
  [component :- (s/protocol p/UserStore)
   email :- s/Str]
  (p/verify-email! component email))

;; UserAuthenticator API

(s/defn authenticate-user :- s/Any
  [component :- (s/protocol p/UserAuthenticator)
   user :- User
   evidence :- {s/Keyword s/Str}]
  (p/authenticate-user component user evidence))

(s/defn hash-password :- s/Str
  [component :- (s/protocol p/UserPasswordHasher)
   password :- s/Str]
  (p/hash-password component password))

;; UserStoreAdmin API

(s/defn list-users :- [s/Any]
  [component :- (s/protocol p/UserStoreAdmin)]
  (p/list-users component))
