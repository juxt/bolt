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

(s/defn create-user!
  [component :- (s/protocol p/UserStore)
   id :- s/Str
   user :- User]
  (p/create-user! component id user))

(s/defn find-user
  [component :- (s/protocol p/UserStore)
   id :- s/Str]
  :- (s/maybe User)
  (p/find-user component id))

(s/defn update-user!
  [component :- (s/protocol p/UserStore)
   id :- s/Str
   user :- User]
  :- nil
  (p/update-user! component id user))

(s/defn delete-user!
  [component :- (s/protocol p/UserStore)
   id :- s/Str]
  :- nil
  (p/delete-user! component id))

(s/defn verify-email!
  [component :- (s/protocol p/UserStore)
   email :- s/Str]
  :- nil
  (p/verify-email! component email))

;; UserAuthenticator API

(s/defn authenticate-user
  [component :- (s/protocol p/UserAuthenticator)
   user :- User
   evidence :- {s/Keyword s/Str}]
  :- s/Any
  (p/authenticate-user component user evidence))

;; UserPasswordHasher API

(s/defn hash-password
  [component :- (s/protocol p/UserPasswordHasher)
   password :- s/Str]
  :- s/Str
  (p/hash-password component password))

;; UserStoreAdmin API

(s/defn list-users
  [component :- (s/protocol p/UserStoreAdmin)]
  :- [s/Any]
  (p/list-users component))
