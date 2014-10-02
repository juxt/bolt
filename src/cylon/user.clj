;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.user
  (:require
   [cylon.user.protocols :as p]
   [schema.core :as s]))

;; UserStore API

(s/defschema User "A user"
  {:uid s/Str
   :email s/Str
   s/Keyword s/Any})

(s/defschema PasswordHashWithSalt
  {:hash s/Str
   :salt s/Str})

(s/defn create-user! :- nil
  [component :- (s/protocol p/UserStore)
   uid :- s/Str
   pw-hash :- PasswordHashWithSalt
   email :- s/Str
   user-details :- {s/Keyword s/Any}]
  (p/create-user! component uid pw-hash email user-details))

(s/defn get-user :- User
  [component :- (s/protocol p/UserStore)
   uid :- s/Str]
  (p/get-user component uid))

(s/defn get-user-password-hash :- PasswordHashWithSalt
  [component :- (s/protocol p/UserStore)
   uid :- s/Str]
  (p/get-user-password-hash component uid))

(s/defn set-user-password-hash! :- nil
  [component :- (s/protocol p/UserStore)
   uid :- s/Str
   pw-hash :- PasswordHashWithSalt]
  (p/set-user-password-hash! component uid pw-hash))

(s/defn get-user-by-email :- User
  [component :- (s/protocol p/UserStore)
   email :- s/Str]
  (p/get-user-by-email component email))

(s/defn delete-user! :- nil
  [component :- (s/protocol p/UserStore)
   uid :- s/Str]
  (p/delete-user! component uid))

(s/defn verify-email! :- nil
  [component :- (s/protocol p/UserStore)
   uid :- s/Str]
  (p/verify-email! component uid))
