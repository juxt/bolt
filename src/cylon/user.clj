;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.user
  (:require
   [cylon.user.protocols :as p]
   [cylon.util :refer (Request)]
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

(s/defn get-user :- (s/maybe User)
  [component :- (s/protocol p/UserStore)
   uid :- s/Str]
  (p/get-user component uid))

(s/defn get-user-password-hash :- (s/maybe PasswordHashWithSalt)
  [component :- (s/protocol p/UserStore)
   uid :- s/Str]
  (p/get-user-password-hash component uid))

(s/defn set-user-password-hash! :- nil
  [component :- (s/protocol p/UserStore)
   uid :- s/Str
   pw-hash :- PasswordHashWithSalt]
  (p/set-user-password-hash! component uid pw-hash))

(s/defn get-user-by-email :- (s/maybe User)
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

;; Emailer API

(s/defschema EmailAddress "An email address (relaxed version)"
  (s/pred (fn [s] (re-matches #"\S+@\S+" s))))

(s/defn send-email! :- nil
  [component :- (s/protocol p/Emailer)
   data :- {:to EmailAddress
            :subject s/Str
            :body s/Str
            (s/optional-key :content-type) s/Str}]
  (p/send-email! component data))

(s/defschema EmailMessage
  {:subject s/Str
   :body s/Str
   (s/optional-key :content-type) s/Str})

;; Login form renderer API

(s/defschema FormField
  {:name s/Str
   (s/optional-key :label) s/Str
   (s/optional-key :placeholder) s/Str
   (s/optional-key :type) s/Str
   (s/optional-key :value) s/Str})

(s/defschema Form
  {:method s/Keyword
   :action s/Str
   :fields [FormField]})

(s/defn render-login-form :- s/Str
  [component :- (s/protocol p/LoginFormRenderer)
   req :- Request
   model :- {:form Form
             (s/optional-key :login-failed?) s/Bool
             s/Keyword s/Any}]
  (p/render-login-form component req model))

;; User form renderer API

(s/defn render-signup-form :- s/Str
  [component :- (s/protocol p/UserFormRenderer)
   req :- Request
   model :- {:form Form}]
  (p/render-signup-form component req model))

(s/defn render-welcome :- s/Str
  [component :- (s/protocol p/UserFormRenderer)
   req :- Request
   model :- {}]
  (p/render-welcome component req model))

(s/defn render-welcome-email-message :- EmailMessage
  [component :- (s/protocol p/UserFormRenderer)
   model :- {:email-verification-link s/Str}]
  (p/render-welcome-email-message component model))

(s/defn render-email-verified :- s/Str
  [component :- (s/protocol p/UserFormRenderer)
   req :- Request
   model :- {:email EmailAddress
             s/Keyword s/Any}]
  (p/render-email-verified component req model))

(s/defn render-reset-password-request-form :- s/Str
  [component :- (s/protocol p/UserFormRenderer)
   req :- Request
   model :- {:form Form
             (s/optional-key :email-failed?) s/Bool}]
  (p/render-reset-password-request-form component req model))

(s/defn render-reset-password-email-message :- EmailMessage
  [component :- (s/protocol p/UserFormRenderer)
   model :- {:link s/Str}]
  (p/render-reset-password-email-message component model))

(s/defn render-reset-password-link-sent-response :- s/Str
  [component :- (s/protocol p/UserFormRenderer)
   req :- Request
   model :- {:email EmailAddress}]
  (p/render-reset-password-link-sent-response component req model))

(s/defn render-password-reset-form :- s/Str
  [component :- (s/protocol p/UserFormRenderer)
   req :- Request
   model :- {:form Form
             s/Keyword s/Any}]
  (p/render-password-reset-form component req model))

(s/defn render-password-changed-response :- s/Str
  [component :- (s/protocol p/UserFormRenderer)
   req :- Request
   model :- {}]
  (p/render-password-changed-response component req model))

;; Error form renderer API

(s/defn render-error :- s/Str
  [component :- (s/protocol p/ErrorRenderer)
   req :- Request
   model :- {:error-type (s/enum :user-already-exists)
             s/Keyword s/Any}]
  (p/render-error-response component req model))
