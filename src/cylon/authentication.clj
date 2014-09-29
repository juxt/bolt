;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.authentication
  (:require
   [cylon.authentication.protocols :as p]
   [cylon.util :refer (Request Response)]
   [schema.core :as s]))

(s/defn initiate-authentication-interaction :- Response
  [component :- (s/protocol p/AuthenticationInteraction)
   request :- Request]
  (p/initiate-authentication-interaction component request))

(s/defn get-outcome :- {s/Keyword s/Any}
  [component :- (s/protocol p/AuthenticationInteraction)
   request :- Request]
  (p/get-outcome component request))
