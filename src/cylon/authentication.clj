;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.authentication
  (:require
   [clojure.string :as str]
   [clojure.tools.logging :refer :all]
   [cylon.authentication.protocols :as p]
   [cylon.util :refer (Request Response)]
   [schema.core :as s]
   [com.stuartsierra.component :refer (using)]
   [plumbing.core :refer (<-)]))

;; RequestAuthenticator

(s/defn authenticate :- {s/Keyword s/Any}
  [component :- (s/protocol p/RequestAuthenticator)
   request :- Request]
  (p/authenticate component request))

(defrecord DispatchingRequestAuthenticator [mappings]
  p/RequestAuthenticator
  (authenticate [this request]
    (when-let [header (get-in request [:headers "authorization"])]
      (let [token-type (first (str/split (str/trim header) #"\s"))
            dependency (get mappings token-type)]
        (if-let [delegate-authenticator (get this dependency)]
          (authenticate delegate-authenticator request)
          (debugf "Unrecognized token type (%s -> %s) in incoming Authorization header, with mappings as %s" token-type dependency mappings))))))

(def new-dispatching-request-authenticator-schema
  {:mappings {s/Str s/Keyword}})

(defn new-dispatching-request-authenticator [& {:as opts}]
  (->> opts
       (merge {})
       (s/validate new-dispatching-request-authenticator-schema)
       (map->DispatchingRequestAuthenticator)
       (<- (using (-> opts :mappings vals vec)))))

;; Utility

;; TODO: It's possible that it would be useful to memoize authentication on each request

(defn get-subject-identifier [authenticator req]
  (:cylon/subject-identifier (authenticate authenticator req)))

;; AuthenticationInteraction

(s/defn initiate-authentication-interaction :- Response
  [component :- (s/protocol p/AuthenticationInteraction)
   request :- Request]
  (p/initiate-authentication-interaction component request))

(s/defn get-outcome :- (s/maybe {s/Keyword s/Any})
  [component :- (s/protocol p/AuthenticationInteraction)
   request :- Request]
  (p/get-outcome component request))
