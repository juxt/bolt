;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns bolt.authentication
  (:require
   [clojure.string :as str]
   [clojure.tools.logging :refer :all]
   [bolt.authentication.protocols :as p]
   [bolt.util :refer (Request Response)]
   [schema.core :as s]
   [com.stuartsierra.component :refer (using)]
   [plumbing.core :refer (<-)]))

;; RequestAuthenticator

(s/defn authenticate :- (s/maybe {s/Keyword s/Any})
  [component :- (s/protocol p/RequestAuthenticator)
   request :- Request]
  (p/authenticate component request))

;; An authenticator that checks an authorization header. It takes a map,
;; which maps Authorization token types to the local keywords of its
;; dependencies that process them. Using declarations are automatically
;; added.

(defrecord AuthorizationHeaderRequestAuthenticator [mappings]
  p/RequestAuthenticator
  (authenticate [this request]
    (when-let [header (get-in request [:headers "authorization"])]
      (let [token-type (first (str/split (str/trim header) #"\s"))
            dependency (get mappings token-type)]
        (if-let [delegate-authenticator (get this dependency)]
          (authenticate delegate-authenticator request)
          (debugf "Unrecognized token type (%s -> %s) in incoming Authorization header, with mappings as %s" token-type dependency mappings))))))

(def new-authorization-header-request-authenticator-schema
  {:mappings {s/Str s/Keyword}})

(defn new-authorization-header-request-authenticator [& {:as opts}]
  (->> opts
       (merge {})
       (s/validate new-authorization-header-request-authenticator-schema)
       (map->AuthorizationHeaderRequestAuthenticator)
       (<- (using (-> opts :mappings vals vec)))))

;;

;; Either - try multiple authenticators until one returns

(defrecord EitherRequestAuthenticator []
  p/RequestAuthenticator
  (authenticate [this request]
    (debugf "Either: %s" (keys this))
    (some (fn [a]
            (when (satisfies? p/RequestAuthenticator a)
              (let [res (authenticate a request)]
                (when res (assoc res ::authenticator a)))))
          (vals this))))

(defn new-either-request-authenticator [& {:as opts}]
  (->> opts
       (merge {})
       (map->EitherRequestAuthenticator)))

;; Utility functions

;; TODO: It's possible that it would be useful to memoize authentication
;; on each request

(defn get-subject-identifier [authenticator req]
  (:bolt/subject-identifier (authenticate authenticator req)))

(s/defn initiate-authentication-handshake :- Response
  [component :- (s/protocol p/AuthenticationHandshake)
   request :- Request]
  (p/initiate-authentication-handshake component request))
