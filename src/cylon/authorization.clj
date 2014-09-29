;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.authorization
  (:require
   [schema.core :as s]
   [cylon.authorization.protocols :as p]
   [cylon.util :refer (Request)]
   [clojure.tools.logging :refer :all]))

(s/defn authorized-request? :- s/Bool
  [component :- (s/protocol p/RequestAuthorizer)
   request :- Request
   requirement :- s/Any]
  (p/authorized-request? component request requirement))

(defrecord MultiRequestAuthorizer [mappings]
  RequestAuthorizer
  (request-authorized? [this request role]
    (when-let [header (get-in request [:headers "authorization"])]
      (let [token-type (first (str/split (str/trim header) #"\s"))
            dependency (get mappings token-type)]
        (if-let [authorizer (get this dependency)]
          (request-authorized? authorizer request role)
          (debugf "Unrecognized token type (%s -> %s) in incoming Authorization header, with mappings as %s" token-type dependency mappings))))))

(def new-multi-request-authorizer-schema
  {:mappings {s/Str s/Keyword}})

(defn new-multi-request-authorizer [& {:as opts}]
  (->> opts
       (merge {})
       (s/validate new-multi-request-authorizer-schema)
       (map->MultiRequestAuthorizer)))
