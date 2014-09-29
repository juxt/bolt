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
