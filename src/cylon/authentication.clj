;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.authentication
  (:require
   ;;[cylon.user :refer (UserStore lookup-user)]
   [schema.core :as s])
  (:import
   (javax.xml.bind DatatypeConverter)))

;; Define HTTP request authentication

;; TODO
(defprotocol Authenticator
  ;; Return a map, potentially containing entries to be merged with the request.
  (authenticate [_ request]))

;; TODO
(extend-protocol Authenticator
  Boolean
  (authenticate [this request]
    (when this {})))
