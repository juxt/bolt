;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.authentication)

(defprotocol Authenticator
  ;; If the request is authentic, return a map containing additional
  ;; facts about the request.
  (authenticate [_ request]))

(extend-protocol Authenticator
  Boolean
  (authenticate [this request]
    (when this {})))
