;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.oauth.authorization
  (:require
   [cylon.authentication :refer (authenticate)])
  )

(defn scope-authorized? [authenticator req scope]
  (let [creds (authenticate authenticator req)]
    (contains? (:cylon/scopes creds) scope)))
