;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns bolt.oauth.authorization
  (:require
   [bolt.authentication :refer (authenticate)])
  )

(defn scope-authorized? [authenticator req scope]
  (let [creds (authenticate authenticator req)]
    (contains? (:bolt/scopes creds) scope)))
