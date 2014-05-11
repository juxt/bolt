;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.user)

(defprotocol UserStore
  (lookup-user [_ user password]))

(extend-protocol UserStore
  Boolean
  (lookup-user [this user password] this))
