;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.user)

(defprotocol UserStore
  (get-user [_ uid])
  (store-user! [_ uid user]))

(defprotocol UserDomain
  (verify-user [_ uid password])
  (add-user! [_ uid user password]))
