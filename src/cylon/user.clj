;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.user)

(defprotocol UserAuthenticator
  (authenticate-user [_ user password]))

(extend-protocol UserAuthenticator
  Boolean
  (authenticate-user [this user password] this))
