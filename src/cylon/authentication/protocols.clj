;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.authentication.protocols)

(defprotocol RequestAuthenticator
  ;; Determine if given credentials (found in request)
  (authenticate [_ req]))

(extend-protocol RequestAuthenticator
  nil
  (authenticate [_ req] nil))

(defprotocol AuthenticationHandshake
  (initiate-authentication-handshake [_ request])
  (get-outcome [_ request]))
