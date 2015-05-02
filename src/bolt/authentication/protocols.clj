;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.authentication.protocols)

(defprotocol RequestAuthenticator
  (authenticate [_ request]
    "Return (as a map) any credentials that can be determined from the
    given Ring request"))

(extend-protocol RequestAuthenticator
  nil
  (authenticate [_ request] nil))

(defprotocol AuthenticationHandshake
  (initiate-authentication-handshake [_ request]
    "Return a Ring response that redirects the user-agent into an
    interaction to establish its authenticity"))
