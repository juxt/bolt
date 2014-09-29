(ns cylon.authentication.protocols)

(defprotocol AuthenticationInteraction
  (initiate-authentication-interaction [_ request])
  (get-outcome [_ request]))
