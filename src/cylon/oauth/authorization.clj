(ns cylon.oauth.authorization)

(defprotocol AccessTokenAuthorizer
  ;; Determine if given credentials (found in request) meet a given
  ;; requirement
  (authorized? [_ access-token scope]))
