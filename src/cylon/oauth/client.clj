(ns cylon.oauth.client)



;; I don't think this is a wonderful name but until we can think of
;; something better :)
(defprotocol AccessTokenGrantee
  (get-access-token [_ req]
    "Get the access-token held by the client, if one has been granted, ")

  (request-access-token
    [_ req]
    [_ req scope-korks]
    "Initiate a process (typically via a HTTP redirect) that will result
    in a new request being made with an access token, if possible. Don't
    request specific scopes but get the defaults for the client.")

  (refresh-access-token [_ req]
    "Initiate a process (typically via a HTTP redirect) that will result
    in a new request being made with an access token, if possible."
    ))


(defprotocol UserIdentity
  (get-claims [_ req]
    "Get the claims contained in the id-token returned as part of an
    OpenID/Connect exchange."))
