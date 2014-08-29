(ns cylon.oauth.client
  (:require [clojure.tools.logging :refer :all])
)

;; I don't think this is a wonderful name but until we can think of
;; something better :)
(defprotocol AccessTokenGrantee
  (get-access-token [_ req]
    "Get the access-token held by the client, if one has been granted, ")

  (solicit-access-token
    [_ req]
    [_ req scope-korks]
    "Initiate a process (typically via a HTTP redirect) that will result
    in a new request being made with an access token, if possible. Don't
    request specific scopes but get the defaults for the client.")

  (expired? [_ req access-token])

  (refresh-access-token [_ req]
    "Initiate a process (typically via a HTTP redirect) that will result
    in a new request being made with an access token, if possible."
    ))

(defprotocol UserIdentity
  (get-claims [_ req]
    "Get the claims contained in the id-token returned as part of an
    OpenID/Connect exchange."))


;; Ring middleware to restrict a handler to a given role.
;; The algo in here should fit many usages. However, other functions
;; could be provided to implement different policies.
(defn wrap-restricted
  "Restrict a handler to a role. :identity and :access-token are added
  to the request. If a role is specified, also check that the role
  exists in the scope of the client. If role isn't specified, the
  identity and access-token are still retrieved."
  [h client & [role]]
  (fn [req]
    (let [{:keys [access-token scope]} (get-access-token client req)
          identity (-> (get-claims client req) :sub)]
      (cond
       (nil? access-token)
       (do
         (debugf "No access token, so soliciting one from client %s" client)
         (solicit-access-token client req))
       ;; The thinking here is that any refresh token that was returned
       ;; to the client will still be held by the client and can be
       ;; used to refresh the access-token
       (expired? client req access-token)
       (do
         (debugf "access token has expired, seeking to refresh it")
         (refresh-access-token client req))

       (and role (not (contains? scope role)))
       ;; TODO Must do something better than this
       {:status 401 :body "Sorry, you just don't have enough privileges to access this page"}

       :otherwise
       (h (assoc req :identity identity :access-token access-token))))))
