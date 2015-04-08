(ns cylon.oauth.client
  (:require
   [clojure.tools.logging :refer :all]
   [cylon.authentication :refer (authenticate)]
   [cylon.util :refer (absolute-uri)]
   [schema.core :as s]))

;; I don't think this is a wonderful name but until we can think of
;; something better :)
(defprotocol AccessTokenGrantee
  (solicit-access-token
    [_ req uri]
    [_ req uri scope-korks]
    "Initiate a process (typically via a HTTP redirect) that will result
    in a new request being made with an access token, if possible. Don't
    request specific scopes but get the defaults for the client.")

  (expired? [_ req access-token])

  (refresh-access-token [_ req]
    "Initiate a process (typically via a HTTP redirect) that will result
    in a new request being made with an access token, if possible."
    ))

;; Ring middleware to restrict a handler to a given role.
;; The algo in here should fit many usages. However, other functions
;; could be provided to implement different policies.

(defn wrap-require-authorization
  "Restrict a handler to a role. :identity and :access-token are added
  to the request. If a role is specified, also check that the role
  exists in the scope of the client. If role isn't specified, the
  identity and access-token are still retrieved."
  [h client & [scope]]
  (fn [req]
    (let [{access-token :cylon/access-token
           scopes :cylon/scopes
           sub :cylon/subject-identifier
           :as user}
          (authenticate client req)]

      (cond
       (nil? access-token)
       (do
         (debugf "No access token, so soliciting one from client %s" client)
         (solicit-access-token client req (absolute-uri req)))
       (expired? client req access-token)
       (do
         (debugf "access token has expired, seeking to refresh it")
         ;; The thinking here is that any refresh token that was returned
         ;; to the client will still be held by the client and can be
         ;; used to refresh the access-token
         (refresh-access-token client req))

       (and scope (not (contains? scopes scope)))
       ;; TODO Must do something better than this
       {:status 401 :body "Sorry, you just don't have enough privileges to access this page"}

       :otherwise
       (h (assoc req
                 :cylon/user user
                 ;; Deprecated
                 :cylon/subject-identifier sub
                 :cylon/access-token access-token))))))
