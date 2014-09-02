(ns cylon.oauth.client
  (:require
   [clojure.tools.logging :refer :all]
   [schema.core :as s]))

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

(s/defn ^{:doc "May returns nil if no access token"}
  get-access-token+ :- {(s/optional-key :access-token) s/Str
                        (s/optional-key :scope) #{s/Keyword}
                        (s/optional-key :original-uri) s/Str
                        s/Keyword s/Any}
  [p :- (s/protocol AccessTokenGrantee)
   req :- s/Any]
  (or (get-access-token p req) {}))

(defprotocol UserIdentity
  (get-claims [_ req]
    "Get the claims contained in the id-token returned as part of an
    OpenID/Connect exchange."))

(defn get-identity [client req]
  (-> (get-claims client req) :sub))

;; Ring middleware to restrict a handler to a given role.
;; The algo in here should fit many usages. However, other functions
;; could be provided to implement different policies.
(defn wrap-require-authorization
  "Restrict a handler to a role. :identity and :access-token are added
  to the request. If a role is specified, also check that the role
  exists in the scope of the client. If role isn't specified, the
  identity and access-token are still retrieved."
  [h client & [role]]
  (fn [req]
    (let [{:keys [access-token scope]}
          (s/with-fn-validation (get-access-token+ client req))]
      (cond
       (nil? access-token)
       (do
         (debugf "No access token, so soliciting one from client %s" client)
         (solicit-access-token client req))
       (expired? client req access-token)
       (do
         (debugf "access token has expired, seeking to refresh it")
         ;; The thinking here is that any refresh token that was returned
         ;; to the client will still be held by the client and can be
         ;; used to refresh the access-token
         (refresh-access-token client req))

       (and role (not (contains? scope role)))
       ;; TODO Must do something better than this
       {:status 401 :body "Sorry, you just don't have enough privileges to access this page"}

       :otherwise
       (h (assoc req
            :identity (get-identity client req)
            :access-token access-token))))))
