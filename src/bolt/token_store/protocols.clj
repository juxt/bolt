;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns bolt.token-store.protocols)

;; All TokenStore implementations must provide temporary or persistent
;; storage and must expire tokens that are no longer valid. Expiry
;; policies are left to the implementor to decide. Token ids are
;; determined by the client, but are recommended to be resistent to
;; prediction and thus forgery (using HMAC, etc.).

(defprotocol TokenStore
  (create-token! [_ id m]
    "Create a new token identified by id")
  (get-token-by-id [_ id]
    "Return the token identified by id")
  (purge-token! [_ id])
  (renew-token! [_ id]
    "Renew the token so that it has a fresh expiry date. Returns the renewed token.")
  (merge-token! [_ id m]
    "Merge the token identified by id with the given map")
  (dissoc-token! [_ id ks]))
