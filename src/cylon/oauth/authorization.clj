;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.oauth.authorization
  (:require
   [cylon.authentication :refer (authenticate)])
  )

(defn scope-authorized? [authenticator req scope]
  (let [creds (authenticate authenticator req)]
    (contains? (:cylon/scopes creds) scope)))

#_AccessTokenAuthorizer
  #_(authorized? [component access-token scope]
    (if-not (contains? (set (keys scopes)) scope)
      (throw (ex-info "Scope is not a known scope to this authorization server"
                      {:component component
                       :scope scope
                       :scopes scopes}))
      (when-let [{scopes :cylon/scopes :as token} (get-token-by-id access-token-store access-token)]
        (when (contains? scopes scope) token))))
