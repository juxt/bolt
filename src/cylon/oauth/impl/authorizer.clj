(ns cylon.oauth.impl.authorizer
  (require [com.stuartsierra.component :as component]
           [clojure.tools.logging :refer :all]
           [cylon.authorization :refer (Authorizer)]
           [cylon.session :refer (get-session)]
           [cylon.oauth.scopes :refer (valid-scope?)]))

;; renamed from OAuth2AccessTokenAuthorizer to OAuth2Authorizer
;; because I still don't know/find another way to authorize in oauth2 spec

(defrecord OAuth2Authorizer []
  Authorizer
  (authorized? [this request scope]
    (if (valid-scope? (:auth-server this) scope)
      (when-let [auth-header (get (:headers request) "authorization")]

        (let [access-token (second (re-matches #"\Qtoken\E\s+(.*)" auth-header))
              session (get-session (:access-token-store this) access-token)
              scopes (:scopes session)]
          (infof "session is %s, scopes is %s" session scopes)
          (when session
            (when scopes (scopes scope)))))

      ;; Not a valid scope - (internal error)
      (throw (ex-info "Not a valid scope!" {:scope scope})))))

(defn new-oauth2-authorizer [& {:as opts}]
  (component/using (->OAuth2Authorizer) [:access-token-store :auth-server]))
