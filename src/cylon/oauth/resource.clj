;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.oauth.resource
  (:require
   [clojure.string :as str]
   [com.stuartsierra.component :refer (Lifecycle using)]
   [cylon.token-store :refer (get-token-by-id)]
   [cylon.token-store.protocols :refer (TokenStore)]
   [cylon.authentication.protocols :refer (RequestAuthenticator)]
   [cylon.authentication :refer (authenticate)]
   [schema.core :as s]
   [plumbing.core :refer (<-)]))

;; Having established an access token store, we can now use it to verify
;; incoming requests bearing access tokens.

(defrecord AccessTokenRequestAuthenticator [access-token-store]
  Lifecycle
  (start [component]
    (s/validate
     {:access-token-store (s/protocol TokenStore)}
     component))
  (stop [component] component)

  RequestAuthenticator
  (authenticate [component request]
    (when-let [auth-header (get (:headers request) "authorization")]
      ;; Only match 'Bearer' tokens for now
      (when-let [access-token (second (re-matches #"\QBearer\E\s+(.*)" auth-header))]
        (get-token-by-id access-token-store access-token)))))

(defn new-access-token-request-authenticator [& {:as opts}]
  (->> opts
       (merge {})
       map->AccessTokenRequestAuthenticator
       (<- (using [:access-token-store]))))

;; Personal access tokens can be created. Same as GitHub's 'personal
;; access tokens'.

(def new-personal-access-token-request-authenticator-schema
  {:header-token s/Str})

(defrecord PersonalAccessTokenRequestAuthenticator [header-token token-store]
  Lifecycle
  (start [component]
    (s/validate
     (merge new-personal-access-token-request-authenticator-schema
            {:token-store (s/protocol TokenStore)})
     component)
    (assoc component
      :pattern (re-pattern (format "\\Q%s\\E\\s+(.*)" header-token))))
  (stop [component] component)

  RequestAuthenticator
  (authenticate [component request]
    (when-let [auth-header (get (:headers request) "authorization")]
      (when-let [token-id (second (re-matches (:pattern component) (str/trim auth-header)))]
        (get-token-by-id token-store token-id)))))

(defn new-personal-access-token-request-authenticator [& {:as opts}]
  (->> opts
       (merge {})
       (s/validate new-personal-access-token-request-authenticator-schema)
       map->PersonalAccessTokenRequestAuthenticator
       (<- (using [:token-store]))))
