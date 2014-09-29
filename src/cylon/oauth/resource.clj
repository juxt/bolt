;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.oauth.resource
  (:require
   [clojure.string :as str]
   [com.stuartsierra.component :refer (Lifecycle using)]
   [cylon.token-store :refer (get-token-by-id)]
   [cylon.authentication.protocols :refer (RequestAuthenticator)]
   [cylon.authentication :refer (authenticate)]
   [schema.core :as s]
   [plumbing.core :refer (<-)]))

(def new-personal-access-token-request-authenticator-schema
  {:header-token s/Str})

;; This is almost identical to the GitHub 'personal access token'

(defrecord PersonalAccessTokenRequestAuthenticator [header-token token-store]
  Lifecycle
  (start [component]
    (assoc component
      :pattern (re-pattern (format "\\Q%s\\E\\s+(.*)" header-token))))
  (stop [component] component)

  RequestAuthenticator
  (authenticate [component request]
    ;; TODO: We should possibly only return the access-token content
    ;; here, and separate the concern of determining whether the
    ;; access token content satisfies a given requirement (scope,
    ;; user, etc.)
    (when-let [auth-header (get (:headers request) "authorization")]
      (when-let [token-id (second (re-matches (:pattern component) (str/trim auth-header)))]
        (get-token-by-id token-store token-id)))))

(defn new-personal-access-token-request-authenticator [& {:as opts}]
  (->> opts
       (merge {})
       (s/validate new-personal-access-token-request-authenticator-schema)
       map->PersonalAccessTokenRequestAuthenticator
       (<- (using [:token-store]))))
