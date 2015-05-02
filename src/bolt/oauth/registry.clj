;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns bolt.oauth.registry
  (:require
   [bolt.oauth.registry.protocols :as p]
   [schema.core :as s]))

(s/defn register-client :- {:client-id s/Str
                            :client-secret s/Str}
  [p :- (s/protocol p/ClientRegistry)
   ;; If client-id and/or client-secret are not specified, they will be
   ;; generated.
   properties :- {(s/optional-key :client-id) s/Str
                  (s/optional-key :client-secret) s/Str
                  :application-name s/Str
                  :homepage-uri s/Str
                  (s/optional-key :description) s/Str
                  :redirection-uri s/Str
                  :required-scopes (s/either #{s/Keyword} #{s/Str})
                  :requires-user-acceptance? s/Bool}]
  (p/register-client p properties))

(s/defn lookup-client :- {:application-name s/Str
                          :homepage-uri s/Str
                          (s/optional-key :description) s/Str
                          :redirection-uri s/Str
                          :client-id s/Str
                          :client-secret s/Str
                          :required-scopes (s/either #{s/Keyword} #{s/Str})
                          :requires-user-acceptance? s/Bool}
  [p :- (s/protocol p/ClientRegistry)
   client-id :- s/Str]
  (p/lookup-client p client-id))
