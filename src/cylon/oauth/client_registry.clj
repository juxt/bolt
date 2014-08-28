(ns cylon.oauth.client-registry
  (:require
   [schema.core :as s]))

(defprotocol ClientRegistry
  (register-client [_ properties])
  (lookup-client [_ client-id]))

(s/defn register-client+ :- {:client-id s/Str
                             :client-secret s/Str}
  [p :- (s/protocol ClientRegistry)
   ;; If client-id and/or client-secret are not specified, they will be
   ;; generated.
   properties :- {(s/optional-key :client-id) s/Str
                  (s/optional-key :client-secret) s/Str
                  :application-name s/Str
                  :homepage-uri s/Str
                  (s/optional-key :description) s/Str
                  :callback-uri s/Str
                  :required-scopes #{s/Keyword}
                  :requires-user-acceptance? s/Bool}]
  (register-client p properties))

(s/defn lookup-client+ :- {:application-name s/Str
                           :homepage-uri s/Str
                           (s/optional-key :description) s/Str
                           :callback-uri s/Str
                           :client-id s/Str
                           :client-secret s/Str
                           :required-scopes #{s/Keyword}
                           :requires-user-acceptance? s/Bool}
  [p :- (s/protocol ClientRegistry)
   client-id :- s/Str]
  (lookup-client p client-id))
