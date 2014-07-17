(ns cylon.oauth.application-registry
  (:require
   [schema.core :as s]))

(defprotocol ApplicationRegistry
  (register-application [_ properties])
  (lookup-application [_ client-id]))

(s/defn register-application+ :- {:client-id s/Str
                                  :client-secret s/Str}
  [p :- (s/protocol ApplicationRegistry)
   ;; If client-id and/or client-secret are not specified, they will be
   ;; generated.
   properties :- {(s/optional-key :client-id) s/Str
                  (s/optional-key :client-secret) s/Str
                  :application-name s/Str
                  :homepage-uri s/Str
                  (s/optional-key :description) s/Str
                  :callback-uri s/Str}]
  (register-application p properties))

(s/defn lookup-application+ :- {:application-name s/Str
                                :homepage-uri s/Str
                                (s/optional-key :description) s/Str
                                :callback-uri s/Str
                                :client-id s/Str
                                :client-secret s/Str}
  [p :- (s/protocol ApplicationRegistry)
   client-id :- s/Str]
  (lookup-application p client-id))
