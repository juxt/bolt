(ns cylon.oauth.registry.protocols)

(defprotocol ClientRegistry
  (register-client [_ properties])
  (lookup-client [_ client-id]))
