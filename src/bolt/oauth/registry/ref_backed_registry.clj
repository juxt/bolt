(ns cylon.oauth.registry.ref-backed-registry
  (require
   [com.stuartsierra.component :as component]
   [cylon.oauth.registry.protocols :refer (ClientRegistry)]))

;; Optional ClientRegistry implementation

(defrecord RefBackedClientRegistry []
  component/Lifecycle
  (start [this]
    (assoc this :store {:last-client-id (ref 1000)
                        :clients (ref {})}))
  (stop [this] this)

  ClientRegistry
  (register-client [this properties]
    (dosync
     (let [client-id (or (:client-id properties)
                         (str (alter (-> this :store :last-client-id) inc)))
           properties (assoc properties
                        :client-id client-id
                        :client-secret (or (:client-secret properties)
                                           (str (java.util.UUID/randomUUID))))]
       (alter (-> this :store :clients) assoc client-id properties)
       (select-keys properties [:client-id :client-secret]))))

  (lookup-client [this client-id]
    (-> this :store :clients deref (get client-id))))

(defn new-ref-backed-client-registry []
  (->RefBackedClientRegistry))
