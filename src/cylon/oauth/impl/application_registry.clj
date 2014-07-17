(ns cylon.oauth.impl.application-registry
  (require    [com.stuartsierra.component :as component]
              [cylon.oauth.application-registry :refer (ApplicationRegistry)]))

;; Optional ApplicationRegistry implementation

(defrecord RefBackedApplicationRegistry []
  component/Lifecycle
  (start [this]
    (assoc this :store {:last-client-id (ref 1000)
                        :applications (ref {})}))
  (stop [this] this)

  ApplicationRegistry
  (register-application [this properties]
    (dosync
     (let [client-id (or (:client-id properties)
                         (str (alter (-> this :store :last-client-id) inc)))
           properties (assoc properties
                        :client-id client-id
                        :client-secret (or (:client-secret properties)
                                           (str (java.util.UUID/randomUUID))))]
       (alter (-> this :store :applications) assoc client-id properties)
       (select-keys properties [:client-id :client-secret]))))

  (lookup-application [this client-id]
    (-> this :store :applications deref (get client-id))))

(defn new-ref-backed-application-registry []
  (->RefBackedApplicationRegistry))
