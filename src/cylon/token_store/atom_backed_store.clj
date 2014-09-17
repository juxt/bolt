(ns cylon.token-store.atom-backed-store
  (:require
   [cylon.token-store.protocols :refer (TokenStore get-token-by-id renew-token! purge-token!)]
   [com.stuartsierra.component :refer (Lifecycle)]
   [schema.core :as s]
   ))

(defn expiry-date
  "Calculate an expiry date in the future"
  [ttl-in-secs]
  (assert (pos? ttl-in-secs))
  (java.util.Date.
   (+ (.getTime (java.util.Date.))
      (* ttl-in-secs 1000))))

(defn now
  "Return now in milliseconds since the epoch"
  []
  (.getTime (java.util.Date.)))

(defrecord AtomBackedTokenStore [ttl-in-secs tokens]
  TokenStore
  (create-token! [component id m]
    (when (get-token-by-id component id)
      (throw (ex-info "Token id already used" {:id id})))
    (let [token (merge (when ttl-in-secs {:cylon/expiry (expiry-date ttl-in-secs)}) (merge {:cylon/token-id id}  m))]
      (swap! tokens assoc id token)
      token))

  (get-token-by-id [component id]
    (let [token (get @tokens id)
          expiry (:cylon/expiry token)]
      (cond
       (nil? expiry) token
       (< (now) (.getTime expiry)) (do
                                     (println "Must renew token")
                                     (renew-token! component id))
       :otherwise (do
                    (println "Must purge token")
                    (purge-token! component id)
                    ))))

  (purge-token! [_ id]
    (swap! tokens dissoc id)
    nil)

  (renew-token! [_ id]
    (swap! tokens update-in [id]
           #(if (:cylon/expiry %)
              (assoc % :cylon/expiry (expiry-date ttl-in-secs))
              %))
    ;; Return the renewed token
    (get @tokens id))

  (merge-token! [component id m]
    (if-let [token (get-token-by-id component id)]
      (let [newtoken (merge token m)]
        (swap! tokens assoc id newtoken)
        newtoken)))

  (dissoc-token! [component id ks]
    (if-let [token (get-token-by-id component id)]
      (let [newtoken (dissoc token ks)]
        (swap! tokens assoc id newtoken)
        newtoken))))

(def new-atom-backed-token-store-schema
  {:ttl-in-secs (s/maybe s/Num) ; nil means 'do not expire'
   :tokens s/Any})

(defn new-atom-backed-token-store [& {:as opts}]
  (->> opts
       (merge {:ttl-in-secs (* 60 60 4)
               :tokens (atom {})})
       (s/validate new-atom-backed-token-store-schema)
       map->AtomBackedTokenStore))
