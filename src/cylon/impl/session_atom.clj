;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.session-atom
  (:require
   [com.stuartsierra.component :as component]
   [cylon.session :refer (HttpSessionStore)]
   [cylon.impl.session-atom-state :as state]
   ))

(defrecord AtomBackedSessionStore [expiry-seconds]
  component/Lifecycle
  (start [this] (assoc this :sessions state/sessions-atom))
  (stop [this] (dissoc this :sessions))

  HttpSessionStore
  (start-session! [this username]
    (let [uuid (str (java.util.UUID/randomUUID))]
      (swap! (:sessions this)
             assoc uuid
             {:username username
              :expiry (+ (.getTime (java.util.Date.)) (* expiry-seconds 1000))})
      ;; TODO: Make this cookie name configurable
      ;; TODO: Use, or remain compatible with, session stores from ring-session
      {:value uuid
       :max-age expiry-seconds}))
  (get-session [this cookies]
    (when-let [{:keys [expiry] :as session} (->> (get cookies "session") :value (get @(:sessions this)))]
      (when (< (.getTime (java.util.Date.)) expiry)
        session)))
  (end-session! [this value]
    (swap! (:sessions this)
           dissoc value)))

(defn new-atom-backed-session-store [expiry-seconds]
  (->AtomBackedSessionStore expiry-seconds))
