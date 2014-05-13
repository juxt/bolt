;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.session
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [cylon.session :refer (SessionStore get-session)]
   [cylon.impl.session-atom-state :as state]
   [modular.ring :refer (ring-handler RingHandler)]
   [cylon.authentication :refer (Authenticator authenticate)]
   [ring.middleware.cookies :refer (cookies-request)]
   [schema.core :as s]))

(defrecord CookieAuthenticator []
  Authenticator
  (authenticate [this request]
    (when-let [session (get-session (:session-store this)
                                    (-> request cookies-request :cookies (get "session") :value))]
      {:session session  ; retain compatibility with Ring's wrap-session
       :cylone/session session
       :cylon/user (:username session)
       :cylon/authentication-method :cookie})))

(defn new-cookie-authenticator [& {:as opts}]
  (component/using
   (->> opts
        map->CookieAuthenticator)
   [:session-store]))

(defrecord AtomBackedSessionStore [expiry-seconds]
  component/Lifecycle
  (start [this] (assoc this :sessions state/sessions-atom))
  (stop [this] (dissoc this :sessions))

  SessionStore
  (start-session! [this username]
    (let [uuid (str (java.util.UUID/randomUUID))
          expiry (+ (.getTime (java.util.Date.)) (* expiry-seconds 1000))]
      (swap! (:sessions this) assoc uuid {:username username :expiry expiry})
      {:value uuid :max-age expiry-seconds}))

  (get-session [this value]
    (when-let [{:keys [expiry] :as session} (get @(:sessions this) value)]
      (when (< (.getTime (java.util.Date.)) expiry)
        session)))

  (end-session! [this value]
    (swap! (:sessions this) dissoc value)))

(defn new-atom-backed-session-store [& {:as opts}]
  (->> opts
       (merge {:expiry-seconds 3600})
       (s/validate {:expiry-seconds s/Int})
       map->AtomBackedSessionStore))
