;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.session
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [cylon.session :refer (SessionStore get-session)]
   [cylon.impl.session-atom-state :as state]
   [cylon.authentication :refer (Authenticator authenticate)]
   [cylon.session :refer (renew-session!)]
   [ring.middleware.cookies :refer (wrap-cookies cookies-request)]
   [modular.ring :refer (WebRequestMiddleware WebRequestBinding)]
   [schema.core :as s]))

(defrecord CookieAuthenticator [check-csrf-cookie-to-header?]
  Authenticator
  (authenticate [this request]
    (tracef "Authenticating with cookie: %s" (:uri request))
    (when-let [cookie-val (-> request cookies-request :cookies (get "session-id") :value)]
      (tracef "Authenticating %s with cookie value of %s" (:uri request) cookie-val)
      (when-let [session (get-session (:session-store this) cookie-val)]
        (tracef "Found session, user is %s" (:username session))
        (let [ring-session {:session session ; retain compatibility with Ring's wrap-session
                            :cylon/session-id cookie-val
                            :cylon/session session
                            :cylon/user (:username session)
                            :cylon/authentication-method :cookie}]
          (println check-csrf-cookie-to-header? ring-session (get (:headers request) "x-csrf-token"))
          (if check-csrf-cookie-to-header?
            (if (= cookie-val (get (:headers request) "x-csrf-token"))
              ring-session
              (tracef "CSRF cookie-to-header invalid %s" (get (:headers request) "x-csrf-token")))
            ring-session)))))

  WebRequestMiddleware
  (request-middleware [this]
    (fn [h]
      (wrap-cookies
       (fn [req]
         (if-let [facts (authenticate this req)]
           (-> req
               (merge facts)
               h ; call original handler
               ;; Renew
               #_(merge {:cookies (renew-session! (:session-store this) (:cylon/session-id facts))}))
           (h req)))))))

(defn new-cookie-authenticator [& {:as opts}]
  (component/using
   (->> opts
        (merge {:check-csrf-cookie-to-header? false})
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

  (renew-session! [this uuid]
    (let [expiry (+ (.getTime (java.util.Date.)) (* expiry-seconds 1000))]
      (swap! (:sessions this) update-in [uuid] assoc :expiry expiry)
      {:value uuid :max-age expiry-seconds}))

  (end-session! [this value]
    (swap! (:sessions this) dissoc value))

  (get-session [this uuid]
    (when-let [{:keys [expiry] :as session} (get @(:sessions this) uuid)]
      (when (< (.getTime (java.util.Date.)) expiry)
        session))))

(defn new-atom-backed-session-store [& {:as opts}]
  (->> opts
       (merge {:expiry-seconds 3600})
       (s/validate {:expiry-seconds s/Int})
       map->AtomBackedSessionStore))
