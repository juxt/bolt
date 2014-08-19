;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.session
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [cylon.session :refer (SessionStore get-session)]
   [cylon.impl.session-atom-state :as state]
   [cylon.authentication :refer (Authenticator authenticate)]
   [cylon.session :refer (renew-session! purge-session!)]
   [ring.middleware.cookies :refer (wrap-cookies cookies-request)]
   [modular.ring :refer (WebRequestMiddleware WebRequestBinding)]
   [schema.core :as s]))

(defrecord CookieAuthenticator [check-csrf-cookie-to-header?]
  Authenticator
  (authenticate [this request]
    (tracef "Authenticating with cookie: %s" (:uri request))
    (when-let [cookie-val (-> request cookies-request :cookies (get "session-id") :value)]
      (tracef "Authenticating %s with cookie value of %s" (:uri request) cookie-val)

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
            ring-session))))

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
  (start [this] (assoc this :sessions (atom {})))
  (stop [this] (dissoc this :sessions))

  SessionStore
  (create-session! [this m]
    (let [key (str (java.util.UUID/randomUUID))
          expiry-in-ms (+ (.getTime (java.util.Date.)) (* expiry-seconds 1000))]
      (let [res (merge m {:cylon.session/key key :cylon.session/expiry expiry-in-ms})]
        (swap! (:sessions this) assoc key res)
        res)))

  (get-session [this id]
    (when-let [{expiry :cylon.session/expiry :as session} (get @(:sessions this) id)]
      (if (< (.getTime (java.util.Date.)) expiry)
        session
        (purge-session! this id))))

  (renew-session! [this id]
    (let [expiry-in-ms (+ (.getTime (java.util.Date.)) (* expiry-seconds 1000))]
      (swap! (:sessions this) update-in [id] assoc :cylon.session/expiry expiry-in-ms)
      (get @(:sessions this) id)))

  (purge-session! [this id]
    (swap! (:sessions this) dissoc id)
    nil)

  (assoc-session! [this id k v]
    (swap! (:sessions this) update-in [id] assoc k v))

  (dissoc-session! [this id k]
    (swap! (:sessions this) update-in [id] dissoc k)))

(defn new-atom-backed-session-store [& {:as opts}]
  (->> opts
       (merge {:expiry-seconds (* 4 60 60)})
       (s/validate {:expiry-seconds s/Int
                    :id s/Keyword})
       map->AtomBackedSessionStore))
