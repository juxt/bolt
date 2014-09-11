;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.session
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :as component]
   [cylon.session :refer (SessionStore get-session BrowserSession get-data exists? create-and-attach! create-session! cookies-response-with-session purge-session! assoc-session! Store)]
   [cylon.impl.session-atom-state :as state]
   [cylon.authentication :refer (Authenticator authenticate)]
   [cylon.session :refer (renew-session! purge-session! get-session-id)]
   [ring.middleware.cookies :refer (wrap-cookies cookies-request)]
   [modular.ring :refer (WebRequestMiddleware WebRequestBinding)]
   [schema.core :as s]
   [plumbing.core :refer (<-)]))

(defrecord CookieAuthenticator []
  Authenticator
  (authenticate [this request]
    (tracef "Authenticating with cookie: %s" (:uri request))
    (when-let [cookie-val (-> request cookies-request :cookies (get "session-id") :value)]
      (tracef "Authenticating %s with cookie value of %s" (:uri request) cookie-val)

      (when-let [session (get-session (:session-store this) cookie-val)]
        (tracef "Found session, user is %s" (:username session))
        {:session session  ; retain compatibility with Ring's wrap-session
         :cylon/session-id cookie-val
         :cylon/session session
         :cylon/identity (:identity session)
         :cylon/authentication-method :cookie})))

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
      (let [res (merge m {:cylon.session/key key
                          :cylon.session/expiry expiry-in-ms})]
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
    (assert id)
    (swap! (:sessions this)
           (fn [sessions] (update-in sessions [id]
                                     (fn [session]
                                       (assert session)
                                       (assoc session k v))))))

  (dissoc-session! [this id k]
    (swap! (:sessions this) update-in [id] dissoc k)))

(defn new-atom-backed-session-store [& {:as opts}]
  (->> opts
       (merge {:expiry-seconds (* 4 60 60)})
       (s/validate {:expiry-seconds s/Int
                    :id s/Keyword})
       map->AtomBackedSessionStore))



(defrecord AtomBackedStore [expiry-seconds]
  component/Lifecycle
  (start [this] (assoc this :rows (atom {})))
  (stop [this] (dissoc this :rows))

  Store
  (create-store! [this m]
    (let [key (str (java.util.UUID/randomUUID))]
      (let [res (merge m {:cylon.session/key key})]
        (swap! (:rows this) assoc key res)
        res)))

  (get-store [this id]
    (get @(:rows this) id))


  (purge-store! [this id]
    (swap! (:rows this) dissoc id)
    nil)

  (assoc-store! [this id k v]
    (assert id)
    (swap! (:rows this)
           (fn [rows] (update-in rows [id]
                                (fn [row]
                                  (assert row)
                                  (assoc row k v))))))

  (dissoc-store! [this id k]
    (swap! (:rows this) update-in [id] dissoc k)))

(defn new-atom-backed-store [& {:as opts}]
  (->> opts
       (s/validate {:id s/Keyword})
       map->AtomBackedStore))



(defrecord UserBrowserSession [cookie-id]
  BrowserSession
  (exists? [this req]
    (when-let  [session-id (get-session-id req cookie-id)]
      ((complement nil?) (get-session (:session-store this) session-id))) )
  (create-and-attach! [this req resp]
    (create-and-attach! this req resp {})
    )
  (create-and-attach! [this req response data]
    (->>
     (create-session! (:session-store this) data)
     (cookies-response-with-session response cookie-id)))

  (remove! [this req]

    (purge-session! (:session-store this) (get-session-id req cookie-id))
    )
  (get-data [this req]
    (assert (exists? this req) (format "No session available for: %s" cookie-id))
    (->> (get-session-id req cookie-id)
         (get-session (:session-store this))))
  (get-data [this req key]
    (get (get-data this req) key))

  (assoc-data! [this req data]
    (let [session-id (get-session-id req cookie-id)]
      (doseq [[k v] data]
        (assoc-session! (:session-store this) session-id k v))
      ))
  (dissoc-data! [this req key]))

(defn new-browser-session [& {:as opts}]
  (->> opts
       (merge {:expiry-seconds (* 4 60 60)})
       (s/validate
        {:cookie-id s/Str
         :expiry-seconds s/Int})
       map->UserBrowserSession
       (<- (component/using
            [:session-store]))))
