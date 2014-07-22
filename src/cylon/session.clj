;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.session
  (:require
   [com.stuartsierra.component :as component]
   [ring.middleware.cookies :refer (cookies-request)]
   [schema.core :as s]))

(defprotocol SessionStore
  (create-session! [_ m])
  (get-session [_ id])
  (renew-session! [_ id])
  (purge-session! [_ id])
  (assoc-session! [_ id k v])
  (dissoc-session! [_ id k]))

(defn ->cookie [session]
  {:value (::key session)
   :max-age (long (/ (::expiry session) 1000))
   :path "/"
   })

(defn get-cookie-value [request cookie-name]
  (-> request cookies-request :cookies (get cookie-name) :value))

(defn get-session-value [request cookie-name session-store k]
  (get (get-session session-store (get-cookie-value request cookie-name)) k))
