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

(defn get-session-id [request cookie-name]
  (-> request cookies-request :cookies (get cookie-name) :value))

(s/defn get-session-from-cookie :- {:cylon.session/key s/Str
                                    :cylon.session/expiry s/Num
                                    s/Keyword s/Any}
  [request
   cookie-name :- s/Str
   session-store :- (s/protocol SessionStore)]
  (get-session session-store (get-session-id request cookie-name)))
