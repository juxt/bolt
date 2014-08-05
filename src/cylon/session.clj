;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.session
  (:require
   [com.stuartsierra.component :as component]
   [ring.middleware.cookies :refer (cookies-request cookies-response)]
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
   :expires (.toGMTString
             (doto (new java.util.Date)
               (.setTime (::expiry session))))
   :path "/"})

(defn cookies-response-with-session [response id-cookie session]
  ;; Use of cookies-response mean it is non-destructive - existing
  ;; cookies are preserved (but existing :cookies entries are not)
  (cookies-response
   (merge-with merge response
    {:cookies {id-cookie (->cookie session)}})))

(defn get-session-id [request cookie-name]
  (-> request cookies-request :cookies (get cookie-name) :value))

(s/defn get-session-from-cookie :- (s/maybe {:cylon.session/key s/Str
                                             :cylon.session/expiry s/Num
                                             s/Keyword s/Any})
  [request
   cookie-name :- s/Str
   session-store :- (s/protocol SessionStore)]
  (get-session session-store (get-session-id request cookie-name)))

(defn get-session-value [request cookie-name session-store k]
    (get (get-session-from-cookie request cookie-name session-store) k))
