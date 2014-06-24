;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.authentication
  (:require
   [com.stuartsierra.component :as component]
   [cylon.authentication :refer (Authenticator authenticate)]
   [clojure.tools.logging :refer :all]
   [cylon.user :refer (UserStore verify-user)]
   [schema.core :as s])
  (:import
   (javax.xml.bind DatatypeConverter)))

(defrecord StaticAuthenticator [user]
  Authenticator
  (authenticate [this request]
    {:cylon/user user}))

(defn new-static-authenticator [& {:as opts}]
  (->> opts
       (s/validate {:user s/Str})
       map->StaticAuthenticator))

(defrecord HttpBasicAuthenticator []
  Authenticator
  (authenticate [this request]
    (when-let [header (get-in request [:headers "authorization"])]
      (when-let [basic-creds (second (re-matches #"\QBasic\E\s+(.*)" header))]
        (let [[user password] (->> (String. (DatatypeConverter/parseBase64Binary basic-creds) "UTF-8")
                                   (re-matches #"(.*):(.*)")
                                   rest)]
          (when (verify-user (:user-domain this) user password)
            {:cylon/user user
             :cylon/authentication-method :http-basic}))))))


(defn new-http-basic-authenticator [& {:as opts}]
  (component/using
   (->> opts
        map->HttpBasicAuthenticator)
   [:user-domain]))

;; A request authenticator that tries multiple authenticators in
;; turn. Disjunctive means that a positive result from any given
;; authenticator is sufficient.
(defrecord CompositeDisjunctiveAuthenticator []
  Authenticator
  (authenticate [this request]
    (->> this vals
         (filter (partial satisfies? Authenticator))
         (some #(authenticate % request) ))))

(defn new-composite-disjunctive-authenticator [& deps]
  (component/using
   (->CompositeDisjunctiveAuthenticator)
   (vec deps)))

;; If you're looking for CookieAuthenticator, it's in cylon.impl.session
