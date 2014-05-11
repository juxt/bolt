;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.authentication
  (:require
   ;;[cylon.user :refer (UserStore lookup-user)]
   [schema.core :as s])
  (:import
   (javax.xml.bind DatatypeConverter)))

;; Define HTTP request authentication

;; TODO
(defprotocol Authenticator
  ;; Return a map, potentially containing entries to be merged with the request.
  (authenticate [_ request]))

;; TODO
(extend-protocol Authenticator
  Boolean
  (authenticate [this request]
    (when this {})))

;; TODO
#_(defprotocol FailedAuthenticationHandler
  (failed-authentication [_ request]))

;; TODO
#_(defrecord HttpBasicAuthenticator [user-store user-roles]
  Authenticator
  (authenticate [_ request]
    (when-let [header (get-in request [:headers "authorization"])]
      (when-let [basic-creds (second (re-matches #"\QBasic\E\s+(.*)" header))]
        (let [[username password] (->> (String. (DatatypeConverter/parseBase64Binary basic-creds) "UTF-8")
                                       (re-matches #"(.*):(.*)")
                                       rest)]
          (when (lookup-user user-store username password)
            {::username username
             ::user-roles user-roles}))))))

;; TODO
#_(defn new-http-basic-authenticator [& {:as opts}]
  (->> opts
       (s/validate {:user-store (s/protocol UserStore)
                    ;; :user-roles (s/protocol UserRoles)
                    })
       map->HttpBasicAuthenticator))
