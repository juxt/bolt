;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.request
  (:require
   [cylon.user :refer (UserAuthenticator authenticate-user)]
   [schema.core :as s])
  (:import
   (javax.xml.bind DatatypeConverter))
)

;; Define HTTP request authentication

;; TODO
#_(defprotocol HttpRequestAuthenticator
  ;; Return a map, potentially containing entries to be merged with the request.
  (authenticate-request [_ request]))

;; TODO
#_(extend-protocol HttpRequestAuthenticator
  Boolean
  (authenticate-request [this request]
    (when this {})))

;; TODO
#_(defprotocol FailedAuthenticationHandler
  (failed-authentication [_ request]))

;; TODO
#_(defrecord HttpBasicRequestAuthenticator [user-authenticator user-roles]
  HttpRequestAuthenticator
  (authenticate-request [_ request]
    (when-let [auth (get-in request [:headers "authorization"])]
      (when-let [basic-creds (second (re-matches #"\QBasic\E\s+(.*)" auth))]
        (let [[username password] (->> (String. (DatatypeConverter/parseBase64Binary basic-creds) "UTF-8")
                                       (re-matches #"(.*):(.*)")
                                       rest)]
          (when (authenticate-user user-authenticator username password)
            {::username username
             ::user-roles user-roles}))))))

;; TODO
#_(defn new-http-basic-request-authenticator [& {:as opts}]
  (->> opts
       (s/validate {:user-authenticator (s/protocol UserAuthenticator)
                    ;; :user-roles (s/protocol UserRoles)
                    })
       map->HttpBasicRequestAuthenticator))
