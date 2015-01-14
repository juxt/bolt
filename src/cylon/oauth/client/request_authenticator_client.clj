(ns cylon.oauth.client.request-authenticator-client
  (:require [com.stuartsierra.component :as component]
            [cylon.token-store :refer (get-token-by-id)]
            [cylon.session :refer (session)]
            [cylon.authentication.protocols :refer (RequestAuthenticator)]))

(defrecord RequestAuthenticatorClient [session-store access-token-store]
  RequestAuthenticator
  (authenticate [component request]
    (let [{access-token :cylon/access-token
           scopes :cylon/scopes
           sub :cylon/subject-identifier :as authentication} (session session-store request)]
      (when (get-token-by-id access-token-store access-token)
        authentication))))

(defn new-client-request-authenticator
  "If your webapp behaves as resource server (so it has protected resources),
  then your webapp needs to authenticate the requests using current sesssion and access-token-store"
  [& {:as opts}]
  (component/using
   (->> opts
        (merge {})
        map->RequestAuthenticatorClient)
   [:session-store :access-token-store]))
