;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.session
  (:require
   [com.stuartsierra.component :as component]
   [cylon.request :refer (HttpRequestAuthenticator authenticate-request)]
   [ring.middleware.cookies :refer (cookies-request)]
   [schema.core :as s])
  )

(defprotocol HttpSessionStore
  (start-session! [_ username]) ; return cookie map compatible with wrap-cookies
  (get-session [_ request])
  (end-session! [_ value]))

(defrecord SessionBasedRequestAuthenticator [http-session-store user-roles]
  HttpRequestAuthenticator
  (authenticate-request [_ request]
    (when-let [session (get-session http-session-store (:cookies (cookies-request request)))]
      {:session session ; retain compatibility with Ring's wrap-session
       ::session session
       ::username (:username session)
       ;;::user-roles user-roles
       })))

(defn new-session-based-request-authenticator [& {:as opts}]
  (->> opts
       (s/validate {:http-session-store (s/protocol HttpSessionStore)
                    ;; :user-roles (s/protocol UserRoles)
                    })
       map->SessionBasedRequestAuthenticator))
