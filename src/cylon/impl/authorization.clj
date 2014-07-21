;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.impl.authorization
  (:require
   [com.stuartsierra.component :as component]
   [clojure.set :refer (union)]
   [clojure.tools.logging :refer :all]
   [cylon.role :refer (user-in-role?)]
   [cylon.authorization :refer (RequestAuthorizer)]
   [cylon.authentication :refer (authenticate)]
   [schema.core :as s]))

;; A ValidUserRequestAuthorizer simply checks for :cylon/user in the
;; request. If there is one, they are authorized.
(defrecord ValidUserRequestAuthorizer []
  RequestAuthorizer
  (request-authorized? [this request _]
    (:cylon/user (authenticate (:authenticator this) request))))

(defn new-valid-user-authorizer []
  (component/using
   (->ValidUserRequestAuthorizer) [:authenticator]))

(defrecord StaticUserRequestAuthorizer []
  RequestAuthorizer
  (request-authorized? [this request user]
    (= user (:cylon/user request))))

(defn new-static-user-authorizer [& {:as opts}]
  (->> opts
       map->StaticUserRequestAuthorizer))

(defrecord RoleBasedRequestAuthorizer [user-role-mappings]
  RequestAuthorizer
  (request-authorized? [this request requirement]
    (when-let [roles (:cylon/roles request)]
      (user-in-role? user-role-mappings (:cylon/user request) requirement))))

(defn new-role-based-authorizer [& {:as opts}]
  (->> opts
       (s/validate {:user-role-mappings s/Any})
       map->RoleBasedRequestAuthorizer))
