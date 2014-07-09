;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.authorization
  (:require
   [schema.core :as s]
   [cylon.restricted :as restricted]
   [cylon.authentication :refer (authenticate)]
   [clojure.tools.logging :refer :all]))

;; Now we can define authorization for Ring handlers (and other
;; functions). In Cylon, it is handlers that are restricted, rather than
;; routes. Handlers are 'closer' to the data, since they serve it, and
;; it is better to consider authorization at the level of the data,
;; rather than define authorizations in the routing logic. The design
;; goal is for Cylon to be completely agnostic to the means by which
;; handlers are accessed, whether via a particular routing library
;; (Compojure, bidi, etc.) or via some other mechanism.

;; An Authorizer is responsible for protected sensitive resources in
;; addition to determining the access credentials of a potential
;; accessor.

(defprotocol Authorizer
  ;; Determine if given credentials (found in request) meet a given
  ;; requirement
  (authorized? [_ req requirement]))

(extend-protocol Authorizer
  nil
  (authorized? [_ req requirement]
    (warnf "Authorizer is nil, so failing authorization check")
    false))

;; Note: this implementation will cause the authenticator to be called twice if calling code wraps an invoke call with a restricted/authorized? check

(defrecord RestrictedHandler [f authorizer requirement rejectfn]
  restricted/Restricted
  (restricted/authorized? [this req]
    (authorized?
     authorizer
     (if-let [authenticator (:authenticator authorizer)]
       (merge req (authenticate authenticator req))
       req)
     requirement))

  clojure.lang.IFn
  (invoke [this req]
    ;; We are applying the restricted/authorized? function defined above
    (if (restricted/authorized?
         this
         (if-let [authenticator (:authenticator authorizer)]
           (merge req (authenticate authenticator req))
           req))
      (f req)
      ;; If you don't want this default, call authorized? first
      (rejectfn req))))

(defn restrict-fn
  "Restrict a given function, such as a Ring handler, by some classification (which could be a set of roles, or anything that indicates the qualifying credentials a caller must exhibit in order to call the function. A function (or IFn) is returned."
  [f authorizer requirement rejectfn]
  (->RestrictedHandler f authorizer requirement rejectfn))

(defn restrict-handler
  ([handler authorizer requirement rejectfn]
     (restrict-fn handler authorizer requirement rejectfn))
  ([handler authorizer]
     (restrict-fn handler authorizer nil))
  ([handler authorizer requirement]
     (restrict-fn handler authorizer requirement
                  (constantly {:status 401 :body "Unauthorized"}))))

(defn restrict-handlers
  "Restrict all the values in the given map according to the given
  authorizer."
  ([m authorizer]
     (reduce-kv (fn [acc k v] (assoc acc k (restrict-handler v authorizer))) {} m))
  ([m authorizer rejectfn]
     (reduce-kv (fn [acc k v] (assoc acc k (restrict-handler v authorizer rejectfn))) {} m)))
