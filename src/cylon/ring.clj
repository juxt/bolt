;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.ring
  (:require
   [com.stuartsierra.component :as component]
   [modular.ring :refer (ring-handler RingHandler)]
   [cylon.request :refer (authenticate-request failed-authentication)]
   [cylon.session :refer (new-session-based-request-authenticator)])
  )

(defn wrap-authentication
  "Ring middleware to pre-authenticate a request through an authenticator. If
given, the failure-handler is given the request to handle in the event
that authentication fails."
  ([h authenticator failure-handler]
     (fn [req]
       (let [auth (authenticate-request authenticator req)]
         (cond auth (h (merge req auth))
               failure-handler (failed-authentication failure-handler req)
               ;; Continue without merging auth
               :otherwise (h req)))))
  ([h authenticator]
     (wrap-authentication h authenticator nil)))

;; This record wraps an existing RingHandler and sets
;; authentication entries in the incoming request, according to its
;; protection system dependency.
(defrecord AuthBinder []
  RingHandler
  (ring-handler [this]
    (-> (:ring-handler this)
        ring-handler
        (wrap-authentication
         (new-session-based-request-authenticator
          :http-session-store (-> this :protection-system :http-session-store)
          :user-roles (-> this :protection-system :user-roles))))))

(defn new-auth-binder
  "Constructor for a ring handler provider that amalgamates all bidi
  routes provided by components in the system."
  []
  (component/using (->AuthBinder) [:protection-system :ring-handler]))
