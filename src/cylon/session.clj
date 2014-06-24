;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.session
  (:require
   [com.stuartsierra.component :as component]

   [schema.core :as s]))

(defprotocol SessionStore
  (start-session! [_ username]) ; return cookie map compatible with wrap-cookies
  (renew-session! [_ uuid])
  (end-session! [_ uuid])
  (get-session [_ uuid]))



;; TODO
#_(defn wrap-authentication
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
;; TODO
#_(defrecord AuthenticationInterceptor []
  RingHandler
  (ring-handler [this]
    (-> (:ring-handler this)
        ring-handler
        (wrap-authentication
         (new-session-based-request-authenticator
          :session-store (:session-store this))))))

;; TODO
#_(defn new-authentication-interceptor
  ""
  []
  (component/using (->AuthenticationInterceptor) [:session-store :ring-handler]))
