;; Copyright © 2014 JUXT LTD.

(ns ^{:doc "Support for Liberator's authorized? and allowed? decision points"}
  cylon.impl.liberator
  (:require
   #_[cylon.session :refer (SessionStore new-session-based-request-authenticator)]
   #_[cylon.impl.request :refer (new-composite-disjunctive-request-authenticator)]
   #_[cylon.request :refer (new-http-basic-request-authenticator authenticate-request)]
   [cylon.user :refer (UserAuthenticator)]
   [schema.core :as s]))

;; For a REST API, it is useful to support both HTTP Basic
;; Auth (for machines) but to honor cookies passed from a
;; browser in an AJAX call, when the user has logged in via a login
;; form.

;; Here are some utility functions that take a protection system and
;; return a function which takes a Ring request and returns whether that
;; request is authenticated. This is useful to implement the authorized?
;; or allowed? decision points in Liberator.

#_(defn make-composite-authenticator
  "Construct a composite authenticator"
  [& {:as opts}]

  (let [{:keys [session-store user-authenticator]}
        (->> opts
             (s/validate {:session-store (s/protocol SessionStore)
                          :user-authenticator (s/protocol UserAuthenticator)}))]

    (fn [context]
      (let [authenticator
            (new-composite-disjunctive-request-authenticator
             (new-session-based-request-authenticator :session-store session-store)
             (new-http-basic-request-authenticator :user-authenticator user-authenticator))]

        (when-let [auth (authenticate-request authenticator (:request context))]
          {:auth-request auth})))))
