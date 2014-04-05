;; Copyright © 2014 JUXT LTD.

(ns ^{:doc "Support for Liberator's authorized? and allowed? decision points"}
  cylon.liberator
  (:require
   [cylon.core :refer (new-composite-disjunctive-request-authenticator
                       new-session-based-request-authenticator
                       new-http-basic-request-authenticator
                       HttpSessionStore
                       UserAuthenticator
                       allowed-request?)]
   [schema.core :as s]))

;; For a REST API, it is useful to support both HTTP Basic
;; Auth (for machines) but to honor cookies passed from a
;; browser in an AJAX call, when the user has logged in via a login
;; form.

;; Here are some utility functions that take a protection system and
;; return a function which takes a Ring request and returns whether that
;; request is authenticated. This is useful to implement the authorized?
;; or allowed? decision points in Liberator.

(defn make-composite-authenticator
  "Construct a composite authenticator"
  [protection-domain]

  (let [{:keys [http-session-store user-authenticator]}
        (s/validate {:http-session-store (s/protocol HttpSessionStore)
                     :user-authenticator (s/protocol UserAuthenticator)}
           (select-keys protection-domain [:http-session-store :user-authenticator]))]
    (fn [context]
      (let [authenticator
            (new-composite-disjunctive-request-authenticator
             (new-session-based-request-authenticator :http-session-store http-session-store)
             (new-http-basic-request-authenticator :user-authenticator user-authenticator))]

        (when-let [auth (allowed-request? authenticator (:request context))]
          {:auth-request auth})))))
