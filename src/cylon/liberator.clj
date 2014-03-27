;; Copyright © 2014 JUXT LTD.

(ns ^{:doc "Support for Liberator's authorized? decision point"}
  cylon.liberator
  (:require
   [cylon.core :refer (new-composite-disjunctive-request-authorizer
                       new-session-based-request-authorizer
                       new-http-basic-request-authorizer
                       HttpSessionStore
                       UserPasswordAuthorizer
                       authorized-request?)]
   [schema.core :as s]))

;; For a REST API, it is useful to support both HTTP Basic
;; Authentication (for machines) but to honor cookies passed from a
;; browser in an AJAX call, when the user has logged in via a login
;; form.

;; Here are some utility functions that take a protection system and
;; return a function which takes a Ring request and returns whether that
;; request is authorized. This is useful to implement the authorizd? decision point in Liberator.

(defn make-composite-authorizer
  "Construct a composite authorizer, based on "
  [protection-domain]

  (let [{:keys [http-session-store user-password-authorizer]}
        (s/validate {:http-session-store (s/protocol HttpSessionStore)
                     :user-password-authorizer (s/protocol UserPasswordAuthorizer)
                     }
                    (select-keys protection-domain [:http-session-store :user-password-authorizer]))]
    (fn [context]
      (let [authorizer
            (new-composite-disjunctive-request-authorizer
             (new-session-based-request-authorizer :http-session-store http-session-store)
             (new-http-basic-request-authorizer :user-password-authorizer user-password-authorizer))]

        (when-let [auth (authorized-request? authorizer (:request context))]
          {:auth-request auth})))))
