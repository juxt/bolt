(ns cylon.authorization.protocols
  (:require
   [clojure.tools.logging :refer :all]))


;; A RequestAuthorizer is responsible for protected sensitive resources
;; in addition to determining the access credentials of a potential
;; accessor.

(defprotocol RequestAuthorizer
  ;; Determine if given credentials (found in request) meet a given requirement
  (authorized-request? [_ req requirement]))

(extend-protocol RequestAuthorizer
  nil
  (request-authorized? [_ req requirement]
    (warnf "RequestAuthorizer is nil, so failing authorization check")
    false))
