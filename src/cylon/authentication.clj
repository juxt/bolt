;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.authentication)

;; Deprecated?

(defprotocol Authenticator
  ;; If the request is authentic, return a map containing additional
  ;; facts about the request.
  (authenticate [_ request]))

(extend-protocol Authenticator
  Boolean
  (authenticate [this request]
    (when this {})))


;; -- NEW AUTH STEPS -----------------------------------------------------------

;; We define a state-machine

;; Steps can register in the state machine

;; but in future, when we've removed the original protocol above, let's rename this to Authenticator
(defprotocol AuthenticationInteraction
  (initiate-authentication-interaction [_ request initial-session-state])
  (get-outcome [_ request])
  #_(clean-resources! [_ request])
)

(defprotocol InteractionStep
  (get-location [_ request])
  ;; Given the request, is this step required? If not, continue to the next step
  (step-required? [_ request]))

;; Each step is a REDIRECT-GET / POST pair

;; We start with a session populated with an original-uri, which is where the user wants to be

;; Login Flow


;; TOTP Flow
