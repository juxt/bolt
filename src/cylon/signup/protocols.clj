(ns cylon.signup.protocols)

(defprotocol SignupFormRenderer
  (render-signup-form [_ req model]))

(defprotocol WelcomeRenderer
  (render-welcome [_ req model]))

(defprotocol EmailVerifiedRenderer
  (render-email-verified [_ req model]))

(defprotocol ResetPasswordRenderer
  (render-reset-password [_ req model]))

(defprotocol Emailer
  (send-email [_ email subject body]))
