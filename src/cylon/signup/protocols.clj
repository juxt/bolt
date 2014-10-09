(ns cylon.signup.protocols)

(defprotocol SignupFormRenderer
  (render-signup-form [_ req model]))

(defprotocol SimpleMessageRenderer
  (render-simple-message [_ req heading message]))

(defprotocol RequestResetPasswordFormRenderer
  (render-request-reset-password-form [_ req model]))

(defprotocol WelcomeRenderer
  (render-welcome [_ req model]))

(defprotocol EmailVerifiedRenderer
  (render-email-verified [_ req model]))

(defprotocol Emailer
  (send-email [_ email title body])
  (send-verification-link [_ email link])
  )

(defprotocol EmailVerifier
  (send-verification [_ req email]))

(def verify-email-results-codes
  {::success "Thanks, Your email has been verified correctly"
   ::error-email-not-in-store "Sorry but your session associated with this email seems to not be logic"
   ::error-code-not-valid "Sorry but your session associated with this email seems to not be valid"
   ::error-form-data "Sorry but there were problems trying to retrieve your data related"})
