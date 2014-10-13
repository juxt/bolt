;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.user.protocols)

(defprotocol UserStore
  "A store for users that doesn't involve password hashing"
  (create-user! [_ uid pw-hash email user-details])
  (get-user [_ uid])
  (get-user-password-hash [_ uid])
  (set-user-password-hash! [_ uid pw-hash])
  (get-user-by-email [_ email])
  (delete-user! [_ uid])
  (verify-email! [_ uid]))

(defprotocol VerifyUserEmail
  (user-email-verified! [_ identity]))

;; User management

(defprotocol LoginFormRenderer
  (render-login-form [_ req model]))

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
  (send-email! [_ address subject body content-type]
    "Send an email to a recipient, with the given subject and body. The
    content-type argument is intended to allow the sending of HTML
    emails, with embedded images."))

(defprotocol WelcomeEmailRenderer
  (render-email-verification-message [_ link]
    "Return the text that will be emailed to a new user who has just
    signing up. The text should include the given link."))
