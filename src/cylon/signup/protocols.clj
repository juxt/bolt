;; Copyright © 2014, JUXT LTD. All Rights Reserved.

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
  (send-email! [_ address subject body content-type]
    "Send an email to a recipient, with the given subject and body. The
    content-type argument is intended to allow the sending of HTML
    emails, with embedded images."))

(defprotocol WelcomeEmailRenderer
  (render-email-verification-message [_ link]
    "Return the text that will be emailed to a new user who has just
    signing up. The text should include the given link."))
