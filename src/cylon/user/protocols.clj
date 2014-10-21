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

(defprotocol Emailer
  (send-email! [_ data]
    "Send an email to a recipient, with the given subject and body. The
    data may optionally contain a :content-type entry that is intended
    to allow the sending of HTML emails, with embedded images."))

(defprotocol LoginFormRenderer
  (render-login-form [_ req model]
    "Render a login from from the data contained in the given model"))

(defprotocol UserFormRenderer
  (render-signup-form [_ req model]
    "Return the HTML that will be used to display the sign up form for a
    new user to complete.")
  (render-welcome [_ req model]
    "Return the HTML that will be used to welcome the new user.")
  (render-welcome-email-message [_ model]
    "Return the text that will be emailed to a new user who has just
    signing up. The text should include the given link. Return nil for
    no email message.")
  (render-email-verified [_ req model]
    "Return the HTML that will be used to thank the user for verifying
    their email address.")
  (render-reset-password-request-form [_ req model]
    "Return the HTML that will be used to capture the email address of a user that wishes to reset their password.")
  (render-reset-password-email-message [_ model]
    "Return the text that will be emailed to a user, including a link
    that allows them to reset their password.")
  (render-reset-password-link-sent-response [_ req model]
    "Return the HTML that will inform a user that an email has been sent")
  (render-password-reset-form [_ req model]
    "Return the HTML that will be used to display the password reset
    form that will capture the new password. ")
  (render-password-changed-response [_ req model]
    "Return the HTML that will be used to tell the user that their
    password has been changed.")
  )

(defprotocol ErrorRenderer
  (render-error-response [_ req model]
    "If anything fails, gracefully report to the user."))
