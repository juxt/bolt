;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns bolt.user.protocols)

(defprotocol UserStore
  "A store for users that doesn't involve password hashing"

  (check-create-user [_ user]
    "Check the user can be created. E.g. username and/or email doesn't
already exist, otherwise render an error page, all required fields in
correct format, etc. All fields are sent apart from the password. This
is exposed as a function so that it be used in form validation prior to
submission. May return a (manifold) deferred for async.")

  (create-user! [_ user]
    "Create the user. Implementations should call, and return the result
of, create-user-error? prior to adding the user to storage. Returns the
created user, perhaps with more information than the parameter
given. May return the user wrapped in a (manifold) deferred for async.")

  (find-user [_ id]
    "Find the user identified by id")

  (update-user! [_ id user]
    "Update the user identified by id with the new details provided")

  (delete-user! [_ id]
    "Delete the user identified by id")

  (verify-email! [_ email]
    "Verify that the given email exists"))

(defprotocol UserAuthenticator
  (authenticate-user [_ user evidence]
    "Return some signed token upon valid evidence"))

(defprotocol UserPasswordHasher
  (hash-password [_ password]
    "Return a hash of a plain-text password, as a string"))

(defprotocol LoginFormRenderer
  (render-login-form [_ req model]
    "Render a login from from the data contained in the given model"))

;; TODO: Split up into separate protocols for modularity
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
