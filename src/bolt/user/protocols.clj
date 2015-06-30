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
  (authenticate-user [_ user credential]
    "Return truthy if credential is valid"))

(defprotocol UserPasswordHasher
  (hash-password [_ password]
    "Return a hash of a plain-text password, as a string"))

(defprotocol UserStoreAdmin
  (list-users [_] "Return a list of users"))
