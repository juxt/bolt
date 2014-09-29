;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.password.protocols)

(defprotocol PasswordHashAlgorithm
  (make-hash [_ password salt])
  (check [_ password salt hashed]))

(defprotocol PasswordPolicy
  "Check password for validity against a policy. For example, the
  password should contain more than 6 characters. Should return nil if
  the password is valid, otherwise a reason map: {:reason str}."
  (check-password-for-validity [_ password]))

(defprotocol PasswordVerifier
  (verify-password [_ user password])
  (make-password-hash [_ password]))
