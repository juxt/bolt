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

(defprotocol ResetUserEmail
  (find-user-by-email [_ email])
  (reset-password! [_ indentity password])
  )
