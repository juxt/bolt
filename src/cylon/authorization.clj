;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.authorization
  (:require
   [cylon.authentication :refer (get-subject-identifier)]))

(defn behalf-of? [authenticator req user]
  (= (get-subject-identifier authenticator req) user))
