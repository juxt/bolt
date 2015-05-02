;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.restricted)

(defprotocol Restricted
  (authorized? [_ credentials]))

(extend-protocol Restricted
  clojure.lang.Fn
  ;; Unrestricted functions are not wrapped in a record, but must be able to
  ;; give an answer on a call to authorized? above.
  (authorized? [_ credentials] true)
  nil
  (authorized? [_ credentials] nil))
