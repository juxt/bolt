;; Copyright © 2014 JUXT LTD.

(ns cylon.impl.request
  (:require
   [cylon.request :refer (HttpRequestAuthenticator authenticate-request)]
   [schema.core :as s])
  )

;; A request authenticator that tries multiple authenticators in turn

(defrecord CompositeDisjunctiveRequestAuthenticator [delegates]
  HttpRequestAuthenticator
  (authenticate-request [_ request]
    (some #(authenticate-request % request) delegates)))

(defn new-composite-disjunctive-request-authenticator [& delegates]
  (->CompositeDisjunctiveRequestAuthenticator (s/validate [(s/protocol HttpRequestAuthenticator)] delegates)))
