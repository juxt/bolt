;; Copyright © 2014 JUXT LTD.

;; Cylon integration with the modular.ring module.

(ns cylon.impl.webrequest
  (:require
   [com.stuartsierra.component :as component]
   [modular.ring :refer (WebRequestMiddleware)]
   [ring.middleware.cookies :refer (cookies-request)]
   [cylon.authentication :refer (authenticate)]
   [schema.core :as s]
   cylon.impl.session
   cylon.impl.authentication)
  (:import
   (cylon.impl.session CookieAuthenticator)
   (cylon.impl.authentication StaticAuthenticator
                              HttpBasicAuthenticator
                              CompositeDisjunctiveAuthenticator)))

(defrecord AuthenticatorRequestMiddleware []
  WebRequestMiddleware
  (request-middleware [this]
    (fn [h]
      (fn [req]
        (if-let [facts (authenticate (:authenticator this) req)]
          (h (merge req facts))
          (h req))))))

(defn new-authenticator-request-middleware [& {:as opts}]
  (component/using
   (->> opts
        (merge {})
        (s/validate {})
        map->AuthenticatorRequestMiddleware)
   [:authenticator]))

;; For convenience, type extensions are provided for the
;; Authenticator implementations in Cylon. By requiring this namespace,
;; it is possible to use Authenticator records anywhere
;; modular.ring/WebRequestMiddleware is expected.

;; Note, we don't extend cylon.impl.session/CookieAuthenticator
;; because that already has an implementation for WebRequestMiddleware (for renewing cookies)

(doseq [t [StaticAuthenticator
           HttpBasicAuthenticator
           CompositeDisjunctiveAuthenticator]]
  (extend t WebRequestMiddleware
          {:request-middleware
           (fn [this]
             (fn [h]
               (fn [req]
                 (if-let [facts (authenticate this req)]
                   (h (merge req facts))
                   (h req)))))}))
