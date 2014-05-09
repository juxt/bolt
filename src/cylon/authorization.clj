(ns cylon.authorization)

;; Now we can define authorization for Ring handlers. In Cylon, it is
;; handlers that are restricted, rather than routes. Handlers are
;; 'closer' to the data, since they serve it, and it is better to
;; consider authorization at the level of the data, rather than define
;; authorizations in the routing logic. The design goal is for Cylon to
;; be completely agnostic to the means by which handlers are accessed,
;; whether via a particular routing library (Compojure, bidi, etc.) or
;; via some other mechanism.

(defprotocol UserAuthorizer
  (authorize-user [_])
  (restrict-handler [_ roles]))
