(ns cylon.event)

;; A event abstraction

;; Messages are simply maps.

;; In the future this idea may be promoted into juxt.modular/event

;; Cylon components may be made dependent on EventSource implementations
;; but be agnostic to the underlying event architecture (single event
;; bus, multiple individual event channels).

;; Right now it is independent of core.async, although that is a natural
;; implementation.

(defprotocol EventPublisher
  (raise-event! [_ ev]))

(defrecord ChannelEventPublisher [ch]
  ;; We comment this to save having to depend on core.async right now
  EventPublisher
  (raise-event! [_ ev] #_(>! ch ev)))

(extend-protocol EventPublisher
  nil
  (raise-event! [_ ev] nil))

(def etype ::type)
