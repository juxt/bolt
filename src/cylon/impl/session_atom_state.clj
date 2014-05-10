;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns ^{:clojure.tools.namespace.repl/unload false
      :clojure.tools.namespace.repl/load false}
  cylon.impl.session-atom-state
  )

;; This survives across resets because of the metadata on this namespace.
(def sessions-atom (atom {}))
