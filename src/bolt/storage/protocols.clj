(ns bolt.storage.protocols
  (:refer-clojure :exclude [get-in assoc-in update-in]))

(defprotocol TreeStore
  "Trees are convenient storage containers. Ideally we'd have an
  implementation of a tree-diff like React (see Leonardo Borges'
  EuroClojure 2015 talk). But for now, let's update through the protocol
  so backing implementations get hints as to which part of the tree is
  being updated. Particular implementations (such as for relational
  databases) may map onto particular paths in the tree and infer meaning
  from established names. Otherwise the tree is just a tree.

  This design lends itself well to graph-like queries from local and
  remote clients.

  A reference implementation that stores the tree across multiple edn
  files, and can version each individual file. Upfront partition schemes
  could be used to optimise disk usage.

  We use the same signatures as clojure.core library equivalents. The
  advantage is that it's a familiar API to Clojure developers."
  (get-in [_ ks])
  (assoc-in [_ ks v])
  (update-in [_ ks f args])
  )

(extend-protocol TreeStore
  clojure.lang.Atom
  (get-in [a ks] (clojure.core/get-in @a ks))
  (assoc-in [a ks v] (swap! a clojure.core/assoc-in ks v))
  (update-in [a ks f args]
    (swap! a clojure.core/update-in ks (fn [v] (apply f v args)))))
;; Deprecated

(defprotocol Storage
  ""
  (find-objects [_ qualifier] "Find objects matching the qualifier")
  (store-object! [_ object] "Store object (or objects, if sequence) in store")
  (delete-object! [_ qualifier] "Delete objects matching the qualifier"))

(defprotocol StorageWithExpiry)
