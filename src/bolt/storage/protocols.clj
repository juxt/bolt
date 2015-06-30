(ns bolt.storage.protocols)

(defprotocol Storage
  ""
  (find-objects [_ qualifier] "Find objects matching the qualifier")
  (store-object! [_ object] "Store object (or objects, if sequence) in store")
  (delete-object! [_ qualifier] "Delete objects matching the qualifier"))

(defprotocol StorageWithExpiry)
