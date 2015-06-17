;; Copyright © 2015, JUXT LTD.

(ns bolt.schema
  (:require
   schema.utils schema.macros
   [schema.core :as s]))

(defrecord Co-dependency [schema]
  s/Schema
  (s/walker [this]
    (let [sub-walker (s/subschema-walker schema)]
      (fn [x]
        (if x
          (let [res (sub-walker @x)]
            (when (schema.utils/error? res) res))
          (schema.macros/validation-error this x (list 'injected? schema (schema.utils/value-name x)))))))

  (s/explain [this] this))

(defn co-dep [schema]
  (->Co-dependency schema))
