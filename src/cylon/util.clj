;; For internal Cylon use only. Not part of a published API. Do not use.
(ns cylon.util
  (:require
   [schema.core :as s])
  (:import (java.net URLEncoder)))

(defprotocol KorksSet
  (as-set [_]))

(extend-protocol KorksSet
  clojure.lang.Keyword
  (as-set [k] #{k})
  clojure.lang.PersistentHashSet
  (as-set [ks] ks)
  clojure.lang.PersistentVector
  (as-set [v] (set v))
  clojure.lang.PersistentList
  (as-set [l] (set l)))

(defn uri-with-qs [req]
  (str (:uri req)
       (when-let [qs (:query-string req)] (when (not-empty qs) (str "?" qs )))))

(defn absolute-prefix [req]
  (apply format "%s://%s:%s"
         ((juxt (comp name :scheme) :server-name :server-port)
          req)))

(defn absolute-uri [req]
  (str (absolute-prefix req) (uri-with-qs req)))

(defn as-www-form-urlencoded [m]
  (->>
   (map (fn [[k v]] (format "%s=%s" k (URLEncoder/encode v))) m)
   (interpose "&")
   (apply str)))

(defn as-query-string [m]
  (->>
   (map (comp (partial apply str)
              (partial interpose "="))
        m)
   (interpose "&")
   (cons "?")
   (apply str)))

;; Schema

(s/defschema Request "A Ring-style request"
  {:headers s/Any
   s/Keyword s/Any})

(s/defschema Response "A Ring-style response"
  {(s/optional-key :status) s/Num
   (s/optional-key :headers) s/Any
   (s/optional-key :body) s/Str})

;; Schema validation

(defn wrap-schema-validation [h]
  (fn [req]
    (s/with-fn-validation
      (h req))))
