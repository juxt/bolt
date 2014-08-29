(ns cylon.oauth.encoding
  (:require
   [ring.util.codec :refer (url-encode url-decode)]
   [clojure.string :as str]))

(defn encode-scope [scope]
  (->>
   scope
   (map #(apply str (interpose ":" (remove nil? ((juxt namespace name) %)))))
   (interpose " ")
   (apply str)
   url-encode))

(defn decode-scope [s]
  (->> (str/split (url-decode (or s "")) #"\s")
       (remove empty?)
       (map (fn [x] (apply keyword (str/split x #":"))))
       set))

(defn as-query-string [m]
  (->>
   (map (comp (partial apply str)
              (partial interpose "="))
        m)
   (interpose "&")
   (cons "?")
   (apply str)))
