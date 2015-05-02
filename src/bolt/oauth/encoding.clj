(ns cylon.oauth.encoding
  (:require
   [ring.util.codec :refer (url-encode url-decode)]
   [clojure.string :as str]
   [plumbing.core :refer (?>>)]))

(defn encode-scope [scopes]
  (->>
   scopes
   (?>> (keyword? (first scopes)) (map #(apply str (interpose ":" (remove nil? ((juxt namespace name) %))))))
   (interpose " ")
   (apply str)
   url-encode))

(defn decode-scope [s should-be-keyword?]
  (->> (str/split (url-decode (or s "")) #"\s")
       (remove empty?)
       (?>> should-be-keyword? (map (fn [x] (apply keyword (str/split x #":")))))
       set))
