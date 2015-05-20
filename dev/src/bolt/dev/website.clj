(ns bolt.dev.website
  (:require
   [schema.core :as s]
   [bidi.bidi :refer (RouteProvider tag)]
   [modular.bidi :refer (path-for)]
   [clojure.java.io :as io]
   [hiccup.core :refer (html)]
   [com.stuartsierra.component :refer (using)]
   [modular.template :as template :refer (render-template)]
   [modular.component.co-dependency :refer (co-using)]
   [yada.yada :refer (yada)]))

(defn index [{:keys [*router templater]}]
  (yada
   :body
   {"text/html"
    (fn [ctx]
      (render-template
       templater
       "templates/page.html.mustache"
       {:content
        (html
         [:div.container
          [:h2 "Welcome to " [:span.bolt "bolt"] "!"]
          [:ol
           [:li [:a {:href (path-for @*router :bolt.dev.user-guide/user-guide)}
                 "User guide"]]]])}))}))

(defrecord Website [*router templater]
  RouteProvider
  (routes [component]
    ["/index.html" (-> (index component)
                       (tag ::index))]))

(defn new-website [& {:as opts}]
  (-> (->> opts
           (merge {})
           (s/validate {})
           map->Website)
      (using [:templater])
      (co-using [:router])))
