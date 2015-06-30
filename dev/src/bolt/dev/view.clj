(ns bolt.dev.view
  (:require
   [clojure.tools.logging :refer :all]
   [modular.template :refer [render-template]]
   [bolt.session :refer [session-data]]
   [yada.yada :refer [yada]]
   ))

(defn page-body
  "Render a page body"
  [templater template model]
  (render-template
   templater
   "templates/example1/page.html.mustache"
   (merge model {:content (render-template templater template model)})))

(defn page [template templater model *router session]
  (yada (fn [{:keys [request]}]
          (page-body templater template
                     (merge
                      model
                      (when-let [user (some-> (session-data session request) :bolt/user)]
                        {:user user}))))
        :produces "text/html"))
