(ns bolt.dev.view
  (:require
   [clojure.tools.logging :refer :all]
   [modular.template :refer (render-template template-model)]
   [bolt.session :refer (session-data)]))

(defn page-body
  "Render a page body, with the given templater and a (deferred)
  template-model spanning potentially numerous records satisfying
  modular.template's TemplateModel protocol."
  [templater template model]
  (render-template
   templater
   "templates/example1/page.html.mustache"
   (merge model
          {:content
           (render-template
            templater
            template
            model)})))

(defn page [template templater *template-model *router session]
  (fn [req]
    (infof "route is %s" @*router)
    (infof "template-model is %s" @*template-model)
    (infof "session data is %s" (session-data session req))
    (infof "templater is %s" templater)
    {:status 200
     :body (page-body templater template
                      (merge
                       (template-model @*template-model req)

                       (when-let [user (some-> (session-data session req) :bolt/user)]
                         {:user user})))}))
