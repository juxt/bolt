(ns bolt.dev.user-guide
  (:require
   [bidi.bidi :refer (tag RouteProvider alts)]
   [bidi.ring :refer (redirect)]
   [cheshire.core :as json]
   [clojure.java.io :as io]
   [clojure.tools.logging :refer :all]
   [clojure.pprint :refer (pprint *print-right-margin*)]
   [clojure.string :as str]
   [clojure.walk :refer (postwalk)]
   [clojure.xml :refer (parse)]
   [com.stuartsierra.component :refer (using Lifecycle)]
   [hiccup.core :refer (h html) :rename {h escape-html}]
   [markdown.core :refer (md-to-html-string)]
   [modular.bidi :refer (path-for)]
   [modular.template :as template :refer (render-template)]
   [modular.component.co-dependency :refer (co-using)]
   [yada.yada :refer (yada)]))

(defn emit-element
  ;; An alternative emit-element that doesn't cause newlines to be
  ;; inserted around punctuation.
  [e]
  (if (instance? String e)
    (print e)
    (do
      (print (str "<" (name (:tag e))))
      (when (:attrs e)
	(doseq [attr (:attrs e)]
	  (print (str " " (name (key attr))
                      "='"
                      (let [v (val attr)] (if (coll? v) (apply str v) v))
                      "'"))))
      (if (:content e)
	(do
	  (print ">")
          (if (instance? String (:content e))
            (print (:content e))
            (doseq [c (:content e)]
              (emit-element c)))
	  (print (str "</" (name (:tag e)) ">")))
	(print "/>")))))

(defn basename [r]
  (last (str/split (.getName (type r)) #"\.")))

(defn enclose [^String s]
  (format "<div>%s</div>" s))

(defn xml-parse [^String s]
  (parse (io/input-stream (.getBytes s))))

(defn get-source []
  (xml-parse (enclose (md-to-html-string
                       (slurp (io/resource "user-guide.md"))))))

(defn title [s]
  (letfn [(lower [x]
            (if (#{"as" "and" "of" "for"}
                 (str/lower-case x)) (str/lower-case x) x))
          (part [x]
            (if (Character/isDigit (char (first x)))
              (format "(part %s)" x)
              x
              )
            )]
    (->> (re-seq #"[A-Z1-9][a-z]*" s)
         (map lower)
         (map part)
         (str/join " "))))

(defn chapter [c]
  (str/replace (apply str c) #"\s+" ""))

(defn ->meth
  [m]
  (str/upper-case (name m)))

(defn extract-chapters [xml]
  (let [xf (comp (filter #(= (:tag %) :h2)) (mapcat :content))]
    (map str (sequence xf (xml-seq xml)))))

(defn link [r]
  (last (str/split (.getName (type r)) #"\.")))

(defn toc [xml dropno]
  {:tag :ul
   :attrs nil
   :content (vec
             (for [ch (drop dropno (extract-chapters xml))]
               {:tag :li
                :attrs nil
                :content [{:tag :a
                           :attrs {:href (str "#" (chapter ch))}
                           :content [ch]}]}))})

(defn post-process-doc [user-guide xml config]
  (postwalk
   (fn [{:keys [tag attrs content] :as el}]
     (cond
       (= tag :h2)
       ;; Add an HTML anchor to each chapter, for hrefs in
       ;; table-of-contents and elsewhere
       {:tag :div
        :attrs {:class "chapter"}
        :content [{:tag :a :attrs {:name (chapter content)} :content []} el]}

       (= tag :include)
       ;; Include some content
       {:tag :div
        :attrs {:class (:type attrs)}
        :content [{:tag :a :attrs {:name (:ref attrs)} :content []}
                  (some-> (format "includes/%s.md" (:ref attrs))
                          io/resource slurp md-to-html-string enclose xml-parse)]}

       (= tag :toc)
       (toc xml (Integer/parseInt (:drop attrs)))

       (and (= tag :p) (= (count content) 1) (= (:tag (first content)) :div))
       ;; Raise divs in paragraphs.
       (first content)

       (= tag :code)
       (update-in el [:content] (fn [x] (map (fn [y] (if (string? y) (str/trim y) y)) x)))

       :otherwise el))
   xml))

(defn post-process-body
  "Some whitespace reduction"
  [s prefix]
  (assert prefix)
  (-> s
      (str/replace #"\{\{prefix\}\}" prefix)
      (str/replace #"\{\{(.+)\}\}" #(or (System/getProperty (last %)) ""))
      (str/replace #"<p>\s*</p>" "")
      (str/replace #"(bolt)(?![-/])" "<span class='bolt'>bolt</span>")
      ))

(defn body [{:keys [*router templater] :as user-guide} doc {:keys [prefix]}]
  (render-template
   templater
   "templates/page.html.mustache"
   {:content
    (-> (with-out-str (emit-element doc))
        (post-process-body prefix)
        )
    :scripts []}))

(defrecord UserGuide [*router templater prefix ext-prefix]
  Lifecycle
  (start [component]
    (infof "Starting user-guide")
    (assert prefix)
    (let [xbody (get-source)]
      (assoc
       component
       :start-time (java.util.Date.)
       :xbody xbody)))
  (stop [component] component)

  RouteProvider
  (routes [component]
    (let [xbody (:xbody component)]
      ["/user-guide"
       [[".html"
         (->
          (yada
           (fn [ctx]
             (let [config {:prefix prefix :ext-prefix ext-prefix}]
               (body component (post-process-doc component xbody config) config)))
           :produces "text/html")
          (tag ::user-guide))]
        ]])))

(defn new-user-guide [& {:as opts}]
  (-> (->> opts
           (merge {})
           map->UserGuide)
      (using [:templater])
      (co-using [:router])))
