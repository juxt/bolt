;; Copyright © 2014 JUXT LTD.

(defproject cylon/bootstrap-login-form "0.1.0-SNAPSHOT"
  :description "A bootstrap flavored login form"
  :url "https://github.com/juxt/cylon/tree/master/contrib/bootstrap-login-form"
  :license {:name "The MIT License"
            :url "http://opensource.org/licenses/MIT"}
  :dependencies [[cylon "0.2.0"]
                 [garden "1.1.5" :exclusions [org.clojure/clojure]]
                 [prismatic/schema "0.2.1"]
                 [hiccup "1.0.5"]
                 [org.clojure/tools.logging "0.2.6"]]
  :profiles {:dev {:dependencies [[org.clojure/clojure "1.6.0"]]}})
