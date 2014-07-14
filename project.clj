;; Copyright © 2014 JUXT LTD.

(defproject cylon "0.4.0"
  :description "An integrated security system for applications built on component"
  :url "https://github.com/juxt/cylon"
  :license {:name "The MIT License"
            :url "http://opensource.org/licenses/MIT"}
  :dependencies [[juxt.modular/bidi "0.5.0"]
                 [juxt.modular/ring "0.5.0"]
                 [prismatic/schema "0.2.1"]
                 [ring/ring-core "1.2.2"]

                 [hiccup "1.0.5"]
                 [org.clojure/tools.logging "0.2.6"]

                 ;; Required for OAuth2 support
                 [cheshire "5.3.1"]
                 [juxt.modular/http-kit "0.5.1"]
                 [liberator "0.11.0"]
                 ]

  :profiles {:dev {:dependencies [[org.clojure/clojure "1.6.0"]]}})
