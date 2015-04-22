;; Copyright © 2014 JUXT LTD.

(defproject cylon "0.6.0-SNAPSHOT"
  :description "An integrated security system for applications built on component"
  :url "https://github.com/juxt/cylon"
  :license {:name "The MIT License"
            :url "http://opensource.org/licenses/MIT"}
  :dependencies [[juxt.modular/bidi "0.9.1"]
                 [juxt.modular/ring "0.5.2"]
                 [juxt.modular/email "0.0.1"]
                 [prismatic/schema "0.3.3"]
                 [prismatic/plumbing "0.3.5"]
                 [ring/ring-core "1.2.2"]
                 [juxt.modular/co-dependency "0.2.0"]
                 [hiccup "1.0.5"]
                 [org.clojure/tools.logging "0.2.6"]

                 ;; Required for OAuth2/OpenID-Connect support
                 [cheshire "5.3.1"]
                 [juxt.modular/http-kit "0.5.3"]

                 [liberator "0.12.0"]
                 [clj-jwt "0.0.8"]
                 [camel-snake-kebab "0.1.4"]

                 [yada "0.2.3"]

                 [buddy "0.5.1"]
                 ]

  :profiles {:dev {:dependencies [[org.clojure/clojure "1.6.0"]]}})
