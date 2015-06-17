;; Copyright © 2014 JUXT LTD.

(defproject bolt "0.6.0-SNAPSHOT"
  :description "An integrated security system for applications built on component"
  :url "https://github.com/juxt/bolt"
  :license {:name "The MIT License"
            :url "http://opensource.org/licenses/MIT"}
  :dependencies
  [[org.clojure/tools.logging "0.3.1"]

   [juxt.modular/bidi "0.9.2" :exclusions [bidi]]
   [juxt.modular/ring "0.5.3"]
   [juxt.modular/email "0.0.1"]
   [juxt.modular/co-dependency "0.2.0"]

   [prismatic/schema "0.4.2"]
   [prismatic/plumbing "0.4.2"]

   ;; Required for OAuth2/OpenID-Connect support
   [cheshire "5.4.0"]

   ;; Doesn't work with clojure 1.7.0-beta2
   #_[camel-snake-kebab "0.3.1"
    :exclusions [com.keminglabs/cljx]]

   ;; We should probably replace clj-jwt with buddy
   [clj-jwt "0.0.8"
    ;; Important we exclude bc here otherwise get an
    ;; this exception:
    ;;
    ;; class
    ;; "org.bouncycastle.crypto.digests.SHA3Digest"'s
    ;; signer information does not match signer
    ;; information of other classes in the same package
    :exclusions [clj-time
                 org.bouncycastle/bcprov-jdk15]]

   [buddy "0.5.1"]
   [yada "0.5.0-SNAPSHOT"]
   [clj-time "0.9.0"]

   ;; Possibly needed old dependencies
   #_[ring/ring-core "1.3.2"
      :exclusions [org.clojure/tools.reader
                   clj-time]]
   #_[org.clojure/tools.reader "0.8.13"]
   #_[clj-time "0.9.0"]
   #_[juxt.modular/http-kit "0.5.3"]
   #_[hiccup "1.0.5"]
   #_[liberator "0.12.0"]]

  :repl-options {:init-ns user
                 :welcome (println "Type (dev) to start")}

  :profiles
  {:dev {:main bolt.dev.main
         :dependencies
         [[org.clojure/clojure "1.7.0-beta2"]

          [ch.qos.logback/logback-classic "1.0.7"
           :exclusions [org.slf4j/slf4j-api]]
          [org.slf4j/jul-to-slf4j "1.7.2"]
          [org.slf4j/jcl-over-slf4j "1.7.2"]
          [org.slf4j/log4j-over-slf4j "1.7.2"]

          [com.stuartsierra/component "0.2.3"]
          [org.clojure/tools.namespace "0.2.5"]
          [org.clojure/tools.reader "0.9.2"]

          [markdown-clj "0.9.62"]

          [juxt.modular/aleph "0.0.8" :exclusions [manifold]]
          [juxt.modular/bidi "0.9.3" :exclusions [bidi]]
          [juxt.modular/clostache "0.6.3"]
          [juxt.modular/co-dependency "0.2.0"]
          [juxt.modular/maker "0.5.0"]
          [juxt.modular/test "0.1.0"]
          [juxt.modular/template "0.6.3"]

          [org.webjars/jquery "2.1.3"]
          [org.webjars/bootstrap "3.3.2"]
          ]
          :source-paths ["dev/src"]
          :resource-paths ["dev/resources"]}})
