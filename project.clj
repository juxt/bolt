;; Copyright © 2014 JUXT LTD.

(defproject bolt "0.6.0-SNAPSHOT"
  :description "An integrated security system for applications built on component"
  :url "https://github.com/juxt/bolt"
  :license {:name "The MIT License"
            :url "http://opensource.org/licenses/MIT"}
  :dependencies [[org.clojure/tools.logging "0.3.1"]

                 [juxt.modular/bidi "0.9.2" :exclusions [bidi]]
                 [juxt.modular/ring "0.5.2"]
                 [juxt.modular/email "0.0.1"]
                 [juxt.modular/co-dependency "0.2.0"]

                 [prismatic/schema "0.4.2"]
                 [prismatic/plumbing "0.4.2"]

                 ;; Required for OAuth2/OpenID-Connect support
                 [cheshire "5.4.0"]

                 [bidi "1.18.10" :exclusions [ring/ring-core
                                              org.clojure/tools.reader]]
                 [camel-snake-kebab "0.3.1"
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
                 [yada "0.3.3"]
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

  :profiles {:dev {:dependencies [[org.clojure/clojure "1.7.0-beta2"]]}})
