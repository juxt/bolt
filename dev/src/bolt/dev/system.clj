;; Copyright © 2015, JUXT LTD.

(ns bolt.dev.system
  "Components and their dependency relationships"
  (:refer-clojure :exclude (read))
  (:require
   [clojure.java.io :as io]
   [clojure.tools.reader :refer (read)]
   [clojure.string :as str]
   [clojure.tools.reader.reader-types :refer (indexing-push-back-reader)]
   [com.stuartsierra.component :refer (system-map system-using using)]

   [bolt.dev.website :refer (new-website)]
   [bolt.dev.user-guide :refer (new-user-guide)]
   [bolt.dev.database :refer (new-database)]
   [bolt.dev.example1 :refer (new-example)]
   [bolt.dev.login-form :refer (new-login-form)]

   [bolt.session.cookie-session-store :refer (new-cookie-session-store)]
   [bolt.token-store.atom-backed-store :refer (new-atom-backed-token-store)]
   [bolt.user.login :refer (new-login)]
   [bolt.user.email-user-store :refer (new-email-user-store)]
   [bolt.user.buddy-user-authenticator :refer (new-buddy-user-authenticator)]
   [bolt.storage.atom-storage :refer (new-atom-storage)]

   [modular.maker :refer (make)]
   [modular.bidi :refer (new-router new-web-resources new-archived-web-resources new-redirect)]
   [modular.clostache :refer (new-clostache-templater)]
   [modular.template :refer (new-aggregate-template-model)]
   [modular.aleph :refer (new-webserver)]
   [modular.component.co-dependency :refer (co-using system-co-using)]))

(defn ^:private read-file
  [f]
  (read
   ;; This indexing-push-back-reader gives better information if the
   ;; file is misconfigured.
   (indexing-push-back-reader
    (java.io.PushbackReader. (io/reader f)))))

(defn ^:private config-from
  [f]
  (if (.exists f)
    (read-file f)
    {}))

(defn ^:private user-config
  []
  (config-from (io/file (System/getProperty "user.home") ".bolt.edn")))

(defn ^:private config-from-classpath
  []
  (if-let [res (io/resource "bolt.edn")]
    (config-from (io/file res))
    {}))

(defn config
  "Return a map of the static configuration used in the component
  constructors."
  []
  (merge (config-from-classpath)
         (user-config)))

(defn database-components [system config]
  (assoc system
    :database
    (->
      (make new-database config)
      (using []))))

(defn website-components [system config]
  (assoc
   system
   :clostache-templater (make new-clostache-templater config)
   :user-guide (make new-user-guide config
                     :prefix "http://localhost:8084")
   :website (make new-website config)
   :jquery (make new-web-resources config
                 :key :jquery
                 :uri-context "/jquery"
                 :resource-prefix "META-INF/resources/webjars/jquery/2.1.3")
   :bootstrap (make new-web-resources config
                    :key :bootstrap
                    :uri-context "/bootstrap"
                    :resource-prefix "META-INF/resources/webjars/bootstrap/3.3.2")
   :web-resources (make new-web-resources config
                        :uri-context "/static"
                        :resource-prefix "public")
   :highlight-js-resources
    (make new-archived-web-resources config :archive (io/resource "highlight.zip") :uri-context "/hljs/")
   ))

(defn router-components [system config]
  (assoc system
    :router
    (make new-router config)))

(defn http-server-components [system config]
  (assoc system
    :http-server
    (make new-webserver config
          :port 8084)))

(defn example1a-components [system config]
  (let [tag-ns "example1a"
        uri-context (str "/" tag-ns)]
    (assoc
     system
     :example1a (bolt.dev.example1/new-example
                 :title "Example 1a"
                 :tag-ns tag-ns
                 :uri-context uri-context)
     :example1a/session-store (new-cookie-session-store)
     :example1a/token-store (new-atom-backed-token-store)
     :example1a/login (new-login :uri-context uri-context :tag-ns tag-ns)
     :example1a/email-user-store (new-email-user-store)
     :example1a/buddy-user-authenticator (new-buddy-user-authenticator)
     :example1a/atom-storage (new-atom-storage)
     :example1a/login-form (new-login-form)
     :example1a/template-model (new-aggregate-template-model))))

(defn example1b-components [system config]
  (let [tag-ns "example1b"
        uri-context (str "/" tag-ns)]
    (assoc
     system
     :example1b (bolt.dev.example1/new-example
                 :title "Example 1b"
                 :tag-ns tag-ns
                 :uri-context uri-context)
     :example1b/session-store (new-cookie-session-store)
     :example1b/token-store (new-atom-backed-token-store)
     :example1b/login (new-login :uri-context uri-context :tag-ns tag-ns)
     :example1b/email-user-store (new-email-user-store)
     :example1b/buddy-user-authenticator (new-buddy-user-authenticator)
     :example1b/atom-storage (new-atom-storage)
     :example1b/login-form (new-login-form)
     :example1b/template-model (new-aggregate-template-model))))

(defn new-system-map
  [config]
  (apply system-map
    (apply concat
      (-> {}
        (database-components config)
        (website-components config)
        (router-components config)
        (http-server-components config)
        (example1a-components config)
        (example1b-components config)
        (assoc :redirect (new-redirect :from "/" :to :bolt.dev.website/index))
        ))))

(def example1a-dependencies
  {:dependencies
   {:example1a {:templater :clostache-templater
               :session-store :example1a/session-store
               :user-store :example1a/email-user-store
               :password-hasher :example1a/buddy-user-authenticator}
    :example1a/template-model [:example1a]

    ;; These are the components to support security (login, etc.)
    :example1a/session-store {:token-store :example1a/token-store}

    :example1a/login {:user-store :example1a/email-user-store
                     :user-authenticator :example1a/buddy-user-authenticator
                     :session-store :example1a/session-store
                     :renderer :example1a/login-form}

    :example1a/login-form {:templater :clostache-templater}

    :example1a/email-user-store {:storage :example1a/atom-storage}}

   :co-dependencies
   {:example1a {:router :router
                :template-model :example1a/template-model}
    :example1a/login-form {:template-model :example1a/template-model
                           :router :router}}})

(def example1b-dependencies
  {:dependencies
   {:example1b {:templater :clostache-templater
               :session-store :example1b/session-store
               :user-store :example1b/email-user-store
               :password-hasher :example1b/buddy-user-authenticator}
    :example1b/template-model [:example1b]

    ;; These are the components to support security (login, etc.)
    :example1b/session-store {:token-store :example1b/token-store}

    :example1b/login {:user-store :example1b/email-user-store
                     :user-authenticator :example1b/buddy-user-authenticator
                     :session-store :example1b/session-store
                     :renderer :example1b/login-form}

    :example1b/login-form {:templater :clostache-templater}

    :example1b/email-user-store {:storage :example1b/atom-storage}}

   :co-dependencies
   {:example1b {:router :router
                :template-model :example1b/template-model}
    :example1b/login-form {:template-model :example1b/template-model
                           :router :router}}})

(defn new-dependency-map
  []
  (merge
   {:http-server {:request-handler :router}
    :router [:user-guide
             :website
             :jquery :bootstrap
             :web-resources
             :highlight-js-resources
             :redirect
             :example1a
             :example1a/login
             :example1b
             :example1b/login]
    :user-guide {:templater :clostache-templater}
    :website {:templater :clostache-templater}}

   (:dependencies example1a-dependencies)
   (:dependencies example1b-dependencies)))

(defn new-co-dependency-map
  []
  (merge
   {:website {:router :router}
    :user-guide {:router :router}}
   (:co-dependencies example1a-dependencies)
   (:co-dependencies example1b-dependencies)))

(defn new-production-system
  "Create the production system"
  []
  (-> (new-system-map (config))
      (system-using (new-dependency-map))
      (system-co-using (new-co-dependency-map))))
