;; Copyright © 2014, JUXT LTD. All Rights Reserved.
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns ^{:clojure.tools.namespace.repl/unload false
      :clojure.tools.namespace.repl/load false}
  cylon.core
  (:require
   [clojure.java.io :as io]
   [clojure.pprint :refer (pprint)]
   [clojure.set :as set]
   [bidi.bidi :as bidi :refer (path-for resolve-handler unresolve-handler ->WrapMiddleware Matched)]
   [modular.ring :refer (handler RingHandlerProvider)]
   [modular.bidi :as modbidi :refer (BidiRoutesProvider routes context)]
   [schema.core :as s]
   [ring.middleware.cookies :refer (wrap-cookies cookies-request)]
   [ring.middleware.params :refer (wrap-params)]
   [hiccup.core :refer (html)]
   [com.stuartsierra.component :as component])
  (:import
   java.security.SecureRandom
   javax.crypto.SecretKeyFactory
   javax.crypto.spec.PBEKeySpec
   (javax.xml.bind DatatypeConverter)))

;; Define role qualification for authorization (used later on)

(defprotocol RoleQualifier
  (matches-role? [_ role]))

(extend-protocol RoleQualifier
  clojure.lang.Keyword
  (matches-role? [this roles]
    (roles this))

  clojure.lang.PersistentHashSet
  (matches-role? [this roles]
    (let [res (set/intersection this roles)]
      (when (not-empty res) res)))

  clojure.lang.PersistentVector
  (matches-role? [this roles]
    (when (every? #(matches-role? % roles) this)
      this))

  Boolean
  (matches-role? [this roles] this))

(defprotocol UserRoles
  (user-in-role? [_ user role]))

(extend-protocol UserRoles
  clojure.lang.PersistentArrayMap
  (user-in-role? [this user role]
    (when-let [roles (get this user)]
      (matches-role? role roles)))

  clojure.lang.PersistentHashMap
  (user-in-role? [this user role]
    (when-let [roles (get this user)]
      (matches-role? role roles)))

  clojure.lang.Fn
  (user-in-role? [this user role]
    (this user role))

  nil
  (user-in-role? [this user role]
    nil))

;; Define HTTP request authentication

(defprotocol HttpRequestAuthenticator
  ;; Return a map, potentially containing entries to be merged with the request.
  (allowed-request? [_ request]))

(extend-protocol HttpRequestAuthenticator
  Boolean
  (allowed-request? [this request]
    (when this {})))

(defprotocol UserAuthenticator
  (allowed-user? [_ user password]))

(extend-protocol UserAuthenticator
  Boolean
  (allowed-user? [this user password] this))

(def PASSWORD_HASH_ALGO "PBKDF2WithHmacSHA1")

(defn pbkdf2
  "Get a hash for the given string and optional salt. From
http://adambard.com/blog/3-wrong-ways-to-store-a-password/"
  ([password salt]
     (assert password "No password!")
     (assert salt "No salt!")
     (let [k (PBEKeySpec. (.toCharArray password) (.getBytes salt) 1000 192)
           f (SecretKeyFactory/getInstance PASSWORD_HASH_ALGO)]
       (format "%x"
               (java.math.BigInteger. (.getEncoded (.generateSecret f k)))))))

(defn make-salt
  "Make a base64 string representing a salt. Pass in a SecureRandom."
  [rng]
  (let [ba (byte-array 32)]
    (.nextBytes rng ba)
    (javax.xml.bind.DatatypeConverter/printBase64Binary ba)))

(defn create-hash [rng password]
  (let [salt (make-salt rng)
        hash (pbkdf2 password salt)]
    {:salt salt
     :hash hash}))

(defn verify-password [password {:keys [hash salt]}]
  (= (pbkdf2 password salt) hash))

;; ----------------

(defprotocol PasswordStore
  ;; Returns a map of :hash and :salt
  (get-hash-for-uid [_ uid])
  (store-user-hash! [_ uid hash]))

(defrecord PasswordFile [f]
  component/Lifecycle
  (start [this]
    (assoc this
      :ref (ref (if (.exists f) (read-string (slurp f)) {}))
      :agent (agent f)))
  (stop [this] this)
  PasswordStore
  (get-hash-for-uid [this uid] (get @(:ref this) uid))
  (store-user-hash! [this uid hash]
    (dosync
     (alter (:ref this) assoc uid hash)
     (send-off (:agent this) (fn [f]
                               (spit f (with-out-str (pprint @(:ref this))))
                               f))
     (get @(:ref this) uid))))

(defn new-password-file [f]
  (let [f (io/file f)]
    (assert (.exists (.getParentFile f))
            (format "Please create the directory structure which should contain the password file: %s" f))
    (->PasswordFile f)))

(defprotocol NewUserCreator
  (add-user! [_ uid pw]))

;; This implementation of a user domain provides a password storage
;; facility based on PASSWORD_HASH_ALGO and a pluggable store for
;; persistence

(defrecord UserDomain []
  component/Lifecycle
  (start [this] (assoc this :rng (SecureRandom.)))
  (stop [this] this)

  UserAuthenticator
  (allowed-user? [this uid pw]
    (when-let [hash (get-hash-for-uid (:password-store this) uid)]
      (verify-password pw hash)
      ;; TODO There is a slight security concern here. If no uid is
      ;; found, then the system will return slightly faster and this can
      ;; be measured by an attacker to discover usernames. I don't know
      ;; what the current advice is regarding this problem. I have
      ;; consdiered priming the user store with a 'nobody' password to
      ;; use.
      ))

  NewUserCreator
  (add-user! [this uid pw]
    (store-user-hash! (:password-store this) uid (create-hash (:rng this) pw))))

(defn new-user-domain []
  (component/using (->UserDomain) [:password-store]))

;; -------

(defprotocol FailedAuthenticationHandler
  (failed-authentication [_ request]))

;; Certain objects can provide protection for routes
(defprotocol BidiRoutesProtector
  (protect-bidi-routes [_ routes]))

(defn wrap-authentication
  "Ring middleware to pre-authenticate a request through an authenticator. If
given, the failure-handler is given the request to handle in the event
that authentication fails."
  ([h authenticator failure-handler]
     (fn [req]
       (let [auth (allowed-request? authenticator req)]
         (cond auth (h (merge req auth))
               failure-handler (failed-authentication failure-handler req)
               ;; Continue without merging auth
               :otherwise (h req)))))
  ([h authenticator]
     (wrap-authentication h authenticator nil)))

;; bidi (https://github.com/juxt/bidi) is required for the functions below

(defn make-authentication-wrapper
  "Currently bidi's WrapMiddleware only allows middleware with a single
  handler argument. This function provides an adapter."
  [authenticator failure-handler]
  (fn [h]
    (wrap-authentication h authenticator failure-handler)))

(defrecord ProtectMatched [routes opts]
  bidi/Matched
  (resolve-handler [this m]
    (let [r (resolve-handler routes m)]
      (if (:handler r)
        (update-in r [:handler]
                   (comp wrap-cookies
                         (make-authentication-wrapper
                          (:http-request-authenticator opts)
                          (:failed-authentication-handler opts))))
        r)))
  (unresolve-handler [this m]
    (unresolve-handler routes m)))

(defn add-bidi-protection-wrapper [routes & {:as opts}]
  ["" (->ProtectMatched
       [routes]
       (s/validate
        {:http-request-authenticator (s/protocol HttpRequestAuthenticator)
         (s/optional-key :failed-authentication-handler) (s/protocol FailedAuthenticationHandler)}
        opts))])

(defrecord BidiFailedAuthenticationRedirect [h]
  FailedAuthenticationHandler
  (failed-authentication [_ req]
    {:status 302
     :headers {"Location" (path-for (:modular.bidi/routes req) h)}
     :body "Not authenticated\n"
     :cookies {"requested-uri" (:uri req)}}))

(defrecord MapBackedUserRegistry [m]
  UserAuthenticator
  (allowed-user? [_ user password]
    ((set (seq m)) [user password])))

(defn new-map-backed-user-registry [m]
  (->MapBackedUserRegistry m))

;; Sessions

(defprotocol HttpSessionStore
  (start-session! [_ username]) ; return cookie map compatible with wrap-cookies
  (get-session [_ request]))

(def sessions-atom (atom {}))

(defrecord AtomBackedSessionStore [expiry-seconds]
  component/Lifecycle
  (start [this] (assoc this :sessions sessions-atom))
  (stop [this] (dissoc this :sessions))
  HttpSessionStore
  (start-session! [this username]
    (let [uuid (str (java.util.UUID/randomUUID))]
      (swap! (:sessions this)
             assoc uuid
             {:username username
              :expiry (+ (.getTime (java.util.Date.)) (* expiry-seconds 1000))})
      ;; TODO: Make this cookie name configurable
      {"session" {:value uuid
                  :max-age expiry-seconds}}))
  (get-session [this cookies]
    (when-let [{:keys [expiry] :as session} (->> (get cookies "session") :value (get @(:sessions this)))]
      (when (< (.getTime (java.util.Date.)) expiry)
        session))))

(defn new-atom-backed-session-store [expiry-seconds]
  (->AtomBackedSessionStore expiry-seconds))

;; A request authoriser that uses HTTP basic auth

(defrecord HttpBasicRequestAuthenticator [user-authenticator user-roles]
  HttpRequestAuthenticator
  (allowed-request? [_ request]
    (when-let [auth (get-in request [:headers "authorization"])]
      (when-let [basic-creds (second (re-matches #"\QBasic\E\s+(.*)" auth))]
        (let [[username password] (->> (String. (DatatypeConverter/parseBase64Binary basic-creds) "UTF-8")
                                       (re-matches #"(.*):(.*)")
                                       rest)]
          (when (allowed-user? user-authenticator username password)
            {::username username
             ::user-roles user-roles}))))))

(defn new-http-basic-request-authenticator [& {:as opts}]
  (->> opts
       (s/validate {:user-authenticator (s/protocol UserAuthenticator)
                    :user-roles (s/protocol UserRoles)})
       map->HttpBasicRequestAuthenticator))

;; A request authenticator that uses cookie-based sessions

(defrecord SessionBasedRequestAuthenticator [http-session-store user-roles]
  HttpRequestAuthenticator
  (allowed-request? [_ request]
    (when-let [session (get-session http-session-store (:cookies (cookies-request request)))]
      {:session session ; retain compatibility with Ring's wrap-session
       ::session session
       ::username (:username session)
       ::user-roles user-roles})))

(defn new-session-based-request-authenticator [& {:as opts}]
  (->> opts
       (s/validate {:http-session-store (s/protocol HttpSessionStore)
                    :user-roles (s/protocol UserRoles)})
       map->SessionBasedRequestAuthenticator))

;; A request authenticator that tries multiple authenticators in turn

(defrecord CompositeDisjunctiveRequestAuthenticator [delegates]
  HttpRequestAuthenticator
  (allowed-request? [_ request]
    (some #(allowed-request? % request) delegates)))

(defn new-composite-disjunctive-request-authenticator [& delegates]
  (->CompositeDisjunctiveRequestAuthenticator (s/validate [(s/protocol HttpRequestAuthenticator)] delegates)))

;; Since this module is dependent on bidi, let's provide some sample
;; bidi routes that can be used as-is or to demonstrate.

(defn new-login-get-handler [handlers-p post-handler-key {:keys [boilerplate] :as opts}]
  (fn [{{{requested-uri :value} "requested-uri"} :cookies
        routes :modular.bidi/routes}]
    (let [form
          [:form {:method "POST" :style "border: 1px dotted #555"
                  :action (bidi/path-for routes (get @handlers-p post-handler-key))}
           (when requested-uri
             [:input {:type "hidden" :name :requested-uri :value requested-uri}])
           [:div
            [:label {:for "username"} "Username"]
            [:input {:id "username" :name "username" :type "input"}]]
           [:div
            [:label {:for "password"} "Password"]
            [:input {:id "password" :name "password" :type "password"}]]
           [:input {:type "submit" :value "Login"}]
           ]]
      {:status 200
       :body (if boilerplate (boilerplate (html form)) (html [:body form]))})))

(defn new-login-post-handler [handlers-p get-handler-key {:keys [user-authenticator http-session-store] :as opts}]
  (s/validate {:user-authenticator (s/protocol UserAuthenticator)
               :http-session-store (s/protocol HttpSessionStore)}
              opts)
  (fn [{{username "username" password "password" requested-uri "requested-uri"} :form-params
        routes :modular.bidi/routes}]

    (if (and username
             (not-empty username)
             (allowed-user? user-authenticator (.trim username) password))

      {:status 302
       :headers {"Location" requested-uri}
       :cookies (start-session! http-session-store username)}

      ;; Return back to login form
      {:status 302
       :headers {"Location" (path-for routes (get @handlers-p get-handler-key))}})))

(defn- make-login-handlers [opts]
  (let [p (promise)]
    @(deliver p {:get-handler (new-login-get-handler p :post-handler (select-keys opts [:boilerplate]))
                 :post-handler (wrap-params (new-login-post-handler p :get-handler (select-keys opts [:user-authenticator :http-session-store])))})))

(defrecord LoginForm [path context boilerplate]
  component/Lifecycle
  (start [this]
    (let [handlers (make-login-handlers (select-keys this [:user-authenticator :http-session-store :boilerplate]))]
      (assoc this
        :handlers handlers
        :routes [path (->WrapMiddleware
                       {:get (:get-handler handlers)
                        :post (:post-handler handlers)}
                       wrap-cookies)])))
  (stop [this] this)

  BidiRoutesProvider
  (routes [this] (:routes this))
  (context [this] context))

(def new-login-form-schema
  {(s/optional-key :path) s/Str
   (s/optional-key :context) s/Str
   (s/optional-key :boilerplate) (s/=> 1)})

(defn new-login-form [& {:as opts}]
  (let [{:keys [path context boilerplate]}
        (->> opts
             (merge {:context ""
                     :path "/login"
                     :boilerplate #(html [:body %])})
             (s/validate new-login-form-schema))]
    (component/using (->LoginForm path context boilerplate) [:user-authenticator :http-session-store])))

;; Now we can build a protection system, composed of a login form, user
;; authenticator and session store. Different constructors can build this
;; component in different ways.

(defrecord ProtectionSystem [login-form user-authenticator http-session-store user-roles]
  component/Lifecycle
  (start [this] (component/start-system this (keys this)))
  (stop [this] (component/stop-system this (keys this)))
  ;; In this implementation, we export any routes provided by
  ;; sub-components. These are the routes that provide login forms and
  ;; so on, nothing to do with the routes that are protected by this
  ;; protection system.
  BidiRoutesProvider
  (routes [this] ["" (vec (keep #(when (satisfies? BidiRoutesProvider %) (routes %)) (vals this)))])
  (context [this] (or
                   (first (keep #(when (satisfies? BidiRoutesProvider %) (context %))
                                ((juxt :login-form :user-authenticator :http-session-store) this)))
                   ""))

  BidiRoutesProtector
  (protect-bidi-routes [this routes]
    (add-bidi-protection-wrapper
     routes
     :http-request-authenticator (new-session-based-request-authenticator :http-session-store (:http-session-store this) :user-roles user-roles)
     :failed-authentication-handler (->BidiFailedAuthenticationRedirect (get-in (:login-form this) [:handlers :get-handler]))))

  NewUserCreator
  (add-user! [_ uid pw]
    (if (satisfies? NewUserCreator user-authenticator)
      (add-user! user-authenticator uid pw)
      (throw (ex-info "This protection system implementation does not support the creation of new users" {})))))

(def new-default-protection-system-schema
  {:password-file s/Any
   (s/optional-key :session-timeout-in-seconds) s/Int
   (s/optional-key :boilerplate) (s/=> 1)
   (s/optional-key :user-roles) (s/protocol UserRoles)
   })

(defn new-default-protection-system [& {:as opts}]
  (s/validate new-default-protection-system-schema opts)
  (map->ProtectionSystem
   {:login-form (if-let [boilerplate (:boilerplate opts)]
                  (new-login-form :boilerplate boilerplate)
                  (new-login-form))
    :user-authenticator (component/using (new-user-domain) [:password-store])

    :password-store (new-password-file (:password-file opts))
    :http-session-store (new-atom-backed-session-store
                         (or (:session-timeout-in-seconds opts)
                             (* 60 60)  ; one hour by default
                             ))
    :user-roles (or (:user-roles opts) {})}))

;; Now that we have a protection system, we want the ability to create
;; bidi routes components that can be protected by simply declaring a dependency upon the protection system component.

(defrecord ProtectedBidiRoutes [routes context]
  component/Lifecycle
  (start [this]
    (let [protection (get-in this [:protection-system])
          routes (cond-> routes
                         (fn? routes) (apply [this])
                         protection ((partial protect-bidi-routes protection)))]
      (assoc this :routes routes)))
  (stop [this] this)

  BidiRoutesProvider
  (routes [this] (:routes this))
  (context [this] context))

(defn new-optionally-protected-bidi-routes
  "Create a set of protected routes. Routes can a bidi route structure, or
  a function that takes the component and returns a bidi route
  structure."
  [routes & {:as opts}]
  (let [{:keys [context]}
        (->> (merge {:context ""} opts)
             (s/validate {:context s/Str}))]
    (->ProtectedBidiRoutes routes context)))

(defn new-protected-bidi-routes
  "Like new-optionally-protected-bidi-routes above, but the absence of
  a :protection-system dependency will cause an error."
  [routes & {:as opts}]
  (component/using
   (apply new-optionally-protected-bidi-routes routes (apply concat (seq opts)))
   [:protection-system]))

;; Authorization

;; This record wraps an existing RingHandlerProvider and sets
;; authentication entries in the incoming request, according to its
;; protection system dependency.
(defrecord AuthBinder []
  RingHandlerProvider
  (handler [this]
    (-> (:ring-handler-provider this)
        handler
        ;; TODO Just use the one authenticator if possible
        (wrap-authentication (new-session-based-request-authenticator
                              :http-session-store
                              (-> this :protection-system :http-session-store)
                              :user-roles
                              (-> this :protection-system :user-roles))))))

(defn new-auth-binder
  "Constructor for a ring handler provider that amalgamates all bidi
  routes provided by components in the system."
  []
  (component/using (->AuthBinder) [:protection-system :ring-handler-provider]))

;; Bidi handlers can be subject to access restrictions. We restrict at
;; the level of the handler rather than the route, because it's the
;; handler that determines what kind of data is being returned. It is
;; data itself that is sensitive to access, not the URIs.

(defprotocol HandlerAuthorizer
  (allowed-handler? [_ req]))

;; Ring middleware
(defn restrict-to-authorized [h handler-authorizer]
  (fn [req]
    (if (allowed-handler? handler-authorizer req)
      (h req)
      (throw (ex-info "Unauthorized" (merge
                                      (select-keys req [::username ::user-roles])
                                      {:handler-authorizer handler-authorizer}))))))

;; This is intended to wrap an individual Ring handler. By using a
;; record, rather than a function, we can satisfy the HandlerAuthorizer
;; protocol which can indicate whether this handler would be authorized
;; given the current request without asking it to handle the request.
(defrecord RestrictedHandler [matched authorized?]
  Matched
  (resolve-handler [this m]
    (let [handler (resolve-handler matched m)]
      (update-in handler [:handler] restrict-to-authorized this)))
  (unresolve-handler [this m]
    ;; Behave as if we weren't wrapped. We need to handle both the case
    ;; where the handler in the map is a RestrictedHandler, and where it
    ;; isn't.
    (if (instance? RestrictedHandler (:handler m))
      (unresolve-handler matched (update-in m [:handler] :matched))
      (unresolve-handler matched m)))

  HandlerAuthorizer
  (allowed-handler? [this req]
    (cond (satisfies? RoleQualifier authorized?)
          (user-in-role? (::user-roles req) (::username req) authorized?)
          (fn? authorized?)
          (authorized? req)
          :otherwise (throw (ex-info ("Unsupported type of authorizer: %s" (type authorized?)) {:authorized? authorized?})))))

(extend-protocol HandlerAuthorizer
  ;; 'Normal' handlers are not wrapped in a record, but must be able to
  ;; give an answer if given as an argument to allowed-handler? above.
  clojure.lang.Fn
  (allowed-handler? [this req] true))

(defn restrict-handler
  "Restrict the given route. If authorized? is a predicate function, it
  must take a single argument (the Ring request). Otherwise, if
  authorized? is a keyword, then it represents a role that much match
  the user. If it is a set of roles, then the user must match one of
  those roles. If it is a vector of roles, the user must match all."
  [matched authorized?]
  (->RestrictedHandler matched authorized?)
  )
