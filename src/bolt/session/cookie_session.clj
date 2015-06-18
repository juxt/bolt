;; TODO: This is misnamed. The cookie only contains a UUID, which keys
;; into a token store containing the material.

(ns bolt.session.cookie-session
  (:require
   [clojure.tools.logging :refer :all]
   [com.stuartsierra.component :refer (using)]
   [bolt.session :refer (session)]
   [bolt.session.protocols :refer (SessionLifecycle SessionData SessionStore)]

   [bolt.authentication.protocols :refer (RequestAuthenticator)]
   [bolt.token-store :refer (get-token-by-id merge-token! create-token! purge-token!)]
   [ring.middleware.cookies :refer (cookies-request cookies-response)]
   [schema.core :as s]
   [plumbing.core :refer (<-)]))

(defn ->cookie [session]
  {:value (:bolt/token-id session)
   :expires (.toGMTString
             (doto (new java.util.Date)
               (.setTime (.getTime (:bolt/expiry session)))))
   :path "/"})

;(doto (new java.util.Date) (.setTime  (.getTime (:c {:c (new java.util.Date)}))))
(def delete-cookie
  {:value ""
   :expires (.toGMTString (java.util.Date. 70 0 1))
   :path "/"})

(defn cookies-response-with-session [response id-cookie session]
  ;; Use of cookies-response mean it is non-destructive - existing
  ;; cookies are preserved (but existing :cookies entries are not)
  (cookies-response
   (merge-with merge response
    {:cookies {id-cookie (->cookie session)}})))

;; This record satisfies SessionLifecycle and SessionData, indexed by a specific
;; cookie-id. This design allows us to encapsulate the cookie-id, rather
;; than have to pass it through numerous function calls.
(defrecord CookieSession [cookie-id token-store]
  SessionLifecycle
  (start-session! [_ response data]
    ;; TODO Create a HMAC'd identifier, not just a random UUID that
    ;; could be predicted and therefore allow session forgery.

    (let [id (str (java.util.UUID/randomUUID))
          token (create-token! token-store id data)]
      (debugf "Creating new session (%s) cookie %s tied to token %s" (:token-type token-store) id token)
      (cookies-response-with-session response cookie-id token)))

  (stop-session! [component response data]
    (when-let [tokid (::id data)]
      (purge-token! token-store tokid))
    (cookies-response
       (merge-with merge response
                   {:cookies {cookie-id delete-cookie}})))

  SessionData
  (session-data [component request]
    (when-let [tokid (-> request cookies-request :cookies (get cookie-id) :value)]
      (-> (get-token-by-id token-store tokid)
          (assoc ::id tokid))))

  SessionStore
  (session [component request]
    (throw (ex-info "Deprecated: old SessionStore protocol" {}))
    ;; In case the underlying token store accepts nils, we should avoid
    ;; retrieving a nil-indexed token, so we wrap in a 'when-let'.
    (when-let [tokid (-> request cookies-request :cookies (get cookie-id) :value)]
      (get-token-by-id token-store tokid)))

  (assoc-session-data! [component request m]
    (throw (ex-info "Deprecated: old SessionStore protocol" {}))
    (when-let [tokid (-> request cookies-request :cookies (get cookie-id) :value)]
      (merge-token! token-store tokid m)))

  (respond-with-new-session! [component request data response]
    (throw (ex-info "Deprecated: old SessionStore protocol" {}))
    ;; TODO Create a HMAC'd identifier, not just a random UUID that
    ;; could be predicted and therefore allow session forgery.

    (let [id (str (java.util.UUID/randomUUID))
          token (create-token! token-store id data)]
      (debugf "Creating new session (%s) cookie %s tied to token %s" (:token-type token-store) id token)
      (cookies-response-with-session response cookie-id token)))

  (respond-close-session! [component request response]
    (throw (ex-info "Deprecated: old SessionStore protocol" {}))
    (when-let [tokid (-> request cookies-request :cookies (get cookie-id) :value)]
      (purge-token! token-store tokid))
    (cookies-response
       (merge-with merge response
                   {:cookies {cookie-id delete-cookie}})))

  RequestAuthenticator
  (authenticate [component req]
    (session component req)))

(def new-cookie-session-schema {:cookie-id s/Str})

;; This is only a 'cookie' session store by virtue of the fact that it
;; stores the session key in the cookie. The rest of the details go into
;; the token-store. This is misleading. (TODO: rename this component)
(defn new-cookie-session [& {:as opts}]
  (->> opts
       (merge {:cookie-id "session-id"})
       (s/validate new-cookie-session-schema)
       map->CookieSession
       (<- (using [:token-store]))))
