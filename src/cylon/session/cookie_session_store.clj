(ns cylon.session.cookie-session-store
  (:require
   [com.stuartsierra.component :refer (using)]
   [cylon.session.protocols :refer (SessionStore)]
   [cylon.token-store :refer (get-token-by-id merge-token! create-token! purge-token!)]
   [ring.middleware.cookies :refer (cookies-request cookies-response)]
   [schema.core :as s]
   [plumbing.core :refer (<-)]))

(defn ->cookie [session]
  {:value (::key session)
   :expires (.toGMTString
             (doto (new java.util.Date)
               (.setTime (::expiry session))))
   :path "/"})

(def delete-cookie
  {:value nil
   :expires (.toGMTString (java.util.Date. 1970 0 1))
   :path "/"})

(defn cookies-response-with-session [response id-cookie session]
  ;; Use of cookies-response mean it is non-destructive - existing
  ;; cookies are preserved (but existing :cookies entries are not)
  (cookies-response
   (merge-with merge response
    {:cookies {id-cookie (->cookie session)}})))

;; This record satisfies SessionStore, indexed by a specific
;; cookie-id. This design allows us to encapsulate the cookie-id, rather
;; than have to pass it through numerous function calls.
(defrecord CookieSessionStore [cookie-id token-store]
  SessionStore
  (session [component request]
    ;; In case the underlying token store accepts nils, we should avoid
    ;; retrieving a nil-indexed token, so we wrap in a 'when-let'.
    (when-let [tokid (-> request cookies-request :cookies (get cookie-id) :value)]
      (get-token-by-id token-store tokid)))

  (assoc-session-data! [component request m]
    (when-let [tokid (-> request cookies-request :cookies (get cookie-id) :value)]
      (merge-token! token-store tokid m)))

  (respond-with-new-session! [component request data response]
    ;; TODO Create a HMAC'd identifier, not just a random UUID that
    ;; could be predicted and therefore allow session forgery.
    (let [id (str (java.util.UUID/randomUUID))]
      (->>
       (create-token! token-store id data)
       (cookies-response-with-session response cookie-id))))

  (respond-close-session! [component request response]
    (when-let [tokid (-> request cookies-request :cookies (get cookie-id) :value)]
      (purge-token! token-store tokid))
    (cookies-response
       (merge-with merge response
                   {:cookies {cookie-id delete-cookie}}))))

(def new-cookie-session-store-schema {:cookie-id s/Str})

(defn new-cookie-session-store [& {:as opts}]
  (->> opts
       (merge {:cookie-id "session-id"})
       (s/validate new-cookie-session-store-schema)
       map->CookieSessionStore
       (<- (using [:token-store]))))
