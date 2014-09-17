;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.session
  (:require
   [ring.middleware.cookies :refer (cookies-request cookies-response)]
   [cylon.session.protocols :as p]
   [schema.core :as s]))

;; Old functions here

(s/defschema Request "A Ring-style request"
  {:headers s/Any
   s/Keyword s/Any})

(s/defschema Response "A Ring-style response"
  {(s/optional-key :status) s/Num
   (s/optional-key :headers) s/Any
   (s/optional-key :body) s/Str})

(s/defn session :- (s/maybe{s/Keyword s/Any})
  [component :- (s/protocol p/SessionStore)
   request :- Request]
  (p/session component request))

;;(s/defn new-session-response :- )

(s/defn assoc-session-data! :- nil
  [component :- (s/protocol p/SessionStore)
   request :- Request
   m :- {s/Keyword s/Any}]
  (p/assoc-session-data! component request m))

(s/defn respond-with-new-session! :- Response
  [component :- (s/protocol p/SessionStore)
   request :- Request
   data :- {s/Keyword s/Any}
   response :- Response]
  (p/respond-with-new-session! component request data response))

(s/defn respond-close-session! :- Response
  [component :- (s/protocol p/SessionStore)
   request :- Request
   response :- Response]
  (p/respond-close-session! component request response))


(s/defn remove-token! :- nil
  [component :- (s/protocol p/SessionStore)
   tokid :- s/Str]
  (p/remove-token! component tokid))


#_(defn get-session-id [request cookie-name]
  (-> request cookies-request :cookies (get cookie-name) :value))

#_(s/defn get-session-from-cookie :- (s/maybe {:cylon.session/key s/Str
                                             :cylon.session/expiry s/Num
                                             s/Keyword s/Any})
  [request
   cookie-name :- s/Str
   session-store :- (s/protocol SessionStore)]
  (get-session session-store (get-session-id request cookie-name)))

#_(defn get-session-value [request cookie-name session-store k]
    (get (get-session-from-cookie request cookie-name session-store) k))
