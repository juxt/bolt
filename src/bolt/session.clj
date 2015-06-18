;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns bolt.session
  (:require
   [ring.middleware.cookies :refer (cookies-request cookies-response)]
   [bolt.session.protocols :as p]
   [bolt.util :refer (Request Response)]
   [schema.core :as s]))

(s/defn start-session! :- Response
  [component :- (s/protocol p/SessionLifecycle)
   response :- Response
   data :- {s/Keyword s/Any}]
  (p/start-session! component response data))

(s/defn stop-session! :- Response
  [component :- (s/protocol p/SessionLifecycle)
   response :- Response]
  (p/stop-session! component response))

(s/defn session-data :- (s/maybe {s/Keyword s/Any})
  [component :- (s/protocol p/SessionData)
   request ;; :- Request
   ]
  (p/session-data component request))

;; Deprecated

(s/defn session :- (s/maybe {s/Keyword s/Any})
  [component :- (s/protocol p/SessionStore)
   request ;; :- Request
   ]
  (p/session component request))

(s/defn assoc-session-data! :- nil
  [component :- (s/protocol p/SessionStore)
   request ;; :- Request
   m :- {s/Keyword s/Any}]
  (p/assoc-session-data! component request m))

(s/defn respond-with-new-session! :- Response
  [component :- (s/protocol p/SessionStore)
   request ;; :- Request
   data :- {s/Keyword s/Any}
   response :- Response]
  (p/respond-with-new-session! component request data response))

(s/defn respond-close-session! :- Response
  [component :- (s/protocol p/SessionStore)
   request ;; :- Request
   response :- Response]
  (p/respond-close-session! component request response))
