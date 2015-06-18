(ns bolt.session.jwt-session
  (:require
   [bolt.session.protocols :refer (SessionLifecycle SessionData SessionStore)]
   [schema.core :as s]
   [ring.middleware.cookies :refer (cookies-request cookies-response)]
   [buddy.sign.jws :as jws]))

(s/defrecord JsonWebTokenSession
    [cookie-id :- s/Str]
  SessionLifecycle
  (start-session! [_ response data] (cookies-response
                                     (merge-with merge response
                                                 {:cookies {cookie-id {:value (jws/sign data "secret")
                                                                       :path "/"}}})))
  (stop-session! [_ response _]
                 (cookies-response
                  (merge-with merge response
                              {:cookies {cookie-id {:value ""
                                                    :expires (.toGMTString (java.util.Date. 70 0 1))
                                                    :path "/"}}})))

  SessionData
  (session-data [_ request] (when-let [token (-> request cookies-request :cookies (get cookie-id) :value)]
                              (jws/unsign token "secret"))))

(defn new-jwt-session [& {:as opts}]
  (->> opts
       (merge {:cookie-id "jwt"})
       map->JsonWebTokenSession))
