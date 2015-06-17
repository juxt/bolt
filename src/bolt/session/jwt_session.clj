(ns bolt.session.jwt-session
  (:require
   [bolt.session.protocols :refer (SessionStore)]
   [schema.core :as s]
   [ring.middleware.cookies :refer (cookies-request cookies-response)]
   [buddy.sign.jws :as jws]))

(s/defrecord JsonWebTokenSession
    [cookie-id :- s/Str]
  SessionStore
  (session
   [_ request]
   (when-let [token (-> request cookies-request :cookies (get cookie-id) :value)]
     (jws/unsign token "secret")))

  (assoc-session-data!
   [_ req m]
   (throw (ex-info "TODO" {})))

  (respond-with-new-session!
   [_ request data response]
   (cookies-response
    (merge-with merge response
                {:cookies {cookie-id {:value (jws/sign data "secret")
                                      :path "/"}}})))


  (respond-close-session!
   [_ request response]
   (cookies-response
    (merge-with merge response
                {:cookies {cookie-id {:value ""
                                      :expires (.toGMTString (java.util.Date. 70 0 1))
                                      :path "/"}}}))))

(defn new-jwt-session [& {:as opts}]
  (->> opts
       (merge {:cookie-id "jwt"})
       map->JsonWebTokenSession))
