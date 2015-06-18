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
                              (jws/unsign token "secret")))

  ;; Deprecated
  SessionStore
  (session
   [_ request]
   (throw (ex-info "Deprecated: old SessionStore protocol" {}))
   (when-let [token (-> request cookies-request :cookies (get cookie-id) :value)]
     (jws/unsign token "secret")))

  (respond-close-session!
   [_ request response]
   (throw (ex-info "Deprecated: old SessionStore protocol" {}))
   (cookies-response
    (merge-with merge response
                {:cookies {cookie-id {:value ""
                                      :expires (.toGMTString (java.util.Date. 70 0 1))
                                      :path "/"}}})))

  (respond-with-new-session!
   [_ request data response]
   (throw (ex-info "Deprecated: old SessionStore protocol" {}))
   (cookies-response
    (merge-with merge response
                {:cookies {cookie-id {:value (jws/sign data "secret")
                                      :path "/"}}})))

  (assoc-session-data!
   [_ req m]
   (throw (ex-info "Deprecated: old SessionStore protocol" {}))
   (throw (ex-info "TODO: Assoc new data and resign" {}))))

(defn new-jwt-session [& {:as opts}]
  (->> opts
       (merge {:cookie-id "jwt"})
       map->JsonWebTokenSession))
