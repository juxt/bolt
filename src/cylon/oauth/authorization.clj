(ns cylon.oauth.authorization
  (require
   [com.stuartsierra.component :as component]
   [clojure.tools.logging :refer :all]
   [cylon.authorization :refer (RequestAuthorizer)]
   [cylon.session :refer (create-session! get-session)]))

(defprotocol AccessTokenAuthorizer
  ;; Determine if given credentials (found in request) meet a given
  ;; requirement
  (authorized? [_ access-token scope]))
