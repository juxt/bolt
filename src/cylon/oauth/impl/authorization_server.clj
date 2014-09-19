(ns cylon.oauth.impl.authorization-server
  (require
   [com.stuartsierra.component :as component]
   [clojure.tools.logging :refer :all]
   [modular.bidi :refer (WebService)]
   [bidi.bidi :refer (path-for)]
   [clojure.set :as set]
   [hiccup.core :refer (html h)]
   [schema.core :as s]
   [plumbing.core :refer (<-)]
   [clojure.string :as str]
   [cylon.oauth.client-registry :refer (lookup-client+)]
   [cylon.oauth.authorization :refer (AccessTokenAuthorizer authorized?)]
   [cylon.authorization :refer (RequestAuthorizer request-authorized?)]
   [cylon.authentication :refer (initiate-authentication-interaction get-outcome #_clean-resources!)]
   [cylon.user :refer (verify-user)]
   [cylon.totp :refer (OneTimePasswordStore get-totp-secret totp-token)]
   [clj-time.core :refer (now plus days)]
   [cheshire.core :refer (encode)]
   [clj-jwt.core :refer (to-str sign jwt)]
   [ring.middleware.params :refer (wrap-params)]
   [ring.middleware.cookies :refer (cookies-request)]
   [cylon.session :refer (session respond-with-new-session! assoc-session-data! respond-close-session!)]
   [cylon.token-store :refer (create-token! get-token-by-id merge-token!)]
   [ring.middleware.cookies :refer (wrap-cookies cookies-request cookies-response)]
   [ring.util.response :refer (redirect)]
   [cylon.oauth.encoding :refer (decode-scope encode-scope as-query-string)]))

(defprotocol OAuthUserAuthorizer
  (authenticated-user? [_ req])
  (init-user-authentication [_ req])
  (align-client-server-state-value [_ req]
    "each time the client needs to communicate with auth-endpoint,
  client sends a state query param to check the authenticity of the response.
  client-state and server-state must be the same in each communication.
  But there are cases (as signup) that the server-session-state willn't
  the same as new client auth-endpoint request
  That's the reason for this align client-server state function")
  (authorize-response-type-code [_ req]))

(defn wrap-schema-validation [h]
  (fn [req]
    (s/with-fn-validation
      (h req))))


;; --------- fns UTILS ------------------
;; --------- used by both auth-server and user-auth  ------------------

;; auth-server client req scopes
;; this fn is used by both AuthServer and AuthUser
(defn store-scopes-and-code-to-authorized-user! [{:keys [codes-store authenticator session-store] :as component}
                                                 {:keys [client-id] :as client}  req scopes]
  (let [authentication (get-outcome authenticator req)
        code (let [subject-identifier (:cylon/subject-identifier authentication)
                   session (session session-store req)
                   {:keys [client-id] :as client} (lookup-client+ (:client-registry component) (:client-id session))
                   code (str (java.util.UUID/randomUUID))]
               (assoc-session-data! session-store req {:cylon/authenticated? true :code code})
               ;; Remember the code for the possible exchange - TODO expire these
               (create-token! codes-store
                              code
                              (merge
                               {:client-id client-id}
                               {:created (java.util.Date.)}
                               {:cylon/subject-identifier subject-identifier}))
               code
               )]

    (merge-token! codes-store code  { :granted-scopes scopes})))

;; session client
(defn redirect-code-to-client-uri [{:keys [session-store] :as component}  client req]
  ;; 4.1.2: "If the resource owner grants the
  ;; access request, the authorization server
  ;; issues an authorization code and delivers it
  ;; to the client by adding the following
  ;; parameters to the query component of the
  ;; redirection URI"

  (let [{:keys [state code]} (session session-store req)]
    (redirect
     (str (:redirection-uri client)
          (as-query-string
           {"code" code
            "state"  state})))))

;; component client code
(defn generate-auth-code-and-client-redirect [component req client required-scopes]
  (store-scopes-and-code-to-authorized-user! component client req required-scopes)
  (redirect-code-to-client-uri component client req))



;; -----------------------------------------------------
;; --------- records and constructors ------------------

(defrecord AuthorizationServer [codes-store scopes iss session-store access-token-store authenticator user-authorizer]
  WebService
  (request-handlers [component]
    {
     ::authorization-endpoint
     (-> (fn [req]
           (debugf "OAuth2 authorization server: Authorizing request")

           (if (authenticated-user? user-authorizer req)
             (letfn [(authorize-response-type [{:keys [session-store  authenticator user-authorizer] :as component} req]
                       ;; seems to be the better place for this fn-call align-client-server-state-value
                       (align-client-server-state-value user-authorizer req)

                       (let [response-type  (:response-type (session session-store req))]
                         (case response-type
                           "code" (authorize-response-type-code user-authorizer req)
                           ;; Unknown response_type
                           {:status 400
                            :body (format "Bad response_type parameter: '%s'" response-type)}
                           )))]
               (authorize-response-type component req))
             (init-user-authentication user-authorizer req)))
         wrap-params
         wrap-schema-validation)

     ;; TODO Implement RFC 6749 4.1.2.1 Error Response
     ::permit
     (->
      ;; TODO I'm worred about the fact we must ensure that the session
      ;; represents a true authenticated user
      (fn [req]
        (if (authenticated-user? component req)
          (let [{:keys [requested-scopes code client-id state] :as session} (session session-store req)
                {:keys [redirection-uri] :as client} (lookup-client+ (:client-registry component) client-id)

                permitted-scopes (set (map
                                       (fn [x] (apply keyword (str/split x #"/")))
                                       (keys (:form-params req))))

                granted-scopes (set/intersection permitted-scopes requested-scopes)]

            (debugf (format "permitted-scopes is %s, requested-scopes is %s, => Granting scopes: %s"
                            permitted-scopes requested-scopes granted-scopes))

            (generate-auth-code-and-client-redirect component req client  granted-scopes))))

      wrap-params)

     ;; RFC 6749 4.1 (D) - and this is the Token endpoint as described
     ;; in section 3 (Protocol Endpoints)
     ::token-endpoint
     ;; This is initiated by the client
     (-> (fn [req]
           (let [params (:form-params req)
                 code (get params "code")
                 client-id (get params "client_id")
                 client (lookup-client+ (:client-registry component) client-id)]

             ;; "When making the request, the client authenticates with
             ;; the authorization server."
             (if (not= (get params "client_secret") (:client-secret client))
               {:status 403 :body "Client could not be authenticated"}

               (if-let [{sub :cylon/subject-identifier
                         granted-scopes :granted-scopes}
                        (get-token-by-id codes-store
                             ;; I don't think this key has to include client-id
                             ;; - it can just be 'code'.
                                         code)]

                 (let [access-token (str (java.util.UUID/randomUUID))
                       _ (create-token! access-token-store
                                        access-token
                                        {:client-id client-id
                                         :cylon/subject-identifier sub
                                         :scopes granted-scopes})
                       claim {:iss iss
                              :sub sub
                              :aud client-id
                              :exp (plus (now) (days 1)) ; expiry ; TODO unhardcode
                              :iat (now)}]

                   (infof "Claim is %s" claim)

                   ;; 5.1 Successful Response

                   ;; " The authorization server issues an access token
                   ;; and optional refresh token, and constructs the
                   ;; response by adding the following parameters to the
                   ;; entity-body of the HTTP response with a 200 (OK)
                   ;; status code:"

                   (debugf "About to OK, granted scopes is %s (type is %s)" granted-scopes (type granted-scopes))
                   (respond-close-session! session-store req {:status 200
                                                              :body (encode {"access_token" access-token
                                                                             "token_type" "Bearer"
                                                                             "expires_in" 3600
                                                                             ;; TODO Refresh token (optional)

                                                                             ;; 5.1 scope OPTIONAL only if
                                                                             ;; identical to scope requested by
                                                                             ;; client, otherwise required. In
                                                                             ;; this way, we pass back the scope
                                                                             ;; to the client.
                                                                             "scope" (encode-scope granted-scopes)

                                                                             ;; OpenID Connect ID Token
                                                                             "id_token" (-> claim
                                                                                            jwt
                                                                                            (sign :HS256 "secret") to-str)

                                                                             })})
                   )
                 {:status 400
                  :body "Invalid request - unknown code"}))))
         wrap-params )})

  (routes [_]
    ["/" {"authorize" {:get ::authorization-endpoint}
          "permit-client" {:post ::permit}
          ;; TODO: Can we use a hyphen instead here?
          "access_token" {:post ::token-endpoint}}])

  (uri-context [_] "/login/oauth")

  AccessTokenAuthorizer
  (authorized? [component access-token scope]
    (if-not (contains? (set (keys scopes)) scope)
      (throw (ex-info "Scope is not a known scope to this authorization server"
                      {:component component
                       :scope scope
                       :scopes scopes}))
      (contains? (:scopes (get-token-by-id access-token-store access-token))
                 scope)))

  RequestAuthorizer
  (request-authorized? [component request scope]
    (when-let [auth-header (get (:headers request) "authorization")]
      ;; Only match 'Bearer' tokens for now
      (let [access-token (second (re-matches #"\QBearer\E\s+(.*)" auth-header))]
        (authorized? component access-token scope)))))

(defn new-authorization-server [& {:as opts}]
  (->> opts

       (s/validate
        {:scopes {s/Keyword {:description s/Str}}

         :iss s/Str             ; uri actually, see openid-connect ch 2.
         })
       map->AuthorizationServer
       (<- (component/using
            [:access-token-store
             :codes-store
             :session-store
             :client-registry
             :authenticator
             :user-authorizer]))))

(defrecord UserAuthorizer [session-store]
  OAuthUserAuthorizer
  (authenticated-user? [{:keys [session-store authenticator]} req]
    (and
     ;;You dont have server-session-store associated, so let's authenticate first.
     (session session-store req)
     ;;You are not authenticated, so let's authenticate first.
     (get-outcome authenticator req)

     (:cylon/authenticated? (get-outcome authenticator req))
     ))

  (align-client-server-state-value [{:keys [session-store]} req]
    (debugf (format "state session %s , state request %s"
                    (:state (session session-store req))
                    (-> req :query-params (get "state"))))

    (when-let [session-state (:state (session session-store req))]
      (let [request-state (-> req :query-params (get "state"))]
        (when (and request-state (not= session-state request-state))
          (debugf "updating session state to request state")
          (assoc-session-data! session-store req {:state request-state}))))
    )

  (init-user-authentication [{:keys [session-store authenticator]} req]
    ;; auth-server  req
    (debugf "Not authenticated, must authenticate first with %s" authenticator )

    (let [{:keys [response session-state]}
          (initiate-authentication-interaction authenticator req {})]

     (respond-with-new-session! session-store req
      (merge {:client-id (-> req :query-params (get "client_id"))
        :requested-scopes (decode-scope (-> req :query-params (get "scope")))
        :state (-> req :query-params (get "state"))
              :response-type  "code"} session-state)
      response
      )))

  (authorize-response-type-code [{:keys [session-store  client-registry] :as component} req]
    ;; When a user permits a client, the client's scopes that they have accepted, are stored in the user preferences database
    ;; why?
    ;; because next time, we don't have to ask the user for their permission everytime they login
    ;; ok, i understand
    ;; however
    (let [session (session session-store req)
          client (->> (:client-id session) (lookup-client+ client-registry))
          {:keys [requires-user-acceptance? application-name description required-scopes]} client
          ]
      (debugf (if requires-user-acceptance?
                "App requires user acceptance"
                "App does not require user acceptance"))
      ;; Lookup the application - do we have at-least the client id?
      (if requires-user-acceptance?
        (redirect (path-for (:modular.bidi/routes req) ::acceptance-step))
        ;;client-dont-require-user-acceptance
        (do
          (debugf (format "App doesn't require user acceptance, granting scopes as required: [%s]" required-scopes))
          (generate-auth-code-and-client-redirect component req client required-scopes)))))

  WebService
  (request-handlers [component]
    {::logout (fn [req]
                 (->> (redirect "http://localhost:8010/logout")

                      (respond-close-session! session-store req)))

     ::acceptance-step
     (fn [req]
       (let [{:keys [requested-scopes client-id]} (session session-store req)
             {:keys [application-name description] :as client} (lookup-client+ (:client-registry component)  client-id)]
         {:status 200
          :body (html [:body
                       [:form {:method :post :action (path-for (:modular.bidi/routes req) :cylon.oauth.impl.authorization-server/permit)}
                        [:h1 "Authorize application?"]
                        [:p (format "An application (%s) is requesting to use your credentials" application-name)]
                        [:h2 "Application description"]
                        [:p description]
                        [:h2 "Scope"]
                        (for [s requested-scopes]
                          (let [s (apply str (interpose "/" (remove nil? ((juxt namespace name) s))))]
                            [:p [:label {:for s} s] [:input {:type "checkbox" :id s :name s :value s :checked true}]]))
                        [:input {:type "submit"}]]
                       ])}))

     })
  (routes [_]
    ["/" {
          "acceptance" {:get ::acceptance-step}
          "logout" {:get ::logout}}])

  (uri-context [_] "/login/oauth")

  )

(defn new-oauth-user-authorizer [& {:as opts}]
  (->> opts
       (merge {})
       map->UserAuthorizer
       (<- (component/using
            [:codes-store
             :session-store
             :client-registry
             :authenticator]))))
