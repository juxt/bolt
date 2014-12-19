;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.oauth.server.server
  (require
   [clojure.set :as set]
   [clojure.string :as str]
   [clojure.tools.logging :refer :all]
   [bidi.bidi :as bidi]
   [cheshire.core :refer (encode)]
   [clj-jwt.core :refer (to-str sign jwt)]
   [clj-time.core :refer (now plus days)]
   [com.stuartsierra.component :as component :refer (Lifecycle)]
   [cylon.authentication :refer (authenticate initiate-authentication-handshake)]
   [cylon.authentication.protocols :refer (RequestAuthenticator AuthenticationHandshake)]
   [cylon.oauth.registry.protocols :refer (ClientRegistry)]
   [cylon.oauth.registry :refer (lookup-client)]
   [cylon.oauth.encoding :refer (decode-scope encode-scope)]
   [cylon.session :refer (session respond-with-new-session! assoc-session-data! respond-close-session!)]
   [cylon.session.protocols :refer (SessionStore)]
   [cylon.token-store :refer (create-token! get-token-by-id)]
   [cylon.token-store.protocols :refer (TokenStore)]
   [cylon.util :refer (as-query-string wrap-schema-validation uri-with-qs)]
   [hiccup.core :refer (html h)]
   [modular.bidi :refer (WebService path-for)]
   [plumbing.core :refer (<-)]
   [ring.middleware.cookies :refer (cookies-request)]
   [ring.middleware.cookies :refer (wrap-cookies cookies-request cookies-response)]
   [ring.middleware.params :refer (params-request)]
   [ring.util.response :refer (redirect)]
   [schema.core :as s])
  (:import (java.net URLEncoder)))

(def new-authorization-server-schema
  {:scopes {s/Keyword {:description s/Str}}
   :store s/Any
   :iss s/Str             ; uri actually, see openid-connect ch 2.
   :uri-context s/Str
   })

(defrecord AuthorizationServer [store scopes iss
                                session-store
                                access-token-store
                                client-registry
                                uri-context]
  Lifecycle
  (start [component]
    (s/validate
     (merge new-authorization-server-schema
            {:session-store (s/protocol SessionStore)
             :access-token-store (s/protocol TokenStore)
             :client-registry (s/protocol ClientRegistry)
             })
     component))
  (stop [component] component)

  WebService
  (request-handlers [component]
    {::authorization-endpoint
     (->
      (fn [req]

        ;; TODO We should validate the incoming response_type

        (let [authentication (authenticate component req)]
          (debugf "OAuth2 authorization server: Authorizing request. User authentication is %s" authentication)
          ;; Establish whether the user-agent is already authenticated.


          ;; If we aren't authenticated, we hand off to the
          ;; authentication process, which will honor an existing
          ;; session or create a new one if one doesn't already
          ;; exist. Since we want to remember certain details of this
          ;; authorization request, we elect to create the session
          ;; here. The authentication will return to this same handler.

          ;; We initiate an authentication, which will ALWAYS
          ;; create a new session, so we store important details
          ;; about this request for the return. We

          (if-not (:cylon/subject-identifier authentication)
            (initiate-authentication-handshake component req)

            ;; Else... The user is AUTHENTICATED (now), so we AUTHORIZE the CLIENT
            (let [{response-type "response_type"
                   client-id "client_id"
                   scopes-param "scope"
                   state "state"} (-> req params-request :query-params)
                   requested-scopes (decode-scope scopes-param)]

              (case response-type
                "code"
                (let [code (str (java.util.UUID/randomUUID))

                      {:keys [redirection-uri application-name description
                              requires-user-acceptance? required-scopes] :as client}
                      (lookup-client (:client-registry component) client-id)]

                  ;; Why do we do this?
                  ;; you need to associate the user-data, scopes, redirect-uri with params...  with the code
                  ;; (assoc-session-data! session-store req {:code code})

                  ;; Remember the code for the possible exchange - TODO expire these
                  (swap! store assoc
                         code
                         (merge
                          {:created (java.util.Date.)}
                          ;; This is for the OpenID-Connect JWT token that we will send with the access-token
                          (select-keys authentication [:cylon/subject-identifier])))

                  ;; When a user permits a client, the client's scopes that they have accepted, are stored in the user preferences database
                  ;; why?
                  ;; because next time, we don't have to ask the user for their permission everytime they login
                  ;; ok, i understand
                  ;; however

                  (debugf (if requires-user-acceptance?
                            "App requires user acceptance"
                            "App does not require user acceptance"))
                  ;; Lookup the application - do we have at-least the client id?
                  (if requires-user-acceptance?
                    {:status 200
                     :body (html [:body
                                  [:form {:method :post :action (bidi/path-for (:modular.bidi/routes req) ::permit)}
                                   [:h1 "Authorize application?"]
                                   [:p (format "An application (%s) is requesting to use your credentials" application-name)]
                                   [:h2 "Application description"]
                                   [:p description]
                                   [:h2 "Scope"]
                                   (for [s requested-scopes]
                                     (let [s (apply str (interpose "/" (remove nil? ((juxt namespace name) s))))]
                                       [:p [:label {:for s} s] [:input {:type "checkbox" :id s :name s :value s :checked true}]]))
                                   [:input {:type "submit"}]]
                                  ])}

                    (do
                      (debugf (format "App doesn't require user acceptance, granting scopes as required: [%s]" required-scopes))
                      (swap! store update-in [code] assoc :granted-scopes required-scopes)
                      ;; 4.1.2: "If the resource owner grants the
                      ;; access request, the authorization server
                      ;; issues an authorization code and delivers it
                      ;; to the client by adding the following
                      ;; parameters to the query component of the
                      ;; redirection URI"
                      (debugf "Redirecting to redirection uri: %s" redirection-uri)

                      (redirect
                       (str redirection-uri
                            (as-query-string
                             {"code" code
                              "state" state}))))))

                ;; Unknown response_type
                {:status 400
                 :body (format "Bad response_type parameter: '%s'" response-type)})))))

      wrap-schema-validation)

     ;; TODO Implement RFC 6749 4.1.2.1 Error Response

     ;; ::permit is called by ::authorization-endpoint above, and it assumes
     ;; various things are placed in the current session. It hasn't been
     ;; properly tested (and we know it won't work as currently written)
     ;; so treat as a stub for now.
     ::permit
     (fn [req]
       ;; TODO I'm worred about the fact we must ensure that the session
       ;; represents a true authenticated user
       (let [session (session session-store req)
             form-params (-> req params-request :form-params)
             ]
         (if (:cylon/subject-identifier session)
           (let [permitted-scopes (set (map
                                        (fn [x] (apply keyword (str/split x #"/")))
                                        (keys form-params)))
                 _ (debugf "permitted-scopes is %s" permitted-scopes)
                 requested-scopes (:requested-scopes session)
                 _ (debugf "requested-scopes is %s" requested-scopes)

                 granted-scopes (set/intersection permitted-scopes requested-scopes)
                 code (:code session)
                 client-id (:client-id session)
                 {:keys [redirection-uri] :as client} (lookup-client (:client-registry component) client-id)
                 ]

             (debugf "Granting scopes: %s" granted-scopes)
             (swap! store update-in [code] assoc :granted-scopes granted-scopes)

             (redirect
              (format "%s?code=%s&state=%s"
                      redirection-uri code (:state session)))))))

     ;; RFC 6749 4.1 (D) - and this is the Token endpoint as described
     ;; in section 3 (Protocol Endpoints)
     ::token-endpoint
     ;; This is initiated by the client
     (fn [req]
       (let [params (-> req params-request :form-params)
             code (get params "code")
             client-id (get params "client_id")
             client (lookup-client (:client-registry component) client-id)]

         ;; "When making the request, the client authenticates with
         ;; the authorization server."
         (if (not= (get params "client_secret") (:client-secret client))
           {:status 403 :body "Client could not be authenticated"}

           (if-let [{sub :cylon/subject-identifier
                     granted-scopes :granted-scopes}
                    (get @store code)]

             (let [access-token (str (java.util.UUID/randomUUID))
                   claim {:iss iss
                          :sub sub
                          :aud client-id
                          :exp (plus (now) (days 1)) ; expiry ; TODO unhardcode
                          :iat (now)}]

               (create-token! access-token-store
                              access-token
                              {:client-id client-id
                               :cylon/subject-identifier sub
                               :cylon/scopes granted-scopes})

               ;; Store the access token
               (assoc-session-data! session-store req {:cylon/access-token access-token})
               (infof "Claim is %s" claim)

               ;; 5.1 Successful Response

               ;; " The authorization server issues an access token
               ;; and optional refresh token, and constructs the
               ;; response by adding the following parameters to the
               ;; entity-body of the HTTP response with a 200 (OK)
               ;; status code:"

               (debugf "About to OK, granted scopes is %s (type is %s)" granted-scopes (type granted-scopes))
               (respond-close-session!
                session-store req
                {:status 200
                 :body (encode
                        {"access_token" access-token
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
                         "id_token"
                         (-> claim
                             jwt
                             (sign :HS256 "secret") to-str)
                         })}))
             {:status 400
              :body (format "Invalid request - unrecognized code: %s" code)}))))})

  (routes [_]
    ["/" {"authorize" {:get ::authorization-endpoint}
          "permit-client" {:post ::permit}
          "access-token" {:post ::token-endpoint}}])

  (uri-context [_] uri-context)

  AuthenticationHandshake
  (initiate-authentication-handshake [this req]
    (if-let [p (path-for req :cylon.user.login/login-form)]
      (let [loc (str p (as-query-string {"post_login_redirect" (URLEncoder/encode (uri-with-qs req))}))]
        (debugf "Redirecting to %s" loc)
        (redirect loc))
      (throw (ex-info "No path to login form" {}))))

  RequestAuthenticator
  (authenticate [this req]
    (session session-store req))

  )

(defn new-authorization-server [& {:as opts}]
  (->> opts
       (merge {:store (atom {})
               :uri-context "/login/oauth"})
       (s/validate new-authorization-server-schema)
       map->AuthorizationServer
       (<- (component/using
            [:access-token-store
             :session-store
             :client-registry]))))
