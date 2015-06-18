(ns bolt.session.protocols)

(defprotocol SessionLifecycle
  "Start and stop sessions."
  (start-session! [_ response data] "Start a session containing the map of data given. Return a modified Ring response (derived from the given original response), encoding the session token, key, handle or data. The session material may be embedded in a Set-Cookie or other response header.")
  (stop-session! [_ response] "Stop a session. Return a modified Ring response (derived from the given original response), representing the cookies you want to delete."))

(defprotocol SessionData
  "Establish session data, given a request."
  (session-data [_ request] "Extract session data, returned as a map, from the given request. If necessary, verify the request is authentic to prevent forgery. If it isn't valid, return nil. Throw an exception to indicate a potential attack."))


;; Deprecated
(defprotocol SessionStore
  "A SessionStore maps an identifier, stored in a cookie, to a set of
  attributes. It is able to get cookies from the HTTP request, and set
  them on the HTTP response. A SessionStore will typically wrap a
  TokenStore."

  (session [_ req]
    "Returns the attribute map of the session, or nil if is no session")

  (assoc-session-data! [_ req m]
    "Associate data to an existing session. If there is no session,
    throw an exception.")

  (respond-with-new-session! [_ req data resp]
    "Create a new session with the given data, setting the cookie on the response")

  (respond-close-session! [_ req resp]
    "Delete the session from the store, response should inform the
    browser by setting the cookie with a 1970 expiry"))
