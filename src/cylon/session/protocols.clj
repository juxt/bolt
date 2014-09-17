(ns cylon.session.protocols)

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
    browser by setting the cookie with a 1970 expiry")

  (remove-token! [_ tokid]
    "there is times that you can't access to the browser .... :| ")

  #_(dissoc-data! [_ req key]))
