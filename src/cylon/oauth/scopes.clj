(ns cylon.oauth.scopes)

(defprotocol Scopes
  (valid-scope? [_ scope]))
