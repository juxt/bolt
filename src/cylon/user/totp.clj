;; Copyright © 2014, JUXT LTD. All Rights Reserved.

(ns cylon.user.totp)

(defprotocol OneTimePasswordStore
  (set-totp-secret [_ identity secret] "this level add security to previous checked user/password identity")
  (get-totp-secret [_ identity] "Returns nil if no TOTP secret"))


;; Google Authenticator clojure code
;; taken from http://nakkaya.com/2012/08/13/google-hotp-totp-two-factor-authentication-for-clojure/

(defn secret-key []
  (let [buff (make-array Byte/TYPE 10)]
    (-> (java.security.SecureRandom.)
        (.nextBytes buff))

    (-> (org.apache.commons.codec.binary.Base32.)
        (.encode buff)
        (String.))))

(defn qr-code [identifier secret]
  (format (str "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr"
               "&chl=otpauth://totp/%s%%3Fsecret%%3D%s")
          identifier secret))

(defn hotp-token [secret idx]
  (let [secret (-> (org.apache.commons.codec.binary.Base32.)
                   (.decode secret))
        idx (-> (java.nio.ByteBuffer/allocate 8)
                (.putLong idx)
                (.array))
        key-spec (javax.crypto.spec.SecretKeySpec. secret "HmacSHA1")
        mac (doto (javax.crypto.Mac/getInstance "HmacSHA1")
              (.init key-spec))
        hash (->> (.doFinal mac idx)
                  (into []))]

    (let [offset (bit-and (hash 19) 0xf)
          bin-code (bit-or (bit-shift-left (bit-and (hash offset) 0x7f) 24)
                           (bit-shift-left (bit-and (hash (+ offset 1)) 0xff) 16)
                           (bit-shift-left (bit-and (hash (+ offset 2)) 0xff) 8)
                           (bit-and (hash (+ offset 3)) 0xff))]
      (format "%06d" (mod bin-code 1000000)))))

(defn totp-token [secret]
  (hotp-token secret (/ (System/currentTimeMillis) 1000 30)))
