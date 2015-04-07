(ns cylon.user.file-backed-store
  (:require
   [cylon.user.protocols :refer (UserStore)]
   [com.stuartsierra.component :refer (Lifecycle)]
   [clojure.pprint :refer (pprint)]
   [clojure.java.io :as io]
   [schema.core :as s]
   ))

(defn save
  "Save the state of the component's ref to a file, via an agent."
  [component]
  (send-off
   (:agent component)
   (fn [f]
     (spit f (with-out-str (pprint @(:ref component))))
     (:file component))))

(defrecord FileBackedUserStore []
  Lifecycle
  (start [component]
    (let [f (:file component)]
      (assoc component
             :ref (ref (if (.exists f) (read-string (slurp f)) {}))
             :agent (agent f))))
  (stop [component] component)

  UserStore
  (create-user! [component uid pw-hash email user-details]
    (dosync
     (alter (:ref component) assoc uid {:pw-hash pw-hash
                                        :email email
                                        :user-details user-details})
     (save component)
     (get @(:ref component) uid)))

  (get-user [component uid]
    (get @(:ref component) uid))

  (get-user-password-hash [component uid]
    (get-in @(:ref component) [uid :pw-hash]))

  (set-user-password-hash! [component uid pw-hash]
    (dosync
     (alter (:ref component) assoc uid {})
     (save component)
     (get @(:ref component) uid)))

  (get-user-by-email [component email]
    (some #(let [[uid user] %] (when (= email (:email user))
                                 (-> user
                                     (assoc :uid uid)
                                     (dissoc :pw-hash))))
          @(:ref component)))

  (delete-user! [_ uid]
    (throw (ex-info "TODO" {})))

  (verify-email! [_ uid]
    (throw (ex-info "TODO" {}))))

(defn check-file-parent [{f :file :as opts}]
  (assert (.exists (.getParentFile (.getCanonicalFile f)))
          (format "Please create the directory structure which should contain the file: %s" f))
  opts)

(defn new-file-backed-user-store [& {:as opts}]
  (->> opts
       (s/validate {:file s/Any})
       (#(update-in % [:file] io/file))
       check-file-parent
       map->FileBackedUserStore))
