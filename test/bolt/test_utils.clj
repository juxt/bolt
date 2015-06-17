(ns bolt.test-utils
  (:require
   [com.stuartsierra.component :as component]))

(def ^:dynamic *system* nil)

(defmacro with-system
  [system & body]
  `(let [s# (component/start ~system)]
     (try
       (binding [*system* s#] ~@body)
       (finally
         (component/stop s#)))))

(defn with-system-fixture
  [system]
  (fn [f]
    (with-system (system)
      (f))))

(defn new-test-system
  "Create a new system for testing quickly, single arity defaults deps
  to {}"
  ([components]
   (new-test-system components {}))
  ([components deps]
   (component/system-using
    (apply component/system-map (apply concat components))
    deps)))
