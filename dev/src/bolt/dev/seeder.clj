(ns bolt.dev.seeder
  (:require
   [com.stuartsierra.component :refer (using Lifecycle)]
   [bolt.user.protocols :refer (UserStore UserPasswordHasher)]
   [bolt.user :refer (create-user! hash-password)]
   [schema.core :as s]))

(s/defrecord UserSeeder
    [users :- [{:email s/Str :password s/Str :roles #{s/Keyword}}]
     user-store :- (s/protocol UserStore)
     password-hasher :- (s/protocol UserPasswordHasher)]
  Lifecycle
  (start [component]
         (doseq [{:keys [email password roles]} users]
           (println "Creating user! " email)
           (create-user!
            user-store {:email email
                        :password (hash-password password-hasher password)
                        :roles roles}))

         component)
  (stop [component] component))

(defn new-user-seeder [& {:as args}]
  (-> (map->UserSeeder (merge {} args))
      (using [:password-hasher :user-store])))
