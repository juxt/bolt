;; Copyright © 2014 JUXT LTD.

(ns cylon.bootstrap-login-form
  (:require
   [cylon.impl.login-form :refer (LoginFormRenderer)]
   [hiccup.core :refer (html)]
   [garden.core :refer (css)]
   [garden.units :refer (pt em px)]
   [garden.color :refer (rgb)]))

(defn styles
  "From http://getbootstrap.com/examples/signin/signin.css"
  []
  (css
   [:.form-signin {:max-width (px 330)
                   :padding (px 15)
                   :margin "40px auto"}
    [:.form-signin-heading :.checkbox {:margin-bottom (px 10)}]
    [:.checkbox [:font-weight :normal]]
    [:.form-control {:position :relative
                     :height :auto
                     :box-sizing :border-box
                     :padding (px 10)
                     :font-size (px 16)}]
    [:.form-control:focus {:z-index 2}]
    ["input[type=\"email\"]" {:margin-bottom (px -1)
                              :border-bottom-right-radius 0
                              :border-bottom-left-radius 0}]
    ["input[type=\"password\"]" {:margin-bottom (px 10)
                                 :border-bottom-right-radius 0
                                 :border-bottom-left-radius 0}]]))

;; From http://getbootstrap.com/examples/signin/
(defrecord BootstrapLoginFormRenderer []
  LoginFormRenderer
  (render-login-form
    [this request {:keys [requested-uri action login-status fields]}]
    (html
     [:div
      [:style (styles)]
      [:form.form-signin {:role :form
                          :method "POST"
                          :style "border: 1px dotted #555"
                          :action action}

       [:h2.form-signin-heading [:span.glyphicon.glyphicon-user] "&nbsp;&nbsp;Please sign in&#8230"]

       (when login-status
         [:div.alert.alert-warning.alert-dismissable
          [:button.close {:type "button" :data-dismiss "alert" :aria-hidden "true"} "&times;"]
          (case login-status
            :failed [:span [:strong "Failed: "] "Please check email and password and try again or " [:a.alert-link {:href "#"} "reset your password"] "."])])

       (for [{:keys [name type placeholder required autofocus value]} fields]
         [:input.form-control
          (merge
           {:name name :type type :value value}
           (when placeholder {:placeholder placeholder})
           (when required {:required required})
           (when autofocus {:autofocus autofocus}))])

       (when (not-empty requested-uri)
         ;; If requested-uri is not nil, you should add it as a hidden field.
         [:input {:type "hidden" :name :requested-uri :value requested-uri}])

       [:label.checkbox
        [:input {:name "remember" :type :checkbox :value "remember-me"} "Remember me"]]

       [:button.btn.btn-lg.btn-primary.btn-block {:type "submit"} "Sign in"]

       [:p]
       [:a {:href "#"} "Reset password"]
       ]])))


(defn new-bootstrap-login-form-renderer []
  (->BootstrapLoginFormRenderer))
