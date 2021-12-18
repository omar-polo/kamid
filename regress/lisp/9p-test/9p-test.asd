;; test-suite for kamid
;; Copyright (C) 2021  cage

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.
;; If not, see [[http://www.gnu.org/licenses/][http://www.gnu.org/licenses/]].

(defsystem :9p-test
  :author      "cage"
  :license     "GPLv3"
  :version     "0.0.1"
  :serial      t
  :depends-on (:alexandria
               :cl-ppcre
               :osicat
               :cl+ssl
               :clunit2
               :usocket
               :babel
               :uiop)
  :components ((:file "package")
               (:file "text-utils")
               (:file "misc-utils")
               (:file "filesystem-utils")
               (:file "conditions")
               (:file "message-types")
               (:file "client")
               (:module tests
                :components ((:file "package")
                             (:file "all-tests")
                             (:file "kami-tests")))))
