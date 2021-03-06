;; test stuite for kami
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
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

(defpackage :all-tests
  (:use :cl
        :clunit
        :cl+ssl)
  (:export
   :*client-certificate*
   :*certificate-key*
   :*host*
   :*port*
   :with-open-ssl-stream
   :all-suite
   :run-all-tests-with-debugger
   :run-all-tests))

(defpackage :kami-tests
  (:use :cl
        :clunit
        :purgatory
        :all-tests)
  (:export))
