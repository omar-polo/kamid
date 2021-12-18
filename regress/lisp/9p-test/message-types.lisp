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

(in-package :9p-client)

(defparameter *tversion*  100)

(defparameter *rversion*  101)

(defparameter *tauth*     102)

(defparameter *rauth*     103)

(defparameter *tattach*   104)

(defparameter *rattach*   105)

(defparameter *terror*    106) ; there is no terror

(defparameter *rerror*    107)

(defparameter *tflush*    108)

(defparameter *rflush*    108)

(defparameter *twalk*     110)

(defparameter *rwalk*     109)

(defparameter *topen*     112)

(defparameter *ropen*     113)

(defparameter *tcreate*   114)

(defparameter *rcreate*   115)

(defparameter *tread*     116)

(defparameter *rread*     117)

(defparameter *twrite*    118)

(defparameter *rwrite*    119)

(defparameter *tclunk*    120)

(defparameter *rclunk*    121)

(defparameter *tremove*   122)

(defparameter *rremove*   123)

(defparameter *tstat*     124)

(defparameter *rstat*     125)
