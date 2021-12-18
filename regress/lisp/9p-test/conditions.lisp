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

(define-condition 9p-error (error)
  ((error-value
    :initarg :error-value
    :reader error-value)
   (message-type
    :initarg :message-type
    :reader message-type)
   (tag
    :initarg :tag
    :reader tag))
  (:report (lambda (condition stream)
             (format stream
                     "message-type ~a tag ~a: ~a"
                     (message-type condition)
                     (tag condition)
                     (error-value condition))))
  (:documentation "Error for 9p protocol"))


(define-condition 9p-initialization-error (error)
  ((tag
    :initarg :tag
    :reader tag)
   (rtag
    :initarg :rtag
    :reader rtag))
  (:report (lambda (condition stream)
             (format stream "error initialization tag sent ~a, got ~a instead"
                     (tag condition) (rtag condition))))
  (:documentation "Error for 9p protocol"))
