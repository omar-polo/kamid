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

;; uses code from

;; niccolo': a chemicals inventory
;; Copyright (C) 2016  Universita' degli Studi di Palermo

;; This  program is  free  software: you  can  redistribute it  and/or
;; modify it  under the  terms of  the GNU  General Public  License as
;; published  by  the  Free  Software Foundation,  version  3  of  the
;; License, or (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

(in-package :misc-utils)

(defmacro defcond (type)
  `(define-condition ,(alexandria:format-symbol t "TEXT-~a" (string-upcase type))
       (,type)
     ((text
       :initarg :text
       :reader text))
     (:documentation "Error that set text")))

(defcond error)

(define-condition out-of-bounds (error)
  ((seq
    :initarg :seq
    :reader seq)
   (idx
    :initarg :idx
    :reader idx))
  (:documentation "Error when you go out of bound"))

(defgeneric delete@ (sequence position))

(defgeneric safe-delete@ (sequence position)
  (:documentation "Return sequence if position is out of bound"))

(defmacro gen-delete@ ((sequence position) &body body)
  `(if (and (>= ,position 0)
            (< ,position (length ,sequence)))
       ,@body
      (error 'out-of-bounds :seq sequence :idx position)))

(defmethod delete@ ((sequence list) position)
  (gen-delete@
   (sequence position)
   (append (subseq sequence 0 position)
           (and (/= position (- (length sequence) 1))
                (subseq sequence (1+ position))))))

(defmethod delete@ ((sequence vector) position)
  (gen-delete@
   (sequence position)
    (make-array (1- (length sequence))
                :fill-pointer (1- (length sequence))
                :adjustable t
                :initial-contents (concatenate 'vector (subseq sequence 0 position)
                                               (and (/= position (- (length sequence) 1))
                                                    (subseq sequence (1+ position)))))))

(defmethod safe-delete@ ((sequence sequence) position)
  (restart-case
      (delete@ sequence position)
    (return-nil () nil)
    (return-whole () sequence)
    (new-index (i) (safe-delete@ sequence i))))

(defun safe-all-but-last-elt (sequence)
  (handler-bind ((out-of-bounds
                  #'(lambda (c)
                      (declare (ignore c))
                      (invoke-restart 'return-nil))))
    (safe-delete@ sequence (1- (length sequence)))))
