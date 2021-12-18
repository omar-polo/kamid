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

(in-package :filesystem-utils)

(define-constant +preprocess-include+ "^%include"              :test #'string=)

(define-constant +file-path-regex+ "[\\p{L},\\/,\\\\,\\.]+"    :test 'string=)

(defparameter *directory-sep-regexp*
  #+windows "\\"
  #-windows "\\/")

(defparameter *directory-sep*
  #+windows "\\"
  #-windows "/")

(defun cat-parent-dir (parent direntry)
  (format nil "~a~a~a" parent *directory-sep* direntry))

(defmacro do-directory ((var) root &body body)
  (with-gensyms (dir)
    `(let ((,dir (nix:opendir ,root)))
       (unwind-protect
            (handler-case
                (do ((,var (cat-parent-dir ,root (nix:readdir ,dir))
                           (cat-parent-dir ,root (nix:readdir ,dir))))
                    ((cl-ppcre:scan "NIL$" ,var))
                  ,@body)
              (nix::enotdir () 0)
              (nix:eacces () 0)
              (nix:eloop () 0))
       (nix:closedir ,dir)))))

(defun collect-children (parent-dir)
  (let ((all-paths ()))
    (do-directory (path) parent-dir
      (push path all-paths))
    (setf all-paths (sort all-paths #'string<))
    all-paths))

(defun getenv (name)
  (nix:getenv name))

(defun pwd ()
  (getenv "PWD"))

(defgeneric prepend-pwd (object))

(defmethod prepend-pwd ((object string))
  (if (cl-ppcre:scan "^\\." object)
      (text-utils:strcat (pwd) (subseq object 1))
      object))

(defmethod prepend-pwd ((object sequence))
  (map 'list #'prepend-pwd object))

(defun regular-file-p (path)
  (nix:s-isreg (nix:stat-mode (nix:stat path))))

(defun dirp (path)
  (ignore-errors
   (and (nix:stat path)
        (nix:s-isdir (nix:stat-mode (nix:stat path))))))

(defun split-path-elements (path)
  (let ((splitted (cl-ppcre:split *directory-sep-regexp* path)))
    (substitute *directory-sep* "" splitted :test #'string=)))

(defun path-last-element (path)
  (let ((elements (cl-ppcre:split *directory-sep-regexp* path)))
    (and elements
         (last-elt elements))))

(defun path-first-element (path)
  (let ((elements (cl-ppcre:split *directory-sep-regexp* path)))
    (and elements
         (first-elt elements))))

(defun path-to-hidden-file-p (path)
  "unix-like only"
  (let ((last-element (path-last-element path)))
    (and path (cl-ppcre:scan "^\\." last-element))))

(defun strip-dirs-from-path (p)
  (multiple-value-bind (all registers)
      (cl-ppcre:scan-to-strings (concatenate 'string
                                             *directory-sep*
                                             "([^"
                                             *directory-sep*
                                             "]+)$")
                                p)
    (declare (ignore all))
    (and (> (length registers) 0)
         (elt registers 0))))

(defun parent-dir-path (path)
  (let ((splitted (remove-if #'(lambda (a) (string= "" a))
                             (split-path-elements path))))
    (cond
      ((> (length splitted) 1)
       (let ((res (if (string= (string (elt path 0)) *directory-sep*)
                      (concatenate 'string *directory-sep* (first splitted))
                      (first splitted))))
         (loop for i in (subseq splitted 1 (1- (length splitted))) do
              (setf res (concatenate 'string res *directory-sep* i)))
         (setf res (concatenate 'string res *directory-sep*))
         res))
      ((or (= (length splitted) 1)
           (null splitted))
       *directory-sep*)
      (t
       path))))

(defun file-exists-p (f)
  (uiop:file-exists-p f))

(defun directory-exists-p (d)
  (uiop:directory-exists-p d))

(defun delete-file-if-exists (f)
  (uiop:delete-file-if-exists f))

(defun home-dir (&key (add-separator-ends nil))
  (let ((home (getenv "HOME")))
    (if add-separator-ends
        (text-utils:strcat home *directory-sep*)
        home)))
