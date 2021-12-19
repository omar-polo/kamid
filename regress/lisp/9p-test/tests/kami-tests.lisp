;; test suite for kami
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

(in-package :kami-tests)

(defsuite kami-suite (all-suite))

(defparameter *client-certificate* nil)

(defparameter *certificate-key*    nil)

(defparameter *host*               "localhost")

(defparameter *port*               10564)

(defparameter *remote-test-file*   "kami-test")

(defparameter *remote-test-path*   "/kamid/regress/root/dir/subdir/file")

(defparameter *remote-test-path-write*   "/kamid/regress/root/dir/subdir/test-file-write")

(defparameter *remote-test-path-contents* (format nil "qwertyuiopasdfghjklòàù è~%"))

(alexandria:define-constant +remote-test-path-ovewrwrite-data+ "12" :test #'string=)

(defun start-non-tls-socket (host port)
  (usocket:socket-connect host
                          port
                          :protocol     :stream
                          :element-type +byte-type+))

(defun example-mount (&optional (root  "/"))
  (with-open-ssl-stream (stream
                         socket
                         *host*
                         *port*
                         *client-certificate*
                         *certificate-key*)
    (let ((*messages-sent* '())
          (root-fid (mount stream root)))
      (9p-clunk stream root-fid)
      (read-all-pending-message stream)
      (9p-attach stream root)
      (read-all-pending-message stream)
      t)))

(deftest test-mount (kami-suite)
  (assert-true (ignore-errors (example-mount))))

(defun example-walk (path &optional (root "/"))
  (with-open-ssl-stream (stream
                         socket
                         *host*
                         *port*
                         *client-certificate*
                         *certificate-key*)

    (let ((*messages-sent* '())
          (root-fid (mount stream root)))
      (with-new-fid (path-fid)
        (9p-walk stream root-fid path-fid path)
        (read-all-pending-message stream)
        t))))

(deftest test-walk (kami-suite)
  (assert-true (ignore-errors (example-walk *remote-test-file*))))

(defun example-open-path (path &optional (root "/"))
  (with-open-ssl-stream (stream
                         socket
                         *host*
                         *port*
                         *client-certificate*
                         *certificate-key*)
    (let ((*messages-sent* '())
          (root-fid (mount stream root)))
      (with-new-fid (saved-root-fid)
        (9p-walk stream root-fid saved-root-fid +nwname-clone+)
        (open-path stream root-fid path)
        (read-all-pending-message stream)
        t))))

(deftest test-open-path (kami-suite)
  (assert-true (ignore-errors (example-open-path *remote-test-path*))))

(defun example-read (path &optional (root "/"))
  (with-open-ssl-stream (stream
                         socket
                         *host*
                         *port*
                         *client-certificate*
                         *certificate-key*)
    (let ((*messages-sent* ())
          (*buffer-size*   256)
          (root-fid        (mount stream root)))
      (with-new-fid (path-fid)
        (9p-walk stream root-fid path-fid path)
        (9p-open stream path-fid)
        (9p-read stream path-fid 0 10)
        (read-all-pending-message stream)
        t))))

(deftest test-read ((kami-suite) (test-walk))
  (assert-true (ignore-errors (example-open-path *remote-test-file*))))

(defun example-slurp (path &optional (root "/"))
  (with-open-ssl-stream (stream
                         socket
                         *host*
                         *port*
                         *client-certificate*
                         *certificate-key*)
    (let ((*messages-sent* ())
          (*buffer-size*   256)
          (root-fid        (mount stream root)))
      (babel:octets-to-string (slurp-file stream
                                          root-fid path
                                          :buffer-size 3)
                              :errorp nil))))

(deftest test-slurp-file ((kami-suite) (test-read))
  (assert-equality #'string=
      *remote-test-path-contents*
      (example-slurp *remote-test-path*)))

(defun example-write (path &optional (root "/"))
  (with-open-ssl-stream (stream
                         socket
                         *host*
                         *port*
                         *client-certificate*
                         *certificate-key*)
    (let* ((*messages-sent* ())
           (*buffer-size*   256)
           (root-fid        (mount stream root))
           (fid             (open-path stream root-fid path :mode +create-for-read-write+)))
      (9p-write stream fid 0 *remote-test-path-contents*)
      (read-all-pending-message stream)
      t)))

(deftest test-write ((kami-suite) (test-open-path test-read))
  (assert-true (ignore-errors (example-write *remote-test-path-write*))))

(defun example-write-2-3 (path &optional (root "/"))
  (with-open-ssl-stream (stream
                         socket
                         *host*
                         *port*
                         *client-certificate*
                         *certificate-key*)
    (let* ((*messages-sent* ())
           (*buffer-size*   256)
           (root-fid        (mount stream root))
           (fid             (open-path stream root-fid path :mode +create-for-read-write+)))
      (9p-write stream fid 2 +remote-test-path-ovewrwrite-data+)
      (read-all-pending-message stream)
      (babel:octets-to-string (slurp-file stream root-fid path)))))

(defun read-entire-file-as-string (path  &optional (root "/"))
  (with-open-ssl-stream (stream
                         socket
                         *host*
                         *port*
                         *client-certificate*
                         *certificate-key*)
    (let* ((*messages-sent* ())
           (*buffer-size*   256)
           (root-fid        (mount stream root)))
      (babel:octets-to-string (slurp-file stream root-fid path)))))

(deftest test-example-write-2-3 ((kami-suite) (test-write))
  (example-write-2-3 *remote-test-path-write*)
  (let* ((expected-sequence (copy-seq *remote-test-path-contents*))
         (file-sequence     (read-entire-file-as-string *remote-test-path-write*)))
    (setf (subseq expected-sequence 2 4) +remote-test-path-ovewrwrite-data+)
    (assert-equality #'string= file-sequence expected-sequence)))

(defun example-stat (path &optional (root "/"))
  (with-open-ssl-stream (stream
                         socket
                         *host*
                         *port*
                         *client-certificate*
                         *certificate-key*)
    (let* ((*messages-sent* ())
           (*buffer-size*   256)
           (root-fid        (mount stream root))
           (fid             (open-path stream root-fid path :mode +create-for-read+))
           (results         nil))
      (9p-stat stream fid
               :callback (lambda (x data)
                           (declare (ignore x))
                           (setf results (decode-rstat data))))
      (read-all-pending-message stream)
      results)))

(deftest test-stat (kami-suite)
  (example-write-2-3 *remote-test-path-write*)
  (assert-true (ignore-errors (example-stat "/")))
  (assert-true (ignore-errors (example-stat *remote-test-path*)))
  (assert-eq   :directory
      (stat-entry-type (example-stat "/")))
  (assert-eq   :file
      (stat-entry-type (example-stat *remote-test-path*))))
