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

(defparameter *remote-test-file*   "test-file") ; note: missing "/" is intentional

(defparameter *remote-test-path*   "/test-file")

(defparameter *remote-test-path-write*   "/dir/subdir/test-file-write")

(defparameter *remote-test-path-contents* (format nil "qwertyuiopasdfghjklòàù è~%"))

(defsuite kami-suite (all-suite))

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

(defun example-write-fails (path &optional (root "/"))
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
      (read-all-pending-message stream))))

(deftest test-write-on-directory-fails ((kami-suite) (test-write))
  (assert-condition 9p-error (example-write-fails "/")))

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
  (assert-true (ignore-errors (example-stat "/")))
  (assert-true (ignore-errors (example-stat *remote-test-path*)))
  (assert-eq   :directory
      (stat-entry-type (example-stat "/")))
  (assert-eq   :file
      (stat-entry-type (example-stat *remote-test-path*))))

(defun example-create-file (path &optional (root "/"))
  (with-open-ssl-stream (stream
                         socket
                         *host*
                         *port*
                         *client-certificate*
                         *certificate-key*)
    (let* ((*messages-sent* ())
           (root-fid        (mount stream root)))
      (with-new-fid (fid)
        (9p-create stream root-fid path)
        (read-all-pending-message stream)
        t))))

(alexandria:define-constant +create-file+ "test-file-create" :test #'string=)

(defun example-create-directory (path &optional (root "/"))
  (with-open-ssl-stream (stream
                         socket
                         *host*
                         *port*
                         *client-certificate*
                         *certificate-key*)
    (let* ((*messages-sent* ())
           (root-fid        (mount stream root)))
      (create-directory stream root-fid path)
      t)))

(alexandria:define-constant +create-directory+ "test-dir-create" :test #'string=)

(deftest test-create ((kami-suite) (test-open-path))
  (assert-true (ignore-errors (example-create-file +create-file+)))
  (assert-true (ignore-errors (example-create-directory +create-directory+))))
