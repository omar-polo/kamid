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

(in-package :all-tests)

(defparameter *client-certificate* "")

(defparameter *certificate-key*    "")

(defparameter *host*               "localhost")

(defparameter *port*               10564)

(defparameter *remote-test-file*   "test-file") ; note: missing "/" is intentional

(defparameter *remote-test-path*   "/test-file")

(defparameter *remote-test-path-write*   "/dir/subdir/file/test-file-write")

(defparameter *remote-test-path-contents* (format nil "qwertyuiopasdfghjklòàù è~%"))

(alexandria:define-constant +remote-test-path-ovewrwrite-data+ "12" :test #'string=)

(defun open-tls-socket (host port)
  (flet ((open-socket (hostname)
           (usocket:socket-connect hostname
                                   port
                                   :element-type '(unsigned-byte 8))))
    (or (ignore-errors (open-socket host))
        (open-socket host))))

(defmacro with-open-ssl-stream ((ssl-stream socket host port
                                 client-certificate
                                 certificate-key)
                                &body body)
  (alexandria:with-gensyms (tls-context socket-stream ssl-hostname)
    `(let ((,tls-context (cl+ssl:make-context :verify-mode cl+ssl:+ssl-verify-none+)))
       (cl+ssl:with-global-context (,tls-context :auto-free-p t)
         (let* ((,socket        (open-tls-socket ,host ,port))
                (,socket-stream (usocket:socket-stream ,socket))
                (,ssl-hostname  ,host)
                (,ssl-stream
                  (cl+ssl:make-ssl-client-stream ,socket-stream
                                                 :certificate     ,client-certificate
                                                 :key             ,certificate-key
                                                 :external-format nil ; unsigned byte 8
                                                 :unwrap-stream-p t
                                                 :verify          nil
                                                 :hostname        ,ssl-hostname)))
           ,@body)))))

(defsuite all-suite ())

(defun exit-program (&optional (exit-code 0))
  (uiop:quit exit-code))

(defun run-all-tests (&key (use-debugger t))
  (setf *client-certificate* (fs:getenv "REGRESS_CERT")
        *certificate-key*    (fs:getenv "REGRESS_KEY")
        *host*               (fs:getenv "REGRESS_HOSTNAME")
        *port*               (parse-integer (fs:getenv "REGRESS_PORT")))
  (handler-bind ((error (lambda (e)
                          (declare (ignore e))
                          (exit-program 1)))
                 (clunit::assertion-failed (lambda (e)
                          (declare (ignore e))
                          (exit-program 2))))
      (progn
        (clunit:run-suite 'all-suite :use-debugger use-debugger :report-progress t)
        (exit-program 0))))
