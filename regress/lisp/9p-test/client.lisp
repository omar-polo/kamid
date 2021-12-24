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

(define-constant +byte-type+            '(unsigned-byte 8) :test #'equalp)

(define-constant +version+               "9P2000"          :test #'string=)

(define-constant +message-length-size+          4          :test #'=)

(define-constant +message-type-size+            1          :test #'=)

(define-constant +message-tag-size+             2          :test #'=)

(define-constant +message-string-length-size+   2          :test #'=)

(define-constant +nofid+                        #xffffffff :test #'=)

(define-constant +create-for-read+       #x0               :test #'=)

(define-constant +create-for-write+      #x1               :test #'=)

(define-constant +create-for-read-write+ #x2               :test #'=)

(define-constant +create-for-exec+       #x3               :test #'=)

(define-constant +create-dir+            #x80000000        :test #'=)

(define-constant +open-truncate+         #x10              :test #'=)

(define-constant +open-remove-on-clunk+  #x40              :test #'=)

(define-constant +stat-type-dir+          #x80       :test #'=
  :documentation "mode bit for directories")

(define-constant +stat-type-append+       #x40       :test #'=
  :documentation "mode bit for append only files")

(define-constant +stat-type-excl+         #x20       :test #'=
  :documentation "mode bit for exclusive use files")

(define-constant +stat-type-mount+        #x10       :test #'=
  :documentation "mode bit for mounted channel")

(define-constant +stat-type-auth+         #x08       :test #'=
  :documentation "mode bit for authentication file")

(define-constant +stat-type-tmp+          #x04       :test #'=
  :documentation "mode bit for non-backed-up files")

(define-constant +stat-type-symlink+      #x02       :test #'=
  :documentation "mode bit for non-backed-up files")

(define-constant +stat-type-file+         #x00       :test #'=
  :documentation "mode bit for non-backed-up files")

(define-constant +file-types+ (list (cons +stat-type-dir+     :directory)
                                    (cons +stat-type-append+  :append-only)
                                    (cons +stat-type-excl+    :executable)
                                    (cons +stat-type-mount+   :mount)
                                    (cons +stat-type-auth+    :auth )
                                    (cons +stat-type-tmp+     :tmp)
                                    (cons +stat-type-symlink+ :symlink)
                                    (cons +stat-type-file+    :file))
  :test #'equalp)

(defun file-type-number->symbol (key)
  (cdr (assoc key +file-types+)))

;; modes

(define-constant +stat-type-read+         #x4              :test #'=
  :documentation "mode bit for read permission")

(define-constant +stat-type-write+        #x2              :test #'=
  :documentation "mode bit for write permission")

(define-constant +stat-type-exec+         #x1              :test #'=
  :documentation "mode bit for execute permission")

(define-constant +standard-socket-port+   564              :test #'=)

(define-constant +nwname-clone+             0              :test #'=)

(defparameter *buffer-size*  (* 4 1024 1024))

(defparameter *tag* 8)

(defparameter *fid* #x00000001)

(defparameter *messages-sent* '())

(defun tags-exists-p-clsr (tag-looking-for)
  (lambda (a) (octects= tag-looking-for (car a))))

(defun fire-response (tag message-type data)
  (let ((found (find-if (tags-exists-p-clsr tag) *messages-sent*)))
    (if found
        (let ((fn (cdr found)))
          (setf *messages-sent* (remove-if (tags-exists-p-clsr tag) *messages-sent*))
          (funcall fn message-type data))
        (warn (format nil "received unknown response message tag ~a" tag)))))

(defun append-tag-callback (tag function)
  (setf *messages-sent* (push (cons tag function) *messages-sent*)))

(defun read-all-pending-message (stream)
  (when *messages-sent*
    (multiple-value-bind (message-type rtag data)
        (restart-case
            (read-message stream)
          (ignore-error (e)
            (values (message-type e)
                    (tag          e)
                    #())))
      (fire-response rtag message-type data)
      (read-all-pending-message stream))))

(defun next-tag ()
  (prog1
      (make-octects *tag* 2)
    (incf *tag*)))

(defun next-fid ()
  (prog1
      (int32->bytes *fid*)
    (incf *fid*)))

(defun bytes->int (bytes)
  (let ((res #x0000000000000000)
        (ct  0))
    (map nil
         (lambda (a)
           (setf res (boole boole-ior
                            (ash a ct)
                            res))
           (incf ct 8))
         bytes)
    res))

(defmacro gen-intn->bytes (bits)
  (let ((function-name (alexandria:format-symbol t "~:@(int~a->bytes~)" bits)))
    `(defun ,function-name (val &optional (count 0) (res '()))
       (if (>= count ,(/ bits 8))
           (reverse res) ; little endian
           (,function-name (ash val -8)
                           (1+ count)
                           (push (boole boole-and val #x00ff)
                                 res))))))

(gen-intn->bytes  8)

(gen-intn->bytes  16)

(gen-intn->bytes  32)

(gen-intn->bytes  64)

(gen-intn->bytes 512)

(gen-intn->bytes 416)

(defun big-endian->little-endian (bytes)
  (reverse bytes))

(defun vcat (a b)
  (concatenate 'vector a b))

(defclass octects ()
  ((value
    :initform 0
    :initarg :value
    :accessor value)
   (size
    :initform 0
    :initarg :size
    :accessor size)))

(defgeneric octects= (a b))

(defgeneric encode (object))

(defgeneric decode (object))

(defmethod encode ((object octects))
  (with-accessors ((value value)
                   (size size)) object
    (let ((bytes (ecase size
                   (1  (int8->bytes  value))
                   (2  (int16->bytes  value))
                   (4  (int32->bytes  value))
                   (8  (int64->bytes  value))
                   (13 (int416->bytes value))
                   (32 (int512->bytes value))))
          (res   (make-array size :element-type +byte-type+)))
      (loop for i from 0 below size do
        (setf (elt res i) (elt bytes i)))
      res)))

(defmethod octects= ((a octects) b)
  (= (value a) b))

(defmethod octects= ((a number) (b octects))
  (octects= b a))

(defmethod octects= ((a number) (b number))
  (= b a))

(defun add-size (msg)
  (let ((length (int32->bytes (+ +message-length-size+ (length msg)))))
    (vcat length msg)))

(defun close-ssl-socket (socket)
  (usocket:socket-close socket))

(defun close-client (socket)
  (close-ssl-socket socket))

(defun send-message (stream message)
  (write-sequence message stream)
  (finish-output stream))

(defun encode-string (string)
  (let* ((bytes (babel:string-to-octets string))
         (size  (int16->bytes (length bytes))))
    (vcat size bytes)))

(defmethod encode ((object string))
  (encode-string object))

(defmethod encode ((object list))
  (let ((buffer (make-message-buffer (length object))))
    (loop for i from 0 below (length object) do
      (setf (elt buffer i) (elt object i)))
    buffer))

(defmethod encode (object)
  object)

(defmethod decode-string (data)
  (let ((size (bytes->int (subseq data 0 +message-string-length-size+))))
    (babel:octets-to-string (subseq data
                                    +message-string-length-size+
                                    (+ +message-string-length-size+ size))
                            :errorp nil)))

(defun compose-message (message-type tag &rest params)
  (let ((actual-params (reduce #'vcat (mapcar #'encode params))))
    (add-size (reduce #'vcat (list (encode message-type) (encode tag) actual-params)))))

(defun displace-response (response)
  (let ((message-type (subseq response 0 +message-type-size+))
        (message-tag  (subseq response
                              +message-type-size+
                              (+ +message-type-size+
                                 +message-tag-size+)))
        (data         (subseq response
                              (+ +message-type-size+
                                 +message-tag-size+))))
    (values (bytes->int message-type)
            (bytes->int message-tag)
            data)))

(defun make-message-buffer (size)
  (make-array size :element-type +byte-type+))

(defun error-response-p (response)
  (multiple-value-bind (message-type x y)
      (displace-response response)
    (declare (ignore x y))
    (= message-type *rerror*)))

(defun read-message (stream)
  (let ((message-length-buffer  (make-message-buffer +message-length-size+)))
    (read-sequence message-length-buffer stream)
    (let* ((message-length (bytes->int message-length-buffer))
           (buffer         (make-message-buffer (- message-length +message-length-size+))))
      (read-sequence buffer stream)
      (multiple-value-bind (message-type tag data)
          (displace-response buffer)
        (if (error-response-p buffer)
            (error '9p-error
                   :message-type message-type
                   :tag          tag
                   :error-value (decode-string data))
            (values message-type tag data))))))

(defun make-octects (number size)
  (make-instance 'octects :value number :size size))

(defun send-version (stream tag)
  (let ((message (compose-message (make-octects *tversion* 1)
                                  tag
                                  (make-octects *buffer-size* 4)
                                  +version+)))
    (send-message stream message)
    (multiple-value-bind (message-type rtag data)
        (read-message stream)
      (assert (= message-type *rversion*))
      (if (octects= rtag tag)
          (let ((message-size     (bytes->int    (subseq data 0 4)))
                (protocol-version (decode-string (subseq data 4))))
            (if (string= protocol-version +version+)
                (progn
                  (setf *buffer-size* message-size)
                  (values message-size protocol-version))
                (error '9p-error
                       :message-type message-type
                       :tag          tag
                       :error-value  (format nil
                                             "Version mismatch: ~s instead of ~s"
                                             protocol-version
                                             +version+))))
          (error '9p-initialization-error :tag tag :rtag rtag)))))

(defmacro with-new-tag ((tag) &body body)
  `(let ((,tag (next-tag)))
     ,@body))

(defmacro with-new-fid ((fid) &body body)
  `(let ((,fid (next-fid)))
     ,@body))

(defun initialize-session (stream)
  (with-new-tag (tag)
    (multiple-value-bind (buffer-size protocol-version)
        (send-version stream tag)
      (values protocol-version buffer-size))))

(defun decode-quid (data)
  (let ((file-type    (first-elt data))
        (file-version (subseq data 1 4))
        (file-path    (subseq data 1 5)))
    (values file-type
            (bytes->int file-version)
            (bytes->int file-path))))

(defun dummy-callback (message-type data)
  (declare (ignore message-type data)))

(defun dump-callback (message-type data)
  (format t "reply mtype  ~a ~a~%" message-type data))

(defgeneric 9p-attach (stream root &key username callback))

(defmethod 9p-attach (stream (root string)
                      &key
                        (username "nobody")
                        (callback #'dummy-callback))
  (with-new-tag (tag)
    (with-new-fid (root-fid)
      (let* ((message (compose-message (make-octects *tattach* 1)
                                       tag
                                       root-fid
                                       (make-octects +nofid+ 4)
                                       username
                                       root)))
        (append-tag-callback tag callback)
        (send-message stream message)
        root-fid))))

(defun 9p-create (stream parent-dir-fid path
                  &key
                    (callback    #'dummy-callback)
                    (permissions #o640)
                    (mode        +create-for-read-write+))
  "Note: path is relative to root, see attach,
   Also note that successfully creating a file will open it."
  (with-new-tag (tag)
    (let* ((message (compose-message (make-octects *tcreate* 1)
                                     tag
                                     parent-dir-fid
                                     path
                                     (make-octects permissions 4)
                                     (make-octects mode 1))))
      (append-tag-callback tag callback)
      (send-message stream message))))

(defun 9p-open (stream fid
                &key
                  (callback #'dummy-callback)
                  (mode     +create-for-read+))
  "Note before opening you have to 'walk' the file to get the corresponding fid."
  (with-new-tag (tag)
    (let* ((message (compose-message (make-octects *topen* 1)
                                     tag
                                     fid
                                     (make-octects mode 1))))
      (append-tag-callback tag callback)
      (send-message stream message))))

(defgeneric 9p-write (stream fid offset data &key callback))

(defmethod 9p-write (stream fid offset (data vector)
                     &key
                       (callback #'dummy-callback))
  (let* ((data-chunk-num    (floor (/ (length data) *buffer-size*)))
         (data-chunk-length (if (> (length data) *buffer-size*)
                                (* data-chunk-num *buffer-size*)
                                (length data)))
         (remainder         (if (> (length data) *buffer-size*)
                                (- (length data)
                                   (* data-chunk-num *buffer-size*))
                                0)))
    (flet ((write-chunk (chunk chunk-offset)
             (with-new-tag (tag)
               (let* ((message (compose-message (make-octects *twrite* 1)
                                                tag
                                                fid
                                                (make-octects chunk-offset 8)
                                                (make-octects (length chunk) 4)
                                                chunk)))
                 (append-tag-callback tag callback)
                 (send-message stream message)))))
      (loop for i from 0 below (- (length data) remainder) by data-chunk-length do
        (let ((chunk (subseq data i (+ i data-chunk-length))))
          (write-chunk chunk (+ offset i))))
      (when (> remainder 0)
        (write-chunk (subseq data (- (length data) remainder))
                     (+ offset (- (length data) remainder)))))))

(defmethod 9p-write (stream fid offset (data string)
                     &key
                       (callback #'dummy-callback))
  (9p-write stream fid offset (babel:string-to-octets data) :callback callback))

(defun 9p-walk (stream root-fid new-fid new-name &key (callback #'dummy-callback))
  (if (and (numberp new-name)
           (= 0 new-name))
      (%9p-walk-self stream root-fid new-fid :callback callback)
      (with-new-tag (tag)
        (let* ((message (compose-message (make-octects *twalk* 1)
                                         tag
                                         root-fid
                                         new-fid
                                         (make-octects 1 2)
                                         new-name)))
          (append-tag-callback tag callback)
          (send-message stream message)))))

(defun %9p-walk-self (stream root-fid new-fid &key (callback #'dummy-callback))
  (with-new-tag (tag)
    (let* ((message (compose-message (make-octects *twalk* 1)
                                     tag
                                     root-fid
                                     new-fid
                                     (make-octects 0 2))))
      (append-tag-callback tag callback)
      (send-message stream message))))

(defun 9p-remove (stream fid &key (callback #'dummy-callback))
  (with-new-tag (tag)
    (let* ((message (compose-message (make-octects *tremove* 1)
                                     tag
                                     fid)))
      (append-tag-callback tag callback)
      (send-message stream message))))

(defun 9p-clunk (stream fid &key (callback #'dummy-callback))
  (with-new-tag (tag)
    (let* ((message (compose-message (make-octects *tclunk* 1)
                                     tag
                                     fid)))
      (append-tag-callback tag callback)
      (send-message stream message))))

(defun 9p-stat (stream fid &key (callback #'dummy-callback))
  (with-new-tag (tag)
    (let* ((message (compose-message (make-octects *tstat* 1)
                                     tag
                                     fid)))
      (append-tag-callback tag callback)
      (send-message stream message))))

(defun 9p-read (stream fid offset chunk-length &key (callback #'dummy-callback))
  (with-new-tag (tag)
    (let* ((message (compose-message (make-octects *tread* 1)
                                     tag
                                     fid
                                     (make-octects offset 8)
                                     (make-octects chunk-length 4))))
      (append-tag-callback tag callback)
      (send-message stream message))))

(defun decode-read-reply (data &optional (as-string nil))
  (let ((count    (bytes->int (subseq data 0 4)))
        (raw-data (subseq data 4)))
    (values (if as-string
                (babel:octets-to-string raw-data :errorp nil)
                raw-data)
            count)))

(defun encoded-string-offset (decoded-string)
  (+  (length decoded-string)
      +message-string-length-size+))

(defstruct stat
  (entry-size)
  (ktype)
  (kdev)
  (entry-type)
  (version)
  (path)
  (mode)
  (atime)
  (mtime)
  (size)
  (name)
  (user-id)
  (group-id)
  (last-modified-from-id))

(defun decode-rstat (data)
  (flet ((->int (start end)
           (bytes->int (subseq data start end))))
    (let* ((entry-size            (->int  0  2))
           (ktype                 (->int  2  4))
           (kdev                  (->int  4  8))
           (entry-type            (->int  8  9))
           (version               (->int  9 13))
           (path                  (->int 13 21))
           (mode                  (->int 21 25))
           (atime                 (->int 25 29))
           (mtime                 (->int 29 33))
           (size                  (->int 33 41))
           (strings-start         41)
           (name                  (decode-string (subseq data strings-start)))
           (name-offset           (encoded-string-offset name))
           (user-id               (decode-string (subseq data
                                                         (+ strings-start
                                                            name-offset))))
           (user-id-offset        (+ strings-start
                                     (encoded-string-offset user-id)
                                     name-offset))
           (group-id              (decode-string (subseq data user-id-offset)))
           (group-id-offset       (+ user-id-offset
                                     (encoded-string-offset group-id)))
           (last-modified-from-id (decode-string (subseq data group-id-offset))))
      (make-stat :entry-size            entry-size
                 :ktype                 ktype
                 :kdev                  kdev
                 :entry-type            (file-type-number->symbol entry-type)
                 :version               version
                 :path                  path
                 :mode                  mode
                 :atime                 atime
                 :mtime                 mtime
                 :size                  size
                 :name                  name
                 :user-id               user-id
                 :group-id              group-id
                 :last-modified-from-id last-modified-from-id))))

;;; high level routines

(defun read-all-pending-messages-ignoring-errors (stream)
  (handler-bind ((9p-error
                   (lambda (e)
                     (invoke-restart 'ignore-error e))))
    (read-all-pending-message stream)))

(defun clone-fid (stream fid)
  (with-new-fid (saved-fid)
    (9p-walk stream fid saved-fid +nwname-clone+)
    (read-all-pending-message stream)
    saved-fid))

(defun create-directory (stream parent-fid directory-name &key (permissions #o760))
  (with-new-fid (saved-parent-dir)
    (9p-walk stream parent-fid saved-parent-dir +nwname-clone+)
    (read-all-pending-message stream)
    (9p-create stream
               parent-fid
               directory-name
               :permissions (logior +create-dir+ permissions)
               :mode        +create-for-read+)
    (read-all-pending-message stream)
    (with-new-fid (new-dir-fid)
      (9p-walk stream saved-parent-dir new-dir-fid directory-name)
      (read-all-pending-message stream)
      new-dir-fid)))

(defun create-path (stream parent-fid path &key (file-permissions #o640))
  (let ((fs:*directory-sep-regexp* "\\/")
        (path-elements             (remove "/"
                                           (fs:split-path-elements path)
                                           :test #'string=))
        (last-is-dir-p             (cl-ppcre:scan "\\/$" path))
        (last-dir-fid              nil))
    (labels ((%create-dirs (parent-dir-fid path-elements)
               (when path-elements
                 (let ((new-dir-fid (create-directory stream
                                                      parent-dir-fid
                                                      (first path-elements))))
                   (read-all-pending-message stream)
                   (setf last-dir-fid new-dir-fid)
                   (%create-dirs new-dir-fid (rest path-elements))))))
      (%create-dirs parent-fid (misc:safe-all-but-last-elt path-elements))
      (if last-is-dir-p
          (create-directory stream last-dir-fid (last-elt path-elements))
          (progn
            (9p-create stream
                       last-dir-fid
                       (last-elt path-elements)
                       :permissions file-permissions)
            (read-all-pending-messages-ignoring-errors stream)
            last-dir-fid)))))

(defun mount (stream root-path)
  (let ((protocol-version (initialize-session stream))
        (root-fid (9p-attach stream root-path)))
    (read-all-pending-message stream)
    (values root-fid protocol-version)))

(defun open-path (stream root-fid path
                  &key
                    (walk-callback #'dummy-callback)
                    (open-callback #'dummy-callback)
                    (mode          +create-for-read+))
  (let ((fs:*directory-sep-regexp* "\\/")
        (path-elements             (remove "/"
                                           (fs:split-path-elements path)
                                           :test #'string=)))
    (labels ((walk-dirs (path-elements parent-fid)
               (with-new-fid (fid)
                 (if path-elements
                     (progn
                       (9p-walk stream
                                parent-fid
                                fid
                                (first path-elements)
                                :callback walk-callback)
                       (9p-clunk stream parent-fid)
                       (read-all-pending-message stream)
                       (walk-dirs (rest path-elements) fid))
                     parent-fid))))
      (let ((fid (walk-dirs path-elements root-fid)))
        (read-all-pending-message stream)
        (9p-open stream fid :callback open-callback :mode mode)
        (read-all-pending-message stream)
        fid))))

(defun cat-reply-vector (a b)
  (concatenate '(vector (unsigned-byte 8)) a b))

(defun slurp-file (stream root-fid path &key (buffer-size *buffer-size*))
  (let ((res (make-array 0 :element-type +byte-type+ :adjustable nil))
        (fid (open-path stream root-fid path)))
    (labels ((slurp (offset)
               (9p-read stream
                        fid
                        offset
                        buffer-size
                        :callback (lambda (x reply)
                                    (declare (ignore x))
                                    (multiple-value-bind (data count)
                                        (decode-read-reply reply nil)
                                      (setf res (cat-reply-vector res data))
                                      (when (or (= count buffer-size)
                                                (= count *buffer-size*))
                                          (slurp (+ offset count))))))))
      (slurp 0)
      (read-all-pending-message stream)
      res)))

(defun remove-path (stream root-fid path)
  (let* ((saved-root-fid (clone-fid stream root-fid))
         (path-fid       (open-path stream saved-root-fid path)))
    (9p-remove stream path-fid)
    (read-all-pending-message stream)))
