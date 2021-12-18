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

(defpackage :text-utils
  (:use
   :cl)
  (:export
   :strcat))

(defpackage :misc-utils
  (:use :cl)
  (:nicknames :misc)
  (:export
   :safe-all-but-last-elt))

(defpackage :filesystem-utils
  (:use
   :cl
   :alexandria)
  (:nicknames :fs)
  (:export
   :*directory-sep-regexp*
   :getenv
   :cat-parent-dir
   :split-path-elements
   :collect-children
   :prepend-pwd))

(defpackage :9p-client
  (:use
   :cl
   :alexandria)
  (:export
   :+byte-type+
   :+version+
   :+nofid+
   :+create-for-read+
   :+create-for-write+
   :+create-for-read-write+
   :+create-for-exec+
   :+create-dir+
   :+open-truncate+
   :+open-remove-on-clunk+
   :+standard-socket-port+
   :+nwname-clone+
   :*buffer-size*
   :*messages-sent*
   :read-all-pending-message
   :close-client
   :encode-string
   :decode-string
   :encode
   :decode
   :read-message
   :initialize-session
   :with-new-tag
   :with-new-fid
   :dummy-callback
   :dump-callback
   :9p-attach
   :9p-create
   :9p-open
   :9p-write
   :9p-remove
   :9p-clunk
   :9p-stat
   :9p-read
   :9p-walk
   :decode-read-reply
   :decode-rstat
   :read-all-pending-messages-ignoring-errors
   :create-directory
   :create-path
   :mount
   :open-path
   :slurp-file))
