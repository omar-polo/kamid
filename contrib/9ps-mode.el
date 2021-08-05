;;; 9ps-mode.el --- major mode for editing ninepscripts  -*- lexical-binding: t; -*-

;; Copyright (C) 2021  Omar Polo

;; Author: Omar Polo <op@omarpolo.com>
;; Keywords: languages

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; Major mode for editing ninepscripts, the kamid regression tests.

;;; Code:
(eval-when-compile
  (require 'rx))

(defconst 9ps-keywords
  '("assert" "const" "dir" "include" "proc" "str" "testing"
    "u8" "u16" "u32"))

(defconst 9ps--font-lock-keywords
  (list
   (rx-to-string
    `(: (or ,@9ps-keywords))))
  "`9ps-mode' constant keywords.")

(defconst 9ps--font-lock-comments
  "")

(defvar 9ps-mode-syntax-table
  (let ((st (make-syntax-table)))
    (modify-syntax-entry ?\{ "(}" st)
    (modify-syntax-entry ?\} "){" st)
    (modify-syntax-entry ?\( "()" st)
    ;; - and _ are word constituent
    (modify-syntax-entry ?_ "w" st)
    (modify-syntax-entry ?- "w" st)
    ;; both single and double quotes makes strings
    (modify-syntax-entry ?\" "\"" st)
    (modify-syntax-entry ?' "'" st)
    ;; one day we'll have escaping (maybe)
    (modify-syntax-entry ?\\ "\\" st)
    ;; add comments.  is this the correct way?
    (modify-syntax-entry ?# "<" st)
    (modify-syntax-entry ?\n ">" st)
    st))

(defun 9ps-indent-line ()
  "Indent current line."
  (let (indent
        boi-p                           ;begin of indent
        move-eol-p
        (point (point)))
    (save-excursion
      (back-to-indentation)
      (setq indent (car (syntax-ppss))
            boi-p (= point (point)))
      ;; don't indent empty lines, but only when they don't have the
      ;; cursor in it.
      (when (and (eq (char-after) ?\n)
                 (not boi-p))
        (setq indent 0))
      ;; check whether we want to move to the end of line
      (when (and (eq (char-after) ?\n)
                 boi-p)
        (setq move-eol-p t))
      ;; decrement the indent if the first character on the line is a
      ;; closer.
      (when (or (eq (char-after) ?\))
                (eq (char-after) ?\}))
        (setq indent (1- indent)))
      ;; indent the line
      (delete-region (line-beginning-position)
                     (point))
      (indent-to (* tab-width indent)))
    (when move-eol-p
      (move-end-of-line nil))))

;;;###autoload
(define-derived-mode 9ps-mode prog-mode "9ps"
  "Major mode for ninepscript files."
  (setq font-lock-defaults '((9ps--font-lock-keywords)))
  (setq-local comment-start "#")
  (setq-local comment-start-skip "#+[\t ]*")
  (setq-local indent-line-function #'9ps-indent-line))

;;;###autoload
(add-to-list 'auto-mode-alist '("\\.9ps" . 9ps-mode))

(provide '9ps-mode)
;;; 9ps-mode.el ends here
