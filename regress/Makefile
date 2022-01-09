HAVE_LISP ?= No

SUBDIR = ninepscript

.if ${HAVE_LISP:L} == yes
SUBDIR += lisp
.endif

.include <bsd.subdir.mk>
