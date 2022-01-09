CPPFLAGS += -DKAMID_VERSION="\"${KAMID_VERSION}\""

.if ${KAMID_RELEASE} == Yes
PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/bin
MANDIR ?= ${PREFIX}/man/man
.else
CFLAGS += -Werror -Wall -Wmissing-prototypes -Wstrict-prototypes
CFLAGS += -Wwrite-strings -Wno-unused-parameter
PREFIX ?= ${HOME}
BINDIR ?= ${PREFIX}/bin

BINOWN ?= ${USER}
.if !defined(BINGRP)
BINGRP != id -g -n
.endif
.endif
