.PATH:${.CURDIR}/../lib

.include "../kamid-version.mk"

PROG=		kamictl
SRCS=		ctl_parser.c kamictl.c log.c sandbox.c
MAN=		kamictl.8

CPPFLAGS=	-I${.CURDIR}/../lib -I${.CURDIR}/../kamid/ -I${.CURDIR}

LDADD+= -lutil
DPADD+= ${LIBUTIL}

.if ${KAMID_RELEASE} != Yes
NOMAN= Yes
.endif

.include <bsd.prog.mk>
