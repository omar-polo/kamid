REGRESS_TARGETS=suite
NOOBJ=Yes

suite:
	${SUDO} ${PREFIX}/bin/ninepscript -r ${.CURDIR}/../root *-suite.9ps

.include <bsd.regress.mk>
