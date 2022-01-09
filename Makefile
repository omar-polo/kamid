SUBDIR = 
SUBDIR += kamictl
SUBDIR += kamid
SUBDIR += kamiftp
SUBDIR += kamirepl
SUBDIR += ninepscript

.if make(regress) || make(obj) || make(clean) || make(release)
SUBDIR += regress
.endif

.if make(tags) || make(cleandir)
SUBDIR += lib
.endif

.include "kamid-version.mk"

release: clean
	sed -i -e 's/_RELEASE=No/_RELEASE=Yes/' kamid-version.mk
	${MAKE} dist
	sed -i -e 's/_RELEASE=Yes/_RELEASE=No/' kamid-version.mk

dist: clean
	mkdir /tmp/kamid-${KAMID_VERSION}
	pax -rw * /tmp/kamid-${KAMID_VERSION}
	find /tmp/kamid-${KAMID_VERSION} -name obj -type d -delete
	tar -C /tmp -zcf kamid-${KAMID_VERSION}.tar.gz kamid-${KAMID_VERSION}
	rm -rf /tmp/kamid-${KAMID_VERSION}

.include <bsd.subdir.mk>
