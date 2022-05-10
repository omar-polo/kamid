MANPAGES =	../kamictl/kamictl.8	\
		../kamid/9p.7		\
		../kamid/kamid.8	\
		../kamid/kamid.conf.5	\
		../kamiftp/kamiftp.1	\
		../kamiproxy/kamiproxy.1

PAGES =		index.gmi install.gmi tutorial.gmi caveats.gmi

TITLE_caveats.gmi =	caveats
TITLE_index.gmi =	home
TITLE_install.gmi =	install guide
TITLE_tutorial.gmi =	tutorial

SUBST = ./subst CURRV=0.1 NEXTV=0.2 \
	GH=https://github.com/omar-polo/kamid \
	CURRSIGN=RWTaqCGPkA11Nhvo+uW+U1EKASiVo3IxKrQOqLaEtpYDdw5qLzs4a/9T \
	NEXTSIGN=RWRwqQVDYtY1jTc1lXqyu2e+ZGWgN/h3n/LE/at7pNTuJ1qWsogFvDh8

SUBST_GEM =	${SUBST} MANEXT=txt  EXT=gmi
SUBST_WWW =	${SUBST} MANEXT=html EXT=html

.PHONY: all dirs manpages server-www serve-gemini upload clean titles

all: dirs manpages pages
	cp style.css www/
	convert ../art/tohru.png -resize 300x300 www/tohru.png

dirs:
	mkdir -p gemini
	mkdir -p www

manpages:
.for m in ${MANPAGES}
	./mdoc2html.sh $m www/${m:T}.html
	man -O width=65 -Tutf8 -l $m | col -b > gemini/${m:T}.txt
.endfor

pages:
.for p in ${PAGES}
	grep -v '^<' $p | ${SUBST_GEM} > gemini/$p

	${SUBST_WWW} TITLE=${TITLE_${p}:Q} header.html > www/${p:.gmi=.html}
	${MAKE} titles | ./menu.pl "${p:.gmi=.html}" >> www/${p:.gmi=.html}
	${SUBST_WWW} $p | ./gem2html >> www/${p:.gmi=.html}
	cat footer.html >> www/${p:.gmi=.html}
.endfor

serve-www:
	python3 -m http.server --directory www 8888

serve-gemini:
	gmid -p 1966 ./gemini

upload:
	openrsync --rsync-path=openrsync --del -a www/ antartica:/var/www/kamid.omarpolo.com
	openrsync --rsync-path=openrsync --del -a gemini/ antartica:/var/gemini/kamid.omarpolo.com

clean:
	rm -rf gemini www

titles:
.for p in ${PAGES}
	@printf "%s %s\n" "${p:.gmi=.html}" ${TITLE_${p}:Q}
.endfor
