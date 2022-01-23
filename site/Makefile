MANPAGES =	../kamictl/kamictl.8	\
		../kamid/9p.7		\
		../kamid/kamid.8	\
		../kamid/kamid.conf.5	\
		../kamiftp/kamiftp.1

PAGES =		index.gmi install.gmi tutorial.gmi

TITLE_index.gmi =	home
TITLE_install.gmi =	install guide
TITLE_tutorial.gmi =	tutorial

SUBST_GEM =	./subst MANEXT=txt  EXT=gmi
SUBST_WWW =	./subst MANEXT=html EXT=html

.PHONY: all dirs manpages server-www serve-gemini upload clean titles

all: dirs manpages pages
	cp style.css www/

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
	${SUBST_GEM} $p > gemini/$p

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
	rsync --delete -a www/ op:sites/kamid.omarpolo.com
	rsync --delete -a gemini/ op:gemini/kamid.omarpolo.com

clean:
	rm -rf gemini www

titles:
.for p in ${PAGES}
	@printf "%s %s\n" "${p:.gmi=.html}" ${TITLE_${p}:Q}
.endfor
