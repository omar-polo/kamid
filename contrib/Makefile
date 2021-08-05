EMACS = emacs

.PHONY: compile clean

compile: 9ps-mode.elc

9ps-mode.elc: 9ps-mode.el

.SUFFIXES: .el .elc
.el.elc:
	$(EMACS) -Q --batch -L . -f batch-byte-compile $<

clean:
	rm -f *.elc
