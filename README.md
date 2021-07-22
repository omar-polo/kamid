# kamid -- 9p file server daemon

kamid is a FREE implementation of a 9p file server daemon for
UNIX-like systems.


## Building

kamid depends on libtls, libevent and yacc/GNU bison.  To build from a
release tarball:

	./configure
	make
	sudo make install # eventually

to build from a git checkout:

	./bootstrap
	./configure
	make


## License

kamid is released under a BSD-like license.  The bulk of the code is
under the ISC license, but some file are BSD2 or BSD3.
