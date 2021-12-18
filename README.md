# kamid -- 9p file server daemon

kamid is a FREE, easy-to-use and portable implementation of a 9p file
server daemon for UNIX-like systems.


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


## Usage

In order to run, a `_kamid` user must exists.  The home directory of
`_kamid` should be `/var/empty` or similar.  A configuration file is
also needed.  kamid must be started with root privileges.

A sample configuration file:

```
pki localhost cert "/etc/ssl/localhost.crt"
pki localhost key  "/etc/ssl/private/localhost.key"

table users { "SHA256:..." => "op" }

listen on localhost port 1337 tls pki localhost auth <users>
```


## Testing

The regression suite needs to be run with root privileges, since it
has to spawn a subprocess that needs to `chroot(2)` itself.  To run
the tests, issue

	$ make ninepscript && sudo ./run-tests.sh

The regression uses a custom DSL, `ninepscript`, to run the tests.
See `regress/sample.9ps` for an example of the grammar.
`contrib/9ps-mode.el` is the major mode for Emacs.


## License

kamid is released under a BSD-like license.  The bulk of the code is
under the ISC license, but some file are BSD2 or BSD3.

`regress/lisp/9p-test/` (the common lisp regression suite) is released
under the GNU GPLv3+.
