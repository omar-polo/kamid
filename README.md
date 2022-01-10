# kamid -- 9p file server daemon

kamid is a FREE, easy-to-use and portable implementation of a 9p file
server daemon for UNIX-like systems.


## Building

When building from a release tarball:

	$ ./configure
	$ make
	# make install # eventually

to build from a git checkout:

	$ ./autogen.sh
	$ ./configure
	$ make


## Usage

In order to run, the `_kamid` user must exists, with `/var/empty` as
home directory.  A valid configuration file `/etc/kamid.conf` is also
needed.  kamid must be started with root privileges.

A sample configuration file:

```
# /etc/kamid.conf
pki localhost cert "/etc/ssl/localhost.crt"
pki localhost key  "/etc/ssl/private/localhost.key"

table users { "SHA256:..." => "op" }

listen on localhost port 1337 tls pki localhost auth <users>
```


## Testing

The regression suite uses sudo (or doas) because it needs root
privileges for certain operations.  To run the test suite:

	$ make test

The regression are written using a custom DSL, ninepscript.
`contrib/9ps-mode.el` is the major mode for Emacs.

There's another regression suite written in common lisp in
`regress/lisp/9p-test`; it depends on other lisp libraries available
through quicklisp.  Make sure to have sbcl and the relevant lisp
dependencies installed, then run

	$ make HAVE_LISP=yes test


## License

kamid is released under a BSD-like license.  The bulk of the code is
under the ISC license, but some file are BSD2 or BSD3.

`regress/lisp/9p-test/` (the common lisp regression suite) is released
under the GNU GPLv3+.
