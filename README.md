# kamid -- 9p file server daemon

kamid is a FREE, easy-to-use and portable implementation of a 9p file
server daemon for UNIX-like systems.


## Building

NB: the -main branch targets only OpenBSD.  To build on other
platforms, use the -portable branch.

	$ majo obj
	$ make
	$ make install

This will install the following commands:

 - kamid, the daemon
 - kamictl, an utility to control the daemon
 - kamiftp, an ftp(1)-like 9p client
 - kamirepl, a low-level 9p client
 - man pages (only installed if building sources from a kamid release
   tarball)

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

The regression suite uses doas(1) because it needs root privileges for
some operatinos.  To run the test suite:

	$ make regress

The regression are written with a custom DSL, called ninepscript.
`contrib/9ps-mode.el` is the major mode for Emacs.

There's another regression suite written in common lisp in
`regress/lisp/9p-test`; it depends on other common lisp libraries
available through quicklisp.  Make sure to have sbcl installed and the
relevant lisp dependencies installed, then run

	$ make HAVE_LISP=yes regress


## License

kamid is released under a BSD-like license.  The bulk of the code is
under the ISC license, but some file are BSD2 or BSD3.

`regress/lisp/9p-test/` (the common lisp regression suite) is released
under the GNU GPLv3+.
