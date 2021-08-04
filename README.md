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
pki localhost cert "/path/to/localhost.crt"
pki localhost key  "/path/to/localhost.key"

table users { "SHA256:..." => "op" }

# should be <users> but there's currently a bug in the parser so...
listen on localhost port 1337 tls pki localhost auth < users >
```


## Testing

`ninepscript` is a custom DSL used to tests kamid.  It's a fairly
simple scripting language built to simulate various scenarios.


## License

kamid is released under a BSD-like license.  The bulk of the code is
under the ISC license, but some file are BSD2 or BSD3.
