#!/bin/sh

#export REGRESS_CERT="$HOME/lisp/kamid.cert"
#export REGRESS_KEY="$HOME/lisp/kamid.key"
#export REGRESS_HOSTNAME="localhost"
#export REGRESS_PORT=10564

sbcl --eval "(require 'asdf)" --eval "(push \"$(pwd)/\" asdf:*central-registry*)" --eval "(asdf:make \"9p-test\")" --eval "(all-tests:run-all-tests)"
