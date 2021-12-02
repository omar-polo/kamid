#!/bin/sh
#
# Test runner for kamid

set -e

cd regress

./../ninepscript "$@" *-suite.9ps
