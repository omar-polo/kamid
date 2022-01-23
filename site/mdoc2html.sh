#!/bin/sh
#
# Copyright (c) 2022 Omar Polo <op@omarpolo.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# usage: mdoc2html.sh src out
#
# converts the manpage `src' to the HTML file `out', tweaking the
# style

set -e

: ${1:?missing input file}
: ${2:?missing output file}

man -Thtml -l "$1" >"$2"

exec ed "$2" <<EOF
/<style>
a
    body {
        max-width: 960px;
        margin: 0 auto;
        padding: 0 10px;
        font-size: 1rem;
    }

    pre {
        overflow: auto;
    }
.
wq
EOF
