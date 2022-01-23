#!/usr/bin/awk -f
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

BEGIN {
	in_pre = 0;
	in_list = 0;
}

!in_pre && /^###/	{ output("<h3>", substr($0, 4), "</h3>"); next }
!in_pre && /^##/	{ output("<h2>", substr($0, 3), "</h2>"); next }
!in_pre && /^#/		{ output("<h1>", substr($0, 2), "</h1>"); next }
!in_pre && /^>/		{ output("<blockquote>", substr($0, 2), "</blockquote>"); next }
!in_pre && /^\* /	{ output("<li>", substr($0, 2), "</li>"); next }

!in_pre && /^=>/ {
	$0 = substr($0, 3);
	link = $1;
	$1 = "";
	output_link(link, $0);
	next;
}

!in_pre && /^```/ {
	in_pre = 1;
	if (in_list) {
		in_list = 0;
		print("</ul>");
	}
	print "<pre>";
	next
}

in_pre && /^```/	{ in_pre = 0; print "</pre>"; next }
!in_pre			{ output("<p>", $0, "</p>"); next }
in_pre			{ print san($0); next }

END {
	if (in_list)
		print "</ul>"
	if (in_pre)
		print "</pre>"
}

function trim(s) {
	sub("^[ \t]*", "", s);
	return s;
}

function san(s) {
	gsub("&", "\\&amp;", s)
	gsub("<", "\\&lt;", s)
	gsub(">", "\\&gt;", s)
	return s;
}

function output(ot, content, et) {
	content = trim(content);

	if (!in_list && ot == "<li>") {
		in_list = 1;
		print "<ul>";
	}

	if (in_list && ot != "<li>") {
		in_list = 0;
		print "</ul>";
	}

	if (ot == "<p>" && content == "")
		return;

	printf("%s%s%s\n", ot, san(content), et);
}

function output_link(link, content) {
	if (in_list) {
		in_list = 0;
		print "</ul>";
	}

	if (content == "")
		content = link;

	printf("<p><a href=\"%s\">%s</a></p>\n", link, trim(san(content)));
}
