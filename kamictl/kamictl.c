/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "compat.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "ctl_parser.h"
#include "kamid.h"
#include "log.h"

__dead void	 usage(void);

struct imsgbuf	*ibuf;

__dead void
usage(void)
{
	/*
	 * XXX: this will print `kamid' if compat/getprogname.c is
	 * used.
	 */
	fprintf(stderr, "usage: %s [-s socket] command [argument ...]\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	struct sockaddr_un	 sun;
	struct parse_result	*res;
	struct imsg		 imsg;
	int			 ctl_sock;
	int			 done = 0;
	int			 n, verbose = 0;
	int			 ch;
	const char		*sockname;

	log_init(1, LOG_DAEMON); /* Log to stderr. */

	sockname = KD_SOCKET;
	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			sockname = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* parse command line */
	if ((res = parse(argc, argv)) == NULL)
		exit(1);

	/* connect to control socket */
	if ((ctl_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, sockname, sizeof(sun.sun_path));

	if (connect(ctl_sock, (struct sockaddr*)&sun, sizeof(sun)) == -1)
		err(1, "connect: %s", sockname);

#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif

	if ((ibuf = calloc(1, sizeof(*ibuf))) == NULL)
		err(1, NULL);
	imsg_init(ibuf, ctl_sock);
	done = 0;

	/* process user request */
	switch (res->action) {
	case LOG_VERBOSE:
		verbose = 1;
		/* fallthrough */
	case LOG_BRIEF:
		imsg_compose(ibuf, IMSG_CTL_LOG_VERBOSE, 0, 0, -1,
		    &verbose, sizeof(verbose));
		puts("logging request sent.");
		done = 1;
		break;
	case RELOAD:
		imsg_compose(ibuf, IMSG_CTL_RELOAD, 0, 0, -1, NULL, 0);
		puts("reload request sent.");
		done = 1;
		break;
	case DEBUG:
		imsg_compose(ibuf, IMSG_CTL_DEBUG, 0, getpid(), -1, NULL, 0);
		break;
	default:
		usage();
	}

	if (imsg_flush(ibuf) == -1)
		err(1, "imsg_flush");

	while (!done) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			errx(1, "write error");
		if (n == 0)
			errx(0, "pipe closed");

		while (!done) {
			if ((n = imsg_get(ibuf, &imsg)) == -1)
				errx(1, "imsg_get error");
			if (n == 0)
				break;

			switch (res->action) {
			case DEBUG: {
				struct kd_debug_info d;

				if (imsg.hdr.type == IMSG_CTL_DEBUG_END) {
					done = 1;
					break;
				}

				if (imsg.hdr.type != IMSG_CTL_DEBUG_BACK ||
				    IMSG_DATA_SIZE(imsg) != sizeof(d))
					errx(1, "got invalid reply (%d)",
					    imsg.hdr.type);

				memcpy(&d, imsg.data, sizeof(d));
				if (d.path[sizeof(d.path)-1] != '\0')
					errx(1, "got invalid reply");

				printf("%"PRIu32"\t%"PRIu32"\t%s\n",
				    d.client_id, d.fid, d.path);
				break;
			}
			default:
				break;
			}
			imsg_free(&imsg);
		}
	}
	close(ctl_sock);
	free(ibuf);

	return 0;
}
