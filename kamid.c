/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
 * Copyright (c) 2018 Florian Obser <florian@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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

#include <sys/socket.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "client.h"
#include "control.h"
#include "kamid.h"
#include "listener.h"
#include "log.h"
#include "sandbox.h"
#include "table.h"
#include "utils.h"

enum kd_process {
	PROC_MAIN,
	PROC_LISTENER,
	PROC_CLIENTCONN,
};

const char	*saved_argv0;
static int	 debug, nflag;
int		 verbose;

__dead void	usage(void);

void		main_sig_handler(int, short, void *);
void		main_dispatch_listener(int, short, void *);
int		main_reload(void);
int		main_imsg_send_config(struct kd_conf *);
void		main_dispatch_listener(int, short, void *);
__dead void	main_shutdown(void);

static pid_t	start_child(enum kd_process, int, int, int);

struct kd_conf		*main_conf;
static struct imsgev	*iev_listener;
const char		*conffile;
pid_t			 listener_pid;
uint32_t		 cmd_opts;

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-dnv] [-f file] [-s socket]\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	struct event	 ev_sigint, ev_sigterm, ev_sighup;
	int		 ch;
	int		 listener_flag = 0, client_flag = 0;
	int		 pipe_main2listener[2];
	int		 control_fd;
	const char	*csock;

	conffile = KD_CONF_FILE;
	csock = KD_SOCKET;

	log_init(1, LOG_DAEMON);	/* Log to stderr until deamonized. */
	log_setverbose(1);

	saved_argv0 = argv[0];
	if (saved_argv0 == NULL)
		saved_argv0 = "kamid";

	while ((ch = getopt(argc, argv, "D:df:nsT:v")) != -1) {
		switch (ch) {
		case 'D':
			if (cmdline_symset(optarg) == -1)
                                log_warnx("could not parse macro definition %s",
					optarg);
			break;
		case 'd':
			debug = 1;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			nflag = 1;
			break;
		case 's':
			csock = optarg;
			break;
		case 'T':
			switch (*optarg) {
			case 'c':
				client_flag = 1;
				break;
			case 'l':
				listener_flag = 1;
				break;
			default:
				fatalx("invalid process spec %c", *optarg);
			}
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc > 0 || (listener_flag && client_flag))
		usage();

	if (client_flag)
		client(debug, verbose);
	else if (listener_flag)
		listener(debug, verbose);

	if ((main_conf = parse_config(conffile)) == NULL)
		exit(1);

	if (nflag) {
		fprintf(stderr, "configuration OK\n");
		exit(0);
	}

	/* Check for root privileges. */
        if (geteuid())
                fatalx("need root privileges");

	/* Check for assigned daemon user. */
	if (getpwnam(KD_USER) == NULL)
		fatalx("unknown user %s", KD_USER);

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if (!debug)
		daemon(1, 0);

	log_info("startup");

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_main2listener) == -1)
		fatal("main2listener socketpair");

	/* Start children. */
	listener_pid = start_child(PROC_LISTENER, pipe_main2listener[1],
	    debug, verbose);

	log_procinit("main");

	event_init();

	/* Setup signal handler */
	signal_set(&ev_sigint, SIGINT, main_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, main_sig_handler, NULL);
	signal_set(&ev_sighup, SIGHUP, main_sig_handler, NULL);

	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sighup, NULL);

	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	if ((iev_listener = malloc(sizeof(*iev_listener))) == NULL)
		fatal(NULL);
	imsg_init(&iev_listener->ibuf, pipe_main2listener[0]);
	iev_listener->handler = main_dispatch_listener;

	/* Setup event handlers for pipes to listener. */
	iev_listener->events = EV_READ;
	event_set(&iev_listener->ev, iev_listener->ibuf.fd,
	    iev_listener->events, iev_listener->handler, iev_listener);
	event_add(&iev_listener->ev, NULL);

	if ((control_fd = control_init(csock)) == -1)
		fatalx("control socket setup failed");

	main_imsg_compose_listener(IMSG_CONTROLFD, control_fd, 0,
	    NULL, 0);
	main_imsg_send_config(main_conf);

	sandbox_main();

	event_dispatch();

	main_shutdown();
	return 0;
}

void
main_sig_handler(int sig, short event, void *arg)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGTERM:
	case SIGINT:
		main_shutdown();
		break;
	case SIGHUP:
		if (main_reload() == -1)
			log_warnx("configuration reload failed");
		else
			log_debug("configuration reloaded");
		break;
	default:
		fatalx("unexpected signal %d", sig);
	}
}

static inline struct table *
auth_table_by_id(uint32_t id)
{
	struct kd_listen_conf *listen;

	STAILQ_FOREACH(listen, &main_conf->listen_head, entry) {
		if (listen->id == id)
			return listen->auth_table;
	}

	return NULL;
}

static inline struct table *
virtual_table_by_id(uint32_t id)
{
	struct kd_listen_conf *listen;

	STAILQ_FOREACH(listen, &main_conf->listen_head, entry) {
		if (listen->id == id)
			return listen->virtual_table;
	}

	return NULL;
}

static inline struct table *
userdata_table_by_id(uint32_t id)
{
	struct kd_listen_conf *listen;

	STAILQ_FOREACH(listen, &main_conf->listen_head, entry) {
		if (listen->id == id)
			return listen->userdata_table;
	}

	return NULL;
}

static inline void
do_auth_tls(struct imsg *imsg)
{
	char *username = NULL, *user = NULL, *home = NULL, *local_user;
	struct passwd *pw;
	struct table *auth, *virt, *userdata;
	struct kd_auth_req kauth;
	int p[2], free_home = 1;

	if (sizeof(kauth) != IMSG_DATA_SIZE(*imsg))
		fatal("wrong size for IMSG_AUTH_TLS: "
		    "got %lu; want %lu", IMSG_DATA_SIZE(*imsg),
		    sizeof(kauth));
	memcpy(&kauth, imsg->data, sizeof(kauth));

	if (memmem(kauth.hash, sizeof(kauth.hash), "", 1) == NULL)
                fatal("non NUL-terminated hash received");

	log_debug("tls id=%u hash=%s", kauth.listen_id, kauth.hash);

	if ((auth = auth_table_by_id(kauth.listen_id)) == NULL)
		fatal("request for invalid listener id %d", imsg->hdr.pid);

	virt = virtual_table_by_id(kauth.listen_id);
	userdata = userdata_table_by_id(kauth.listen_id);

	if (table_lookup(auth, kauth.hash, &username) == -1) {
		log_warnx("login failed for hash %s", kauth.hash);
		goto err;
	}

	if (virt != NULL && table_lookup(virt, username, &user) == -1) {
		log_warnx("virtual lookup failed for user %s", username);
		goto err;
	}

	/* the local user */
	local_user = user != NULL ? user : username;

	if (user != NULL)
		log_debug("virtual user %s matched local user %s",
		    username, user);
	else
		log_debug("matched local user %s", username);

	if (userdata != NULL && table_lookup(userdata, username, &home)
	    == -1) {
		log_warnx("userdata lookup failed for user %s", username);
		goto err;
	} else if (userdata == NULL) {
		if ((pw = getpwnam(local_user)) == NULL) {
			log_warnx("getpwnam(%s) failed", local_user);
			goto err;
		}

		free_home = 0;
		home = pw->pw_dir;
	}

	if (user != NULL)
		log_debug("matched home %s for virtual user %s",
		    home, username);
	else
		log_debug("matched home %s for local user %s",
		    home, username);

	if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,
	    PF_UNSPEC, p) == -1)
		fatal("socketpair");

	start_child(PROC_CLIENTCONN, p[1], debug, verbose);

	main_imsg_compose_listener(IMSG_AUTH, p[0], imsg->hdr.peerid,
	    local_user, strlen(local_user)+1);
	main_imsg_compose_listener(IMSG_AUTH_DIR, -1, imsg->hdr.peerid,
	    home, strlen(home)+1);

	free(username);
	free(user);
	if (free_home)
		free(home);
	return;

err:
	free(username);
	free(user);
	if (free_home)
		free(home);
	main_imsg_compose_listener(IMSG_AUTH, -1, imsg->hdr.peerid,
	    NULL, 0);
}

void
main_dispatch_listener(int fd, short event, void *d)
{
	struct imsgev	*iev = d;
	struct imsgbuf	*ibuf;
	struct imsg	 imsg;
	ssize_t		 n;
	int		 shut = 0;

	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("imsg_get");
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_AUTH_TLS:
			do_auth_tls(&imsg);
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__,
				imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead.  Remove its event handler. */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

int
main_reload(void)
{
	struct kd_conf *xconf;

	if ((xconf = parse_config(conffile)) == NULL)
		return -1;

	if (main_imsg_send_config(xconf) == -1)
		return -1;

	merge_config(main_conf, xconf);

	return 0;
}

static inline int
make_socket_for(struct kd_listen_conf *l)
{
	struct sockaddr_in	addr4;
	size_t			len;
	int			fd, v;

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(l->port);
	addr4.sin_addr.s_addr = INADDR_ANY;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		fatal("socket");

	v = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) == -1)
		fatal("setsockopt(SO_REUSEADDR)");

	v = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v)) == -1)
		fatal("setsockopt(SO_REUSEPORT)");

	len = sizeof(addr4);
	if (bind(fd, (struct sockaddr *)&addr4, len) == -1)
		fatal("bind(%s, %d)", l->iface, l->port);

	if (listen(fd, 16) == -1)
		fatal("l(%s, %d)", l->iface, l->port);

	return fd;
}

int
main_imsg_send_config(struct kd_conf *xconf)
{
	struct kd_pki_conf *pki;
	struct kd_listen_conf *listen;

#define SEND(type, fd, data, len) do {					\
		if (main_imsg_compose_listener(type, fd, 0, data, len)	\
		    == -1)						\
			return -1;					\
	} while (0)

	/* Send fixed part of config to children. */
	SEND(IMSG_RECONF_CONF, -1, xconf, sizeof(*xconf));

	STAILQ_FOREACH(pki, &xconf->pki_head, entry) {
		log_debug("sending pki %s", pki->name);
		SEND(IMSG_RECONF_PKI, -1, pki->name, sizeof(pki->name));
		SEND(IMSG_RECONF_PKI_CERT, -1, pki->cert, pki->certlen);
		SEND(IMSG_RECONF_PKI_KEY, -1, pki->key, pki->keylen);
	}

	STAILQ_FOREACH(listen, &xconf->listen_head, entry) {
		log_debug("sending listen on port %d", listen->port);
		SEND(IMSG_RECONF_LISTEN, make_socket_for(listen), listen,
		    sizeof(*listen));
	}

	SEND(IMSG_RECONF_END, -1, NULL, 0);
	return 0;

#undef SEND
}

void
merge_config(struct kd_conf *conf, struct kd_conf *xconf)
{
	/* do stuff... */

	free(xconf);
}

struct kd_conf *
config_new_empty(void)
{
	struct kd_conf *xconf;

	if ((xconf = calloc(1, sizeof(*xconf))) == NULL)
		fatal(NULL);

	/* set default values */

	return xconf;
}

void
config_clear(struct kd_conf *conf)
{
	struct kd_conf *xconf;

	/* Merge current config with an empty one. */
	xconf = config_new_empty();
	merge_config(conf, xconf);

	free(conf);
}

__dead void
main_shutdown(void)
{
	pid_t	pid;
	int	status;

	/* close pipes. */
        config_clear(main_conf);

	log_debug("waiting for children to terminate");
	do {
		pid = wait(&status);
		if (pid == -1) {
			if (errno != EINTR && errno != ECHILD)
				fatal("wait");
		} else if (WIFSIGNALED(status))
			log_warnx("%s terminated; signal %d",
			    (pid == listener_pid) ? "logger" : "clientconn",
			    WTERMSIG(status));
	} while (pid != -1 || (pid == -1 && errno == EINTR));

	free(iev_listener);

	log_info("terminating");
	exit(0);
}

static pid_t
start_child(enum kd_process p, int fd, int debug, int verbose)
{
	const char	*argv[5];
	int		 argc = 0;
	pid_t		 pid;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(fd);
		return pid;
	}

	if (fd != 3) {
		if (dup2(fd, 3) == -1)
			fatal("cannot setup imsg fd");
	} else if (fcntl(F_SETFD, 0) == -1)
		fatal("cannot setup imsg fd");

	argv[argc++] = saved_argv0;
	switch (p) {
	case PROC_MAIN:
		fatalx("Can not start main process");
	case PROC_LISTENER:
		argv[argc++] = "-Tl";
		break;
	case PROC_CLIENTCONN:
		argv[argc++] = "-Tc";
		break;
	}
	if (debug)
		argv[argc++] = "-d";
	if (verbose)
		argv[argc++] = "-v";
	argv[argc++] = NULL;

	/* really? */
	execvp(saved_argv0, (char *const *)argv);
	fatal("execvp");
}

int
main_imsg_compose_listener(int type, int fd, uint32_t peerid,
    const void *data, uint16_t datalen)
{
	if (iev_listener)
		return imsg_compose_event(iev_listener, type, peerid, 0,
		    fd, data, datalen);
	else
		return -1;
}
