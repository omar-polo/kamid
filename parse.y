/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
 * Copyright (c) 2018 Florian Obser <florian@openbsd.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2004 Ryan McBride <mcbride@openbsd.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
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

%{
#include "compat.h"

#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "log.h"
#include "kamid.h"
#include "table.h"
#include "utils.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	size_t	 		 ungetpos;
	size_t			 ungetsize;
	u_char			*ungetbuf;
	int			 eof_reached;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 igetc(void);
int		 lgetc(int);
void		 lungetc(int);
int		 findeol(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};

int	 symset(const char *, const char *, int);
char	*symget(const char *);

void	 clear_config(struct kd_conf *xconf);

static void		 add_table(const char *, const char *, const char *);
static struct table	*findtable(const char *name);
static void		 add_cert(const char *, const char *);
static void		 add_key(const char *, const char *);
static struct kd_listen_conf *listen_new(void);

static uint32_t			 counter;
static struct table		*table;
static struct kd_listen_conf	*listener;
static struct kd_conf		*conf;
static int			 errors;

typedef struct {
	union {
		int64_t		 number;
		char		*string;
		struct table	*table;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	AUTH
%token	CERT
%token	ERROR
%token	INCLUDE
%token	KEY
%token	LISTEN
%token	NO
%token	ON
%token	PKI PORT
%token	TABLE TLS
%token	YES

%token	<v.string>	STRING
%token	<v.number>	NUMBER
%type	<v.number>	yesno
%type	<v.string>	string
%type	<v.table>	tableref

%%

grammar		: /* empty */
		| grammar include '\n'
		| grammar '\n'
		| grammar table '\n'
		| grammar pki '\n'
		| grammar listen '\n'
		| grammar varset '\n'
		| grammar error '\n'		{ file->errors++; }
		;

include		: INCLUDE STRING		{
			struct file	*nfile;

			if ((nfile = pushfile($2, 0)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
		}
		;

string		: string STRING	{
			if (asprintf(&$$, "%s %s", $1, $2) == -1) {
				free($1);
				free($2);
				yyerror("string: asprintf");
				YYERROR;
			}
			free($1);
			free($2);
		}
		| STRING
		;

yesno		: YES	{ $$ = 1; }
		| NO	{ $$ = 0; }
		;

optnl		: '\n' optnl		/* zero or more newlines */
		| /*empty*/
		;

nl		: '\n' optnl		/* one or more newlines */
		;

arrow		: '=' '>' ;

comma		: ',' optnl
		| nl
		;

varset		: STRING '=' string		{
			char *s = $1;
			if (verbose)
				printf("%s = \"%s\"\n", $1, $3);
			while (*s++) {
				if (isspace((unsigned char)*s)) {
					yyerror("macro name cannot contain "
					    "whitespace");
					free($1);
					free($3);
					YYERROR;
				}
			}
			if (symset($1, $3, 0) == -1)
				fatal("cannot store variable");
			free($1);
			free($3);
		}
		;

pki		: PKI STRING CERT STRING { add_cert($2, $4); }
		| PKI STRING KEY STRING  { add_key($2, $4); }
		;

table_kp	: string arrow string {
			if (table_add(table, $1, $3) == -1)
				yyerror("can't add to table %s",
				    table->t_name);
			free($1);
			free($3);
		}
		;

table_kps	: table_kp
		| table_kp comma table_kps
		;

stringel	: STRING {
			if (table_add(table, $1, NULL) == -1)
				yyerror("can't add to table %s",
				    table->t_name);
			free($1);
		}
		;

string_list	: stringel
		| stringel comma string_list
		;

table_vals	: table_kps
		| string_list
		;

table		: TABLE STRING STRING {
			char *p;

			if ((p = strchr($3, ':')) == NULL) {
				yyerror("invalid table %s", $2);
				YYERROR;
			}

			*p = '\0';
			add_table($2, $3, p+1);
			free($2);
			free($3);
		}
		| TABLE STRING {
			add_table($2, "static", NULL);
		} '{' table_vals '}' {
			table = NULL;
		}
		;

tableref	: '<' STRING '>' {
			struct table *t;

			t = findtable($2);
			free($2);
			if (t == NULL)
				YYERROR;
			$$ = t;
		}
		;

listen		: LISTEN { listener = listen_new(); }
		listen_opts {
			if (listener->auth_table == NULL)
				yyerror("missing auth table");
			if (!(listener->flags & L_TLS))
				yyerror("can't define a non-tls listener");

			listener = NULL;
		};

listen_opts	: listen_opt
		| listen_opt listen_opts
		;

listen_opt	: ON STRING PORT NUMBER	{
			if (*listener->iface != '\0')
				yyerror("listen address and port already"
				    " defined");
			strlcpy(listener->iface, $2, sizeof(listener->iface));
			listener->port = $4;
		}
		| TLS PKI STRING {
			if (*listener->pki != '\0')
				yyerror("listen tls pki already defined");
			listener->flags |= L_TLS;
			strlcpy(listener->pki, $3, sizeof(listener->pki));
		}
		| AUTH tableref {
			if (listener->auth_table != NULL)
				yyerror("listen auth already defined");
			listener->auth_table = $2;
		}
		;

%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		fatalx("yyerror vasprintf");
	va_end(ap);
	logit(LOG_CRIT, "%s:%d: %s", file->name, yylval.lineno, msg);
	free(msg);
	return 0;
}

int
kw_cmp(const void *k, const void *e)
{
	return strcmp(k, ((const struct keywords *)e)->k_name);
}

int
lookup(char *s)
{
	/* This has to be sorted always. */
	static const struct keywords keywords[] = {
		{"auth",		AUTH},
		{"cert",		CERT},
		{"include",		INCLUDE},
		{"key",			KEY},
		{"listen",		LISTEN},
		{"no",			NO},
		{"on",			ON},
		{"pki",			PKI},
		{"port",		PORT},
		{"table",		TABLE},
		{"tls",			TLS},
		{"yes",			YES},
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return p->k_val;
	else
		return STRING;
}

#define START_EXPAND	1
#define DONE_EXPAND	2

static int	expanding;

int
igetc(void)
{
	int	c;

	while (1) {
		if (file->ungetpos > 0)
			c = file->ungetbuf[--file->ungetpos];
		else
			c = getc(file->stream);

		if (c == START_EXPAND)
			expanding = 1;
		else if (c == DONE_EXPAND)
			expanding = 0;
		else
			break;
	}
	return c;
}

int
lgetc(int quotec)
{
	int		c, next;

	if (quotec) {
		if ((c = igetc()) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return EOF;
			return quotec;
		}
		return c;
	}

	while ((c = igetc()) == '\\') {
		next = igetc();
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	if (c == EOF) {
		/*
		 * Fake EOL when hit EOF for the first time. This gets line
		 * count right if last line in included file is syntactically
		 * invalid and has no newline.
		 */
		if (file->eof_reached == 0) {
			file->eof_reached = 1;
			return '\n';
		}
		while (c == EOF) {
			if (file == topfile || popfile() == EOF)
				return EOF;
			c = igetc();
		}
	}
	return c;
}

void
lungetc(int c)
{
	if (c == EOF)
		return;

	if (file->ungetpos >= file->ungetsize) {
		void *p = reallocarray(file->ungetbuf, file->ungetsize, 2);
		if (p == NULL)
			err(1, "lungetc");
		file->ungetbuf = p;
		file->ungetsize *= 2;
	}
	file->ungetbuf[file->ungetpos++] = c;
}

int
findeol(void)
{
	int	c;

	/* Skip to either EOF or the first real EOL. */
	while (1) {
		c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return ERROR;
}

#if 0
int my_yylex(void);

int
yylex(void)
{
	int x;

	switch (x = my_yylex()) {
	case AUTH:
		puts("auth");
		break;
	case CERT:
		puts("cert");
		break;
	case ERROR:
		puts("error");
		break;
	case INCLUDE:
		puts("include");
		break;
	case KEY:
		puts("key");
		break;
	case LISTEN:
		puts("listen");
		break;
	case NO:
		puts("no");
		break;
	case ON:
		puts("on");
		break;
	case PKI:
		puts("pki");
		break;
	case PORT:
		puts("port");
		break;
	case TABLE:
		puts("table");
		break;
	case TLS:
		puts("tls");
		break;
	case YES:
		puts("yes");
		break;
	case STRING:
		printf("string \"%s\"\n", yylval.v.string);
		break;
	case NUMBER:
		printf("number %"PRIi64"\n", yylval.v.number);
	default:
		printf("character ");
		if (x == '\n')
			printf("\\n");
		else
			printf("%c", x);
		printf(" [0x%x]", x);
		printf("\n");
		break;
	}

	return x;
}

int
my_yylex(void)
#else
int
yylex(void)
#endif
{
	unsigned char	 buf[8096];
	unsigned char	*p, *val;
	int		 quotec, next, c;
	int		 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && !expanding) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return 0;

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return findeol();
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return findeol();
		}
		p = val + strlen(val) - 1;
		lungetc(DONE_EXPAND);
		while (p >= val) {
			lungetc(*p);
			p--;
		}
		lungetc(START_EXPAND);
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return 0;
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || next == ' ' ||
				    next == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return findeol();
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return findeol();
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "yylex: strdup");
		return STRING;
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return findeol();
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return findeol();
			}
			return NUMBER;
		} else {
nodigits:
			while (p > buf + 1)
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return c;
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && \
	x != '!' && x != '=' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_') {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return findeol();
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "yylex: strdup");
		return token;
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return 0;
	return c;
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		log_warn("cannot stat %s", fname);
		return -1;
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		log_warnx("%s: owner not root or current user", fname);
		return -1;
	}
	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
		log_warnx("%s: group writable or world read/writable", fname);
		return -1;
	}
	return 0;
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("calloc");
		return NULL;
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn("strdup");
		free(nfile);
		return NULL;
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("%s", nfile->name);
		free(nfile->name);
		free(nfile);
		return NULL;
	} else if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return NULL;
	}
	nfile->lineno = TAILQ_EMPTY(&files) ? 1 : 0;
	nfile->ungetsize = 16;
	nfile->ungetbuf = malloc(nfile->ungetsize);
	if (nfile->ungetbuf == NULL) {
		log_warn("malloc");
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return NULL;
	}
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return nfile;
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file->ungetbuf);
	free(file);
	file = prev;
	return file ? 0 : EOF;
}

struct kd_conf *
parse_config(const char *filename)
{
	struct sym		*sym, *next;

	counter = 0;
	conf = config_new_empty();

	file = pushfile(filename, 0);
	if (file == NULL) {
		free(conf);
		return NULL;
	}
	topfile = file;

	yyparse();
	errors = file->errors;
	popfile();

	/* Free macros and check which have not been used. */
	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		if (verbose && !sym->used)
			fprintf(stderr, "warning: macro '%s' not used\n",
			    sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	if (errors) {
		clear_config(conf);
		return NULL;
	}

	return conf;
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0)
			break;
	}

	if (sym != NULL) {
		if (sym->persist == 1)
			return 0;
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return -1;

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return -1;
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return -1;
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return 0;
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	ret;

	if ((val = strrchr(s, '=')) == NULL)
		return -1;
	sym = strndup(s, val - s);
	if (sym == NULL)
		errx(1, "%s: strndup", __func__);
	ret = symset(sym, val + 1, 1);
	free(sym);

	return ret;
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return sym->val;
		}
	}
	return NULL;
}

void
clear_config(struct kd_conf *xconf)
{
	/* free stuff? */

	free(xconf);
}

static void
add_table(const char *name, const char *type, const char *path)
{
	if (table_open(conf, name, type, path) == -1)
		yyerror("can't initialize table %s", name);
	table = STAILQ_FIRST(&conf->table_head)->table;
}

static struct table *
findtable(const char *name)
{
	struct kd_tables_conf *i;

	STAILQ_FOREACH(i, &conf->table_head, entry) {
		if (!strcmp(i->table->t_name, name))
			return i->table;
	}

	yyerror("unknown table %s", name);
	return NULL;
}

static void
add_cert(const char *name, const char *path)
{
	struct kd_pki_conf *pki;

	STAILQ_FOREACH(pki, &conf->pki_head, entry) {
		if (strcmp(name, pki->name) != 0)
			continue;

		if (pki->cert != NULL) {
			yyerror("duplicate `pki %s cert'", name);
			return;
		}

		goto set;
	}

	pki = xcalloc(1, sizeof(*pki));
	strlcpy(pki->name, name, sizeof(pki->name));
	STAILQ_INSERT_HEAD(&conf->pki_head, pki, entry);

set:
	if ((pki->cert = tls_load_file(path, &pki->certlen, NULL)) == NULL)
		fatal(NULL);
}

static void
add_key(const char *name, const char *path)
{
	struct kd_pki_conf *pki;

	STAILQ_FOREACH(pki, &conf->pki_head, entry) {
		if (strcmp(name, pki->name) != 0)
			continue;

		if (pki->key != NULL) {
			yyerror("duplicate `pki %s key'", name);
			return;
		}

		goto set;
	}

	pki = xcalloc(1, sizeof(*pki));
	strlcpy(pki->name, name, sizeof(pki->name));
	STAILQ_INSERT_HEAD(&conf->pki_head, pki, entry);

set:
	if ((pki->key = tls_load_file(path, &pki->keylen, NULL)) == NULL)
		fatal(NULL);
}

static struct kd_listen_conf *
listen_new(void)
{
	struct kd_listen_conf *l;

	l = xcalloc(1, sizeof(*l));
	l->id = counter++;
	l->fd = -1;

	STAILQ_INSERT_HEAD(&conf->listen_head, l, entry);
	return l;
}
