/*
 * Copyright (c) 2021, 2022 Omar Polo <op@omarpolo.com>
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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "log.h"
#include "kami.h"
#include "utils.h"

#include "script.h"

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
struct file	*pushfile(const char *);
int		 popfile(void);
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

static int	shouldfail;

typedef struct {
	union {
		struct op	*op;
		struct proc	*proc;
		char		*str;
		int64_t		 num;
	} v;
	int		 lineno;
} YYSTYPE;

%}

/*
 * for bison:
 * %define parse.error verbose
 */

%token	ASSERT
%token	CONST
%token	ERROR
%token	INCLUDE
%token	PROC
%token	REPEAT
%token	SHOULD_FAIL STR
%token	TESTING
%token	U8 U16 U32
%token	VARGS

%token	<v.str>		STRING SYMBOL
%token	<v.num>		NUMBER

%type	<v.op>		cast cexpr check expr faccess funcall
%type	<v.op>		literal sfail var varref vargs

%type	<v.proc>	procname

%%

program : /* empty */
	| program '\n'
	| program include '\n'
	| program const '\n'
	| program proc '\n'
	| program test '\n'
	;

optnl		: '\n' optnl		/* zero or more newlines */
		| /*empty*/
		;

nl	: '\n' optnl ;

include : INCLUDE STRING {
		struct file	*nfile;

		if ((nfile = pushfile($2)) == NULL) {
			yyerror("failed to include file %s", $2);
			free($2);
			YYERROR;
		}
		free($2);

		file = nfile;
		lungetc('\n');
	}
	;

const	: CONST consti
	| CONST '(' optnl mconst ')'
	;

mconst	: consti nl | mconst consti nl ;

consti	: SYMBOL '=' expr {
		if (!global_set($1, $3)) {
			yyerror("can't set %s: illegal expression", $1);
			free($1);
			free_op($3);
			YYERROR;
		}
	}
	;

var	: SYMBOL '=' expr	{ $$ = op_assign($1, $3); }	;
varref	: SYMBOL		{ $$ = op_var($1); }		;
literal	: STRING		{ $$ = op_lit_str($1); }
	| NUMBER		{ $$ = op_lit_num($1); }	;

/*
 * `expr '=' '=' expr` is ambiguous.  furthermore, we're not
 * interested in checking all the possibilities here.
 */
cexpr	: literal | varref | funcall | faccess ;
check	: cexpr '=' '=' cexpr	{ $$ = op_cmp_eq($1, $4); }
	| cexpr '<' '=' cexpr	{ $$ = op_cmp_leq($1, $4); }
	;

expr	: literal | funcall | varref | check | cast | faccess | vargs ;

vargs	: VARGS		{ $$ = op_vargs(); }			;

cast	: expr ':' U8	{ $$ = op_cast($1, V_U8); }
	| expr ':' U16	{ $$ = op_cast($1, V_U16); }
	| expr ':' U32	{ $$ = op_cast($1, V_U32); }
	| expr ':' STR	{ $$ = op_cast($1, V_STR); }
	;

faccess	: varref '.' SYMBOL	{ $$ = op_faccess($1, $3); }
	| faccess '.' SYMBOL	{ $$ = op_faccess($1, $3); }
	;

procname: SYMBOL {
		if (($$ = proc_by_name($1)) == NULL) {
			yyerror("unknown proc %s", $1);
			free($1);
			YYERROR;
		}
		free($1);
	}
	;

funcall	: procname {
		prepare_funcall();
	} '(' args optcomma ')' {
		struct proc	*proc;
		int		 argc;

		$$ = op_funcall($1);
		proc = $$->v.funcall.proc;
		argc = $$->v.funcall.argc;

		if (argc != proc->minargs && !proc->vararg) {
			yyerror("invalid arity for `%s': want %d arguments "
			    "but %d given.", $1->name, proc->minargs, argc);
			/* TODO: recursively free $$ */
			YYERROR;
		}

		if (argc < proc->minargs && proc->vararg) {
			yyerror("invalid arity for `%s': want at least %d "
			    "arguments but %d given.", $1->name, proc->minargs,
			    argc);
			/* TODO: recursively free $$ */
			YYERROR;
		}
	}
	;

optcomma: /* empty */ | ',' ;

dots	: '.' '.' '.' ;

args	: /* empty */
	| args ',' expr	{ push_arg($3); }
	| args ',' dots	{ push_arg(op_rest()); }
	| expr		{ push_arg($1); }
	| dots		{ push_arg(op_rest()); }
	;

proc	: PROC SYMBOL {
		prepare_proc();
	} '(' args ')' {
		if (!proc_setup_body()) {
			yyerror("invalid argument in proc `%s' definition",
			    $2);
			free($2);
			YYERROR;
		}
	} '{' optnl block '}' {
		proc_done($2);
	}
	;

block	: /* empty */
	| block var nl		{ block_push($2); }
	| block funcall nl	{ block_push($2); }
	| block assert nl
	| block sfail nl	{ block_push($2); }
	;

sfail	: SHOULD_FAIL expr		{ $$ = op_sfail($2, NULL); }
	| SHOULD_FAIL expr ':' STRING	{ $$ = op_sfail($2, $4); }
	;

assert	: ASSERT asserti
	| ASSERT '(' optnl massert ')'
	;

massert	: asserti nl | massert asserti nl ;

asserti	: check			{ block_push(op_assert($1)); }
	;

test	: TESTING STRING {
		prepare_test();
	} testopt '{' optnl block '}' {
		test_done(shouldfail, $2);
		shouldfail = 0;
	}
	;

testopt	: /* empty */
	| SHOULD_FAIL	{ shouldfail = 1; }
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
		{"assert",	ASSERT},
		{"const",	CONST},
		{"include",	INCLUDE},
		{"proc",	PROC},
		{"repeat",	REPEAT},
		{"should-fail",	SHOULD_FAIL},
		{"str",		STR},
		{"testing",	TESTING},
		{"u16",		U16},
		{"u32",		U32},
		{"u8",		U8},
		{"vargs",	VARGS},
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return p->k_val;
	else
		return SYMBOL;
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
	case ASSERT: puts("assert"); break;
	case CONST: puts("const"); break;
	case ERROR: puts("error"); break;
	case INCLUDE: puts("include"); break;
	case PROC: puts("proc"); break;
	case REPEAT: puts("repeat"); break;
	case STR: puts(":str"); break;
	case TESTING: puts("testing"); break;
	case U8: puts(":u8"); break;
	case U16: puts(":u16"); break;
	case U32: puts(":u32"); break;

	case STRING: printf("string \"%s\"\n", yylval.v.str); break;
	case SYMBOL: printf("symbol %s\n", yylval.v.str); break;
	case NUMBER: printf("number %"PRIu64"\n", yylval.v.num); break;

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
	unsigned char	*p;
	int		 quotec, next, c;
	int		 token;

	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t' || c == '\f')
		; /* nop */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nop */

	switch (c) {
	case ':':
		return c;
		break;
	case '\'':
	case '\"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return 0;
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return 0;
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

		yylval.v.str = xstrdup(buf);
		return STRING;
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x == ',' || x == '/' || x == '}' \
	    || x == '=' || x == ':')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return findeol();
			}
		} while ((c = lgetc(0)) != EOF && (isdigit(c) || c == 'x'));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			char *ep;

			*p = '\0';
			errno = 0;
			yylval.v.num = strtoll(buf, &ep, 0);
			if (*ep != '\0' || (errno == ERANGE &&
			    (yylval.v.num == LONG_MAX ||
			    yylval.v.num == LONG_MIN))) {
				yyerror("\"%s\" invalid number or out of range",
				    buf);
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

#define allowed_in_symbol(x)				\
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	    x != '{' && x != '}' && \
	    x != '!' && x != '=' && \
	    x != '#' && x != ',' && \
	    x != '.' && x != ':'))

	if (isalnum(c) || c == ':' || c == '_') {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return findeol();
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_symbol(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == SYMBOL)
			yylval.v.str = xstrdup(buf);
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

struct file *
pushfile(const char *name)
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

void
loadfile(const char *path)
{
	int pwdfd, errors;
	char p[PATH_MAX], *dir;

	/*
	 * Ugly workaround: we really need a smarter `include', one that 
	 * is able to resolve path relatively from the currently processed
	 * file.  The workaround consist to save the current directory,
	 * chdir(2) to the script dirname and then jump back by mean of
	 * fchdir.
	 */

	if ((pwdfd = open(".", O_RDONLY|O_DIRECTORY)) == -1)
		err(1, "can't open .");
	strlcpy(p, path, sizeof(p));
	dir = dirname(p);
	if (chdir(dir) == -1)
		err(1, "chdir %s", dir);

	/* XXX: include the *basename* of the file after chdir */
	strlcpy(p, path, sizeof(p));
	file = pushfile(basename(p));
	if (file == NULL)
		err(1, "pushfile");
	topfile = file;

	yyparse();
	errors = file->errors;
	popfile();

	fchdir(pwdfd);
	close(pwdfd);

	if (errors)
		errx(1, "can't load %s because of errors", path);
}
