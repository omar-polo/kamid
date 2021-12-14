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

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pwd.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "client.h"
#include "log.h"
#include "script.h"
#include "utils.h"

#define DEBUG 0

#ifndef INFTIM
#define INFTIM -1
#endif

static const char	*argv0;

static uint8_t		*lastmsg;

static struct imsgbuf	 ibuf;
static int		 ibuf_inuse;
static int		 child_out = -1;

static struct procs procs = TAILQ_HEAD_INITIALIZER(procs);
static struct tests tests = TAILQ_HEAD_INITIALIZER(tests);

static int ntests;

static struct opstacks blocks = TAILQ_HEAD_INITIALIZER(blocks);
static struct opstacks args   = TAILQ_HEAD_INITIALIZER(args);

#define STACK_HEIGHT 64
static struct value	vstack[STACK_HEIGHT];
static int		stackh;

static struct envs envs = TAILQ_HEAD_INITIALIZER(envs);

static struct value v_false = {.type = V_NUM, .v = {.num = 0}};
static struct value v_true  = {.type = V_NUM, .v = {.num = 1}};

static uint8_t lasttag;

static int debug;
static int syntaxcheck;

static const char	*filler;

static inline void
before_printing(void)
{
	if (filler != NULL) {
		printf("%s", filler);
		filler = NULL;
	}
}

static inline void
check_for_output(void)
{
	static char	buf[BUFSIZ];
	struct pollfd	pfd;
	ssize_t		r;

	pfd.fd = child_out;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 0) == -1)
		fatal("poll");

	if (!(pfd.revents & POLLIN))
		return;

	for (;;) {
		if ((r = read(child_out, buf, sizeof(buf))) == -1) {
			if (errno == EAGAIN)
				break;
			fatal("read");
		}
		if (r == 0)
			break;
		before_printing();
		fwrite(buf, 1, r, stdout);
	}
}

static inline void
peekn(int depth, struct value *v)
{
	if (depth > stackh)
		errx(1, "can't peek the stack at %d: underflow",
		    depth);
	memcpy(v, &vstack[stackh - depth], sizeof(*v));

#if DEBUG
	printf("peeking(%d) ", depth); pp_val(v); printf("\n");
#endif
}

static inline void
popv(struct value *v)
{
	if (stackh == 0)
		errx(1, "can't pop the stack: underflow");
	memcpy(v, &vstack[--stackh], sizeof(*v));

#if DEBUG
	printf("popping "); pp_val(v); printf("\n");
#endif
}

static inline void
popvn(int n)
{
	struct value v;

	while (n-- > 0)
		popv(&v);
}

static inline void
pushv(struct value *v)
{
	if (stackh == STACK_HEIGHT)
		errx(1, "can't push the stack: overflow");

#if DEBUG
	printf("pushing "); pp_val(v); printf("\n");
#endif

	memcpy(&vstack[stackh++], v, sizeof(*v));
}

static inline void
pushbool(int n)
{
	pushv(n ? &v_true : &v_false);
}

static inline void
pushnum(int64_t n)
{
	struct value v;

	v.type = V_NUM;
	v.v.num = n;
	pushv(&v);
}

static inline struct opstack *
pushstack(struct opstacks *stack)
{
	struct opstack *ops;

	ops = xcalloc(1, sizeof(*ops));
	TAILQ_INSERT_HEAD(stack, ops, entry);
	return ops;
}

static inline struct opstack *
peek(struct opstacks *stack)
{
	if (TAILQ_EMPTY(stack))
		errx(1, "%s: args underflow", __func__);

	return TAILQ_FIRST(stack);
}

static inline struct op *
finalize(struct opstacks *stack, int *argc)
{
	struct opstack	*ops;
	struct op	*op;

	if (TAILQ_EMPTY(stack))
		errx(1, "%s: args underflow", __func__);

	ops = peek(stack);
	TAILQ_REMOVE(&args, ops, entry);
	op = ops->base.next;

	if (argc != NULL)
		*argc = ops->counter;

	free(ops);
	return op;
}

static inline void
push(struct opstacks *stack, struct op *op)
{
	struct opstack *ops;

	ops = peek(stack);
	if (ops->last == NULL) {
		ops->base.next = op;
		ops->last = op;
	} else {
		ops->last->next = op;
		ops->last = op;
	}

	ops->counter++;
}

static inline void
pushenv(void)
{
	struct env	*e;

	e = xcalloc(1, sizeof(*e));
	TAILQ_INSERT_HEAD(&envs, e, entry);
}

static inline struct env *
currentenv(void)
{
	assert(!TAILQ_EMPTY(&envs));
	return TAILQ_FIRST(&envs);
}

static void
popenv(void)
{
	struct env	*e;
	struct binding	*b, *tb;

	e = currentenv();
	TAILQ_REMOVE(&envs, e, entry);

	TAILQ_FOREACH_SAFE(b, &e->bindings, entry, tb)
		free(b);

	free(e);
}

static inline int
setvar(char *sym, struct op *op)
{
	struct binding	*b;
	struct env	*e;
	int		 ret, height;

	height = stackh;
	if ((ret = eval(op)) != EVAL_OK)
		return ret;

	if (stackh != height + 1) {
		before_printing();
		printf("trying to assign to `%s' a void value: ", sym);
		pp_op(op);
		printf("\n");
		return EVAL_ERR;
	}

	b = xcalloc(1, sizeof(*b));
	b->name = sym;
	popv(&b->val);

	e = TAILQ_FIRST(&envs);
	TAILQ_INSERT_HEAD(&e->bindings, b, entry);

	return EVAL_OK;
}

static inline void
setvar_raw(char *sym, struct op *op)
{
	struct binding	*b;
	struct env	*e;

	b = xcalloc(1, sizeof(*b));
	b->name = sym;
	b->raw = op;

	e = TAILQ_FIRST(&envs);
	TAILQ_INSERT_HEAD(&e->bindings, b, entry);
}

static inline int
getvar(const char *sym, struct value *v)
{
	struct env	*e;
	struct binding	*b;

	TAILQ_FOREACH(e, &envs, entry) {
		TAILQ_FOREACH(b, &e->bindings, entry) {
			if (!strcmp(sym, b->name)) {
				memcpy(v, &b->val, sizeof(*v));
				return EVAL_OK;
			}
		}
	}

	before_printing();
	fprintf(stderr, "unbound variable %s\n", sym);
	return EVAL_ERR;
}

static inline int
getvar_raw(const char *sym, struct op **raw)
{
	struct env	*e;
	struct binding	*b;

	TAILQ_FOREACH(e, &envs, entry) {
		TAILQ_FOREACH(b, &e->bindings, entry) {
			if (!strcmp(sym, b->name)) {
				*raw = b->raw;
				return EVAL_OK;
			}
		}
	}

	return EVAL_ERR;
}

int
global_set(char *sym, struct op *op)
{
	struct binding	*b;
	struct env	*e;

	/* TODO: check for duplicates */

	if (op->type != OP_LITERAL &&
	    (op->type == OP_CAST && op->v.cast.expr->type != OP_LITERAL))
		return 0;

	b = xcalloc(1, sizeof(*b));
	b->name = sym;

	/* it's only a cast on a literal! */
	if (op->type == OP_CAST) {
		if (eval(op) != EVAL_OK) {
			free(b);
			return 0;
		}
		popv(&b->val);
	} else
		memcpy(&b->val, &op->v.literal, sizeof(b->val));

	e = TAILQ_LAST(&envs, envs);
	TAILQ_INSERT_HEAD(&e->bindings, b, entry);

	return 1;
}

struct op *
newop(int type)
{
	struct op *op;

	op = xcalloc(1, sizeof(*op));
	op->type = type;

	return op;
}

void
free_op_rec(struct op *op)
{
	struct op *n;

	while (op != NULL) {
		n = op->next;
		free_op(op);
		op = n;
	}
}

void
free_op(struct op *op)
{
	if (op == NULL)
		return;

	switch (op->type) {
	case OP_REST:
	case OP_LITERAL:
	case OP_VARGS:
		break;
	case OP_ASSIGN:
		free(op->v.assign.name);
		free_op_rec(op->v.assign.expr);
		break;
	case OP_ASSERT:
		free_op_rec(op->v.assert);
		break;
	case OP_FUNCALL:
		free_op_rec(op->v.funcall.argv);
		break;
	case OP_VAR:
		free(op->v.var);
		break;
	case OP_CAST:
		free_op_rec(op->v.cast.expr);
		break;
	case OP_CMP_EQ:
		free_op_rec(op->v.cmp_eq.a);
		free_op_rec(op->v.cmp_eq.b);
		break;
	case OP_FACCESS:
		free_op_rec(op->v.faccess.expr);
		free(op->v.faccess.field);
		break;
	case OP_SFAIL:
		free(op->v.sfail.msg);
		free_op_rec(op->v.sfail.expr);
		break;
	default:
		/* unreachable */
		abort();
	}

	free(op);
}

struct op *
op_rest(void)
{
	return newop(OP_REST);
}

struct op *
op_assign(char *sym, struct op *expr)
{
	struct op *op;

	op = newop(OP_ASSIGN);
	op->v.assign.name = sym;
	op->v.assign.expr = expr;

	return op;
}

struct op *
op_assert(struct op *expr)
{
	struct op *op;

	op = newop(OP_ASSERT);
	op->v.assert = expr;

	return op;
}

struct op *
op_var(char *sym)
{
	struct op *op;

	op = newop(OP_VAR);
	op->v.var = sym;

	return op;
}

struct op *
op_lit_str(char *str)
{
	struct op *op;

	op = newop(OP_LITERAL);
	op->v.literal.type = V_STR;
	op->v.literal.v.str = str;

	return op;
}

struct op *
op_lit_num(uint64_t n)
{
	struct op *op;

	op = newop(OP_LITERAL);
	op->v.literal.type = V_NUM;
	op->v.literal.v.num = n;

	return op;
}

struct op *
op_cmp_eq(struct op *a, struct op *b)
{
	struct op *op;

	op = newop(OP_CMP_EQ);
	op->v.cmp_eq.a = a;
	op->v.cmp_eq.b = b;

	return op;
}

struct op *
op_cast(struct op *expr, int totype)
{
	struct op *op;

	op = newop(OP_CAST);
	op->v.cast.expr = expr;
	op->v.cast.totype = totype;

	return op;
}

struct op *
op_faccess(struct op *expr, char *field)
{
	struct op *op;

	op = newop(OP_FACCESS);
	op->v.faccess.expr = expr;
	op->v.faccess.field = field;

	return op;
}

struct op *
op_sfail(struct op *expr, char *msg)
{
	struct op	*op;

	op = newop(OP_SFAIL);
	op->v.sfail.expr = expr;
	op->v.sfail.msg = msg;

	return op;
}

struct op *
op_vargs(void)
{
	struct op	*op;

	op = newop(OP_VARGS);

	return op;
}

void
ppf_val(FILE *f, struct value *val)
{
	size_t	i;

	switch (val->type) {
	case V_SYM:
		fprintf(f, "%s", val->v.str);
		break;
	case V_STR:
		fprintf(f, "\"%s\"", val->v.str);
		break;
	case V_NUM:
		fprintf(f, "%"PRIi64, val->v.num);
		break;
	case V_U8:
		fprintf(f, "%"PRIu8, val->v.u8);
		break;
	case V_U16:
		fprintf(f, "%"PRIu16, val->v.u16);
		break;
	case V_U32:
		fprintf(f, "%"PRIu32, val->v.u32);
		break;
	case V_MSG:
		fprintf(f, "(");
		for (i = 0; i < val->v.msg.len; ++i)
			fprintf(f, "%x%s", val->v.msg.msg[i],
			    i == val->v.msg.len-1 ? "" : " ");
		fprintf(f, ")");
		break;
	case V_QIDVEC:
		fprintf(f, "qids[n=%zu]", val->v.qidvec.len);
		break;
	default:
		fprintf(f, "<unknown value>");
		break;
	}
}

void
pp_val(struct value *val)
{
	ppf_val(stdout, val);
}

const char *
val_type(struct value *v)
{
	switch (v->type) {
	case V_SYM: return "symbol";
	case V_STR: return "string";
	case V_NUM: return "number";
	case V_MSG: return "message";
	case V_QID: return "qid";
	case V_U8: return "u8";
	case V_U16: return "u16";
	case V_U32: return "u32";
	default: return "unknown";
	}
}

int
val_trueish(struct value *a)
{
	if (val_isnum(a))
		return val_tonum(a);
	return 1;
}

int
val_isnum(struct value *a)
{
	return a->type == V_NUM
		|| a->type == V_U8
		|| a->type == V_U16
		|| a->type == V_U32;
}

int64_t
val_tonum(struct value *a)
{
	switch (a->type) {
	case V_NUM: return a->v.num;
	case V_U8:  return a->v.u8;
	case V_U16: return a->v.u16;
	case V_U32: return a->v.u32;
	default:
		before_printing();
		fprintf(stderr, "%s: given value is not a number\n", __func__);
		abort();
	}
}

int
val_eq(struct value *a, struct value *b)
{
	if (val_isnum(a) && val_isnum(b))
		return val_tonum(a) == val_tonum(b);

	if (a->type != b->type)
		return 0;

	switch (a->type) {
	case V_STR:
	case V_SYM:
		return !strcmp(a->v.str, b->v.str);
	}

	return 0;
}

static inline const char *
pp_totype(int totype)
{
	/*
	 * Not all of these are valid cast type thought, including
	 * every possibility only to aid debugging.
	 */
	switch (totype) {
	case V_STR: return "str";
	case V_SYM: return "sym";
	case V_NUM: return "num";
	case V_QID: return "qid";
	case V_U8:  return "u8";
	case V_U16: return "u16";
	case V_U32: return "u32";
	default:    return "unknown";
	}
}

int
val_cast(struct value *a, int totype)
{
	int64_t v;

#define NUMCAST(val, t, c, totype, max) do {				\
		if (val > max) {					\
			before_printing();				\
			fprintf(stderr, "can't cast %"PRIu64		\
			    " to %s\n", val, pp_totype(totype));	\
			return EVAL_ERR;				\
		}							\
		a->type = totype;					\
		a->v.t = (c)val;					\
		return EVAL_OK;						\
	} while (0)

	if (a->type == totype)
		return EVAL_OK;

	if (!val_isnum(a)) {
		before_printing();
		fprintf(stderr, "can't cast ");
		ppf_val(stderr, a);
		fprintf(stderr, " to type %s\n", pp_totype(totype));
		return EVAL_ERR;
	}

	v = a->v.num;
	switch (totype) {
	case V_U8:  NUMCAST(v, u8,  uint8_t,  totype, UINT8_MAX);
	case V_U16: NUMCAST(v, u16, uint16_t, totype, UINT16_MAX);
	case V_U32: NUMCAST(v, u32, uint32_t, totype, UINT32_MAX);
	default:
		before_printing();
		fprintf(stderr, "can't cast %"PRIu64" to %s\n",
		    v, pp_totype(totype));
		return EVAL_ERR;
	}

#undef NUMCAST
}

int
val_faccess(struct value *a, const char *field, struct value *ret)
{
	uint8_t		 mtype;
	uint16_t	 len;
	const char	*errstr;

#define MSGTYPE(m) *(m.msg + 4)	/* skip the length */

	switch (a->type) {
	case V_QID:
		/* TODO: add path.  needs uint64_t values thought! */
		if (!strcmp(field, "vers")) {
			ret->type = V_U32;
			memcpy(&ret->v.u32, a->v.qid+1, 4);
			return EVAL_OK;
		} else if (!strcmp(field, "type")) {
			ret->type = V_U8;
			ret->v.u8 = *a->v.qid;
			return EVAL_OK;
		}
		break;

	case V_MSG:
		mtype = MSGTYPE(a->v.msg);
		if (!strcmp(field, "type")) {
			ret->type = V_U8;
			ret->v.u8 = MSGTYPE(a->v.msg);
			return EVAL_OK;
		} else if (!strcmp(field, "tag")) {
			ret->type = V_U16;
                        memcpy(&ret->v.u16, &a->v.msg.msg[5], 2);
			ret->v.u16 = le16toh(ret->v.u16);
			return EVAL_OK;
		} else if (!strcmp(field, "msize") && mtype == Rversion) {
			ret->type = V_U32;
			memcpy(&ret->v.u32, &a->v.msg.msg[7], 4);
			ret->v.u32 = le32toh(ret->v.u32);
			return EVAL_OK;
		} else if (!strcmp(field, "qid") && mtype == Rattach) {
			ret->type = V_QID;
			memcpy(&ret->v.qid, &a->v.msg.msg[7], QIDSIZE);
			return EVAL_OK;
		} else if (!strcmp(field, "nwqid") && mtype == Rwalk) {
			ret->type = V_U16;
			memcpy(&ret->v.u16, &a->v.msg.msg[7], 2);
			ret->v.u16 = le16toh(ret->v.u16);
			return EVAL_OK;
		} else if (!strcmp(field, "wqid") && mtype == Rwalk) {
			ret->type = V_QIDVEC;
			ret->v.qidvec.start = &a->v.msg.msg[9];
			memcpy(&len, &a->v.msg.msg[7], 2);
			len = le16toh(len);
			ret->v.qidvec.len = len;
			return EVAL_OK;
		}
		break;

	case V_QIDVEC:
		len = strtonum(field, 0, MAXWELEM, &errstr);
		if (errstr != NULL) {
			before_printing();
			printf("can't access qid #%s: %s\n", field, errstr);
			return EVAL_ERR;
		}

		if (len >= a->v.qidvec.len) {
			before_printing();
			printf("can't access qid #%d: out-of-bound "
			    "(max %zu)\n", len, a->v.qidvec.len);
			return EVAL_ERR;
		}

		ret->type = V_QID;
		memcpy(&ret->v.qid, a->v.qidvec.start + len * QIDSIZE,
		    QIDSIZE);

                return EVAL_OK;

	default:
		break;
	}

	before_printing();
	printf("can't access field `%s' on type %s (", field, val_type(a));
	pp_val(a);
	printf(")\n");
	return EVAL_ERR;

#undef MSGTYPE
}

void
pp_op(struct op *op)
{
	struct op	*aux;

	switch (op->type) {
	case OP_REST:
		printf("...");
		break;
	case OP_ASSIGN:
		printf("%s = ", op->v.assign.name);
                pp_op(op->v.assign.expr);
		break;
	case OP_ASSERT:
		printf("assert ");
		pp_op(op->v.assert);
		break;
	case OP_FUNCALL:
		printf("funcall %s(", op->v.funcall.proc->name);
		for (aux = op->v.funcall.argv; aux != NULL; aux = aux->next) {
			pp_op(aux);
			if (aux->next != NULL)
				printf(", ");
		}
		printf(")");
		break;
	case OP_LITERAL:
                pp_val(&op->v.literal);
		break;
	case OP_VAR:
		printf("%s", op->v.var);
		break;
	case OP_CAST:
		pp_op(op->v.cast.expr);
		printf(":");
		switch (op->v.cast.totype) {
		case V_U8: printf("u8"); break;
		case V_U16: printf("u16"); break;
		case V_U32: printf("u32"); break;
		case V_STR: printf("str"); break;
		default: printf("???"); break;
		}
		break;
	case OP_CMP_EQ:
		pp_op(op->v.cmp_eq.a);
		printf(" == ");
		pp_op(op->v.cmp_eq.b);
		break;
	case OP_FACCESS:
		pp_op(op->v.faccess.expr);
		printf(".%s", op->v.faccess.field);
		break;
	case OP_SFAIL:
		printf("should-fail ");
		pp_op(op->v.sfail.expr);
		if (op->v.sfail.msg != NULL)
			printf(": \"%s\"", op->v.sfail.msg);
		break;
	case OP_VARGS:
		printf("vargs");
		break;
	default:
		printf(" ???[%d] ", op->type);
	}
}

void
pp_block(struct op *op)
{
        while (op != NULL) {
		printf("> ");
		pp_op(op);
		printf("\n");

		op = op->next;
	}
}

int
eval(struct op *op)
{
	struct value	 a, b;
	struct proc	*proc;
	struct op	*t, *tnext;
	int		 i, ret;

#if DEBUG
	pp_op(op);
	printf("\n");
#endif

	switch (op->type) {
	case OP_REST:
		/*
		 * Try to load the rest argument.  Note that it can be
		 * empty!
		 */
                if ((ret = getvar_raw("...", &t)) == EVAL_OK)
			if ((ret = eval(t)) != EVAL_OK)
				return ret;
		break;

	case OP_ASSIGN:
		ret = setvar(op->v.assign.name, op->v.assign.expr);
		if (ret != EVAL_OK)
			return ret;
		break;

	case OP_ASSERT:
		if ((ret = eval(op->v.assert)) != EVAL_OK)
			return ret;
                popv(&a);
                if (!val_trueish(&a)) {
			before_printing();
			printf("assertion failed: ");
			pp_op(op->v.assert);
			printf("\n");
			return EVAL_ERR;
		}
		break;

	case OP_FUNCALL:
		/* assume airity matches */

		proc = op->v.funcall.proc;
		if (proc->nativefn != NULL) {
			/*
			 * Push arguments on the stack for builtin
			 * functions.  Counting the height of the
			 * stack is done to compute the correct number
			 * in the vararg case.  argc only counts the
			 * "syntactical" arguments, i.e. foo(x, ...)
			 * has argc == 2, but at runtime argc may be
			 * 1, 2 or a greater number!
			 */

			i = stackh;
			t = op->v.funcall.argv;
			if (t != NULL && (ret = eval(t)) != EVAL_OK)
				return ret;
			i = stackh - i;

			assert(i >= 0);

			if ((ret = proc->nativefn(i))
			    != EVAL_OK)
				return ret;
		} else {
			if (proc->body == NULL) {
				before_printing();
				printf("warn: calling the empty proc `%s'\n",
				    proc->name);
				break;
			}

			pushenv();

			for (t = op->v.funcall.argv, i = 0;
			     t != NULL;
			     t = t->next, i++) {
				/*
				 * Push a pseudo variable `...' (and
				 * don't evaluate it) in the vararg
				 * case.  A special case is when the
				 * variable is itself `...'.
				 */
				if (proc->vararg && i == proc->minargs) {
					if (t->type != OP_REST)
						setvar_raw(xstrdup("..."), t);
					break;
				}

				/*
				 * The arguments are a linked list of
				 * ops.  Setvar will call eval that
				 * will evaluate *all* the arguments.
				 * The dance here that sets next to
				 * NULL and then restores it is to
				 * avoid this behaviour.
				 */
				tnext = t->next;
				t->next = NULL;
				ret = setvar(proc->args[i], t);
				t->next = tnext;

				if (ret != EVAL_OK)
					return ret;
			}

			if ((ret = eval(proc->body)) != EVAL_OK)
				return ret;

			popenv();
		}

		break;

	case OP_LITERAL:
		pushv(&op->v.literal);
		break;

	case OP_VAR:
                if ((ret = getvar(op->v.var, &a)) != EVAL_OK)
			return ret;
		pushv(&a);
		break;

	case OP_CAST:
		if ((ret = eval(op->v.cast.expr)) != EVAL_OK)
			return ret;
		popv(&a);
		if ((ret = val_cast(&a, op->v.cast.totype)) != EVAL_OK)
			return ret;
		pushv(&a);
		break;

	case OP_CMP_EQ:
		if ((ret = eval(op->v.cmp_eq.a)) != EVAL_OK)
			return ret;
		if ((ret = eval(op->v.cmp_eq.b)) != EVAL_OK)
			return ret;

		popv(&b);
		popv(&a);
		pushbool(val_eq(&a, &b));

		break;

	case OP_FACCESS:
		if ((ret = eval(op->v.faccess.expr)) != EVAL_OK)
			return ret;
		popv(&a);
		if ((ret = val_faccess(&a, op->v.faccess.field, &b))
		    != EVAL_OK)
			return ret;
		pushv(&b);
		break;

	case OP_SFAIL:
		if ((ret = eval(op->v.sfail.expr)) == EVAL_OK) {
			before_printing();
			printf("expecting failure");
			if (op->v.sfail.msg != NULL)
				printf(" \"%s\"", op->v.sfail.msg);
			printf("\n");
			printf("expression: ");
			pp_op(op->v.sfail.expr);
			printf("\n");
			return EVAL_ERR;
		}
		if (ret == EVAL_SKIP)
			return ret;
		break;

	case OP_VARGS:
		if ((ret = getvar_raw("...", &t)) == EVAL_OK) {
                        for (i = 0; t != NULL; t = t->next)
				i++;
			pushnum(i);
		} else
			pushnum(0);
		break;

	default:
		before_printing();
		fprintf(stderr, "invalid op, aborting.\n");
		abort();
	}

	if (op->next)
		return eval(op->next);
	return EVAL_OK;
}

void
prepare_funcall(void)
{
	pushstack(&args);
}

void
push_arg(struct op *op)
{
	push(&args, op);
}

struct op *
op_funcall(struct proc *proc)
{
	struct op	*op, *argv;
	int		 argc;

	argv = finalize(&args, &argc);

	op = newop(OP_FUNCALL);
	op->v.funcall.proc = proc;
	op->v.funcall.argv = argv;
	op->v.funcall.argc = argc;

	return op;
}

void
add_builtin_proc(const char *name, int (*fn)(int), int argc, int vararg)
{
	struct proc *proc;

	proc = xcalloc(1, sizeof(*proc));
	proc->name = xstrdup(name);
	proc->nativefn = fn;
	proc->minargs = argc;
	proc->vararg = vararg;

	TAILQ_INSERT_HEAD(&procs, proc, entry);
}

void
prepare_proc(void)
{
	pushstack(&args);
}

int
proc_setup_body(void)
{
	struct opstack	*argv;
	struct op	*op;
	int		 i;

	argv = peek(&args);
	for (i = 0, op = argv->base.next; op != NULL; i++) {
		/*
		 * TODO: should free the whole list on error but..,
		 * we're gonna exit real soon(tm)!
		 */
		if (op->type != OP_VAR && op->type != OP_REST)
			return 0;

		op = op->next;
	}

	assert(i == argv->counter);
	pushstack(&blocks);
	return 1;
}

void
proc_done(char *name)
{
	struct proc	*proc;
	struct op	*op, *next, *argv, *body;
	int		 i, argc;

	argv = finalize(&args, &argc);
	body = finalize(&blocks, NULL);

	proc = xcalloc(1, sizeof(*proc));
	proc->name = name;
	proc->minargs = argc;

        for (i = 0, op = argv; op != NULL; ++i) {
		if (op->type == OP_REST) {
			proc->vararg = 1;
			proc->minargs = i;
			break;
		}

		proc->args[i] = xstrdup(op->v.var);

		next = op->next;
		free_op(op);
		op = next;
	}
	assert(i == argc || (proc->vararg && i == proc->minargs));

	proc->body = body;

	TAILQ_INSERT_HEAD(&procs, proc, entry);
}

void
block_push(struct op *op)
{
	push(&blocks, op);
}

struct proc *
proc_by_name(const char *name)
{
	struct proc *p;

	TAILQ_FOREACH(p, &procs, entry) {
		if (!strcmp(p->name, name))
			return p;
	}

	return NULL;
}

void
prepare_test(void)
{
	pushstack(&blocks);
}

void
test_done(int shouldfail, char *name, char *dir)
{
	struct test	*test;

	test = xcalloc(1, sizeof(*test));
	test->shouldfail = shouldfail;
	test->name = name;
	test->dir = dir;
	test->body = finalize(&blocks, NULL);

	if (TAILQ_EMPTY(&tests))
		TAILQ_INSERT_HEAD(&tests, test, entry);
	else
		TAILQ_INSERT_TAIL(&tests, test, entry);

	ntests++;
}

static int
builtin_print(int argc)
{
	struct value	v;
	int		i;

	before_printing();

	for (i = argc; i > 0; --i) {
		peekn(i, &v);
		if (v.type == V_STR)
			printf("%s", v.v.str);
		else
			pp_val(&v);
		printf(" ");
	}

	printf("\n");

	popvn(argc);

	return EVAL_OK;
}

static int
builtin_debug(int argc)
{
	if (debug)
		return builtin_print(argc);

	popvn(argc);
	return EVAL_OK;
}

static int
builtin_skip(int argc)
{
	return EVAL_SKIP;
}

static int
builtin_iota(int argc)
{
	struct value v;

	v.type = V_U16;
	if ((v.v.u16 = ++lasttag) == 255)
		v.v.u16 = ++lasttag;

	pushv(&v);
	return EVAL_OK;
}

static int
builtin_send(int argc)
{
	struct ibuf	*buf;
	struct value	 v;
	uint32_t	 len;
	uint16_t	 slen;
	int		 i;

	check_for_output();

	/*
	 * Compute the length of the packet.  4 is for the initial
	 * length field
	 */
	len = 4;

	for (i = argc; i > 0; --i) {
		peekn(i, &v);
		switch (v.type) {
		case V_STR:
			len += 2; /* count */
			len += strlen(v.v.str);
			break;

		case V_U8:
			len += 1;
			break;

		case V_U16:
			len += 2;
			break;

		case V_U32:
			len += 4;
			break;

		default:
			before_printing();
			printf("%s: can't serialize ", __func__);
			pp_val(&v);
			printf("\n");
			return EVAL_ERR;
		}
	}

	if (len > UINT16_MAX) {
		before_printing();
		printf("%s: message size too long: got %d when max is %d\n",
		    __func__, len, UINT16_MAX);
		return EVAL_ERR;
	}

	if ((buf = imsg_create(&ibuf, IMSG_BUF, 0, 0, len)) == NULL)
		fatal("imsg_create(%d)", len);

	len = htole32(len);
	imsg_add(buf, &len, sizeof(len));

	for (i = argc; i > 0; --i) {
		peekn(i, &v);
		switch (v.type) {
		case V_STR:
			slen = strlen(v.v.str);
			slen = htole16(slen);
			imsg_add(buf, &slen, sizeof(slen));
			imsg_add(buf, v.v.str, strlen(v.v.str));
			break;

		case V_U8:
			imsg_add(buf, &v.v.u8, 1);
			break;

		case V_U16:
			v.v.u16 = htole16(v.v.u16);
			imsg_add(buf, &v.v.u16, 2);
			break;

		case V_U32:
			v.v.u32 = htole32(v.v.u32);
			imsg_add(buf, &v.v.u32, 4);
			break;
		}
	}

	imsg_close(&ibuf, buf);

	if (imsg_flush(&ibuf) == -1) {
		i = errno;
		before_printing();
		printf("%s: imsg_flush failed: %s\n", __func__, strerror(i));
		return EVAL_ERR;
	}

	check_for_output();
	return EVAL_OK;
}

static int
builtin_recv(int argc)
{
	struct pollfd	pfd;
        struct value	v;
	struct imsg	imsg;
	ssize_t		n, datalen;
	int		serrno;

	if (lastmsg != NULL) {
		free(lastmsg);
		lastmsg = NULL;
	}

	pfd.fd = ibuf.fd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, INFTIM) == -1) {
		serrno = errno;
		before_printing();
		printf("%s: poll failed: %s\n", __func__, strerror(serrno));
		return EVAL_ERR;
	}

again:
	if ((n = imsg_read(&ibuf)) == -1) {
		if (errno == EAGAIN)
			goto again;
		fatal("imsg_read");
	}
	if (n == 0) {
disconnect:
		before_printing();
		printf("child disconnected\n");
		return EVAL_ERR;
	}

nextmessage:
	check_for_output();

	/* read only one message */
	if ((n = imsg_get(&ibuf, &imsg)) == -1)
		fatal("imsg_get");
	if (n == 0)
		goto disconnect;

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	switch (imsg.hdr.type) {
	case IMSG_BUF:
		v.type = V_MSG;
		if ((v.v.msg.msg = malloc(datalen)) == NULL)
			fatal("malloc");
		memcpy(v.v.msg.msg, imsg.data, datalen);
		v.v.msg.len = datalen;
		pushv(&v);
		imsg_free(&imsg);
                return EVAL_OK;

	case IMSG_CLOSE:
		before_printing();
		printf("subprocess closed the connection\n");
		imsg_free(&imsg);
		return EVAL_ERR;

	case IMSG_MSIZE:
		imsg_free(&imsg);
		goto nextmessage;

	default:
		before_printing();
		printf("got unknown message from subprocess: %d\n",
		    imsg.hdr.type);
		imsg_free(&imsg);
		return EVAL_ERR;
	}
}

static pid_t
spawn_client_proc(void)
{
	const char	*argv[4];
	int		 p[2], out[2], argc = 0;
	pid_t		 pid;

	if (child_out != -1)
		close(child_out);

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, p) == -1)
		fatal("socketpair");

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, out) == -1)
		fatal("socketpair");

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(p[1]);
		close(out[1]);
		child_out = out[0];
		if (ibuf_inuse) {
			msgbuf_clear(&ibuf.w);
			close(ibuf.fd);
		}
		imsg_init(&ibuf, p[0]);
		ibuf_inuse = 1;
		return pid;
	}

	close(p[0]);
	close(out[0]);

	if (dup2(out[1], 1) == -1 ||
	    dup2(out[1], 2) == -1)
		fatal("dup2");

	if (p[1] != 3) {
		if (dup2(p[1], 3) == -1)
			fatal("cannot setup imsg fd");
	} else if (fcntl(F_SETFD, 0) == -1)
		fatal("cannot setup imsg fd");

	argv[argc++] = argv0;
	argv[argc++] = "-Tc";

#if DEBUG
	argv[argc++] = "-v";
#endif

	argv[argc++] = NULL;

	execvp(argv0, (char *const *)argv);
	fatal("execvp");
}

static void
prepare_child_for_test(struct test *t)
{
	struct passwd	*pw;
	struct stat	 sb;

	if (stat(t->dir, &sb) == -1)
		fatal("stat(\"%s\")", t->dir);

	if ((pw = getpwuid(sb.st_uid)) == NULL)
		fatal("getpwuid(%d)", sb.st_uid);

	imsg_compose(&ibuf, IMSG_AUTH, 0, 0, -1,
	    pw->pw_name, strlen(pw->pw_name)+1);
	imsg_compose(&ibuf, IMSG_AUTH_DIR, 0, 0, -1,
	    t->dir, strlen(t->dir)+1);

	if (imsg_flush(&ibuf) == -1)
		fatal("imsg_flush");
}

static int
run_test(struct test *t)
{
	pid_t	pid;
	int	ret;

#if DEBUG
	before_printing();
	puts("=====================");
	pp_block(t->body);
	puts("=====================");
#endif

        if (stackh != 0)
		popvn(stackh);

	if (t->body == NULL) {
		before_printing();
		printf("no instructions, skipping...\n");
		return EVAL_SKIP;
	}

	pid = spawn_client_proc();
        prepare_child_for_test(t);
	ret = eval(t->body);

	imsg_compose(&ibuf, IMSG_CONN_GONE, 0, 0, -1, NULL, 0);
	imsg_flush(&ibuf);

	while (waitpid(pid, NULL, 0) != pid)
		; /* nop */

	check_for_output();

	if (t->shouldfail) {
		if (ret == EVAL_OK) {
			before_printing();
			printf("test was expected to fail\n");
			return EVAL_ERR;
		} else if (ret == EVAL_ERR)
			return EVAL_OK;
	}

	return ret;
}

int
main(int argc, char **argv)
{
	struct test	*t;
	int		 ch, i, r, passed = 0, failed = 0, skipped = 0;
	int		 runclient = 0;
	const char	*pat = NULL;
	regex_t		 reg;

	assert(argv0 = argv[0]);

	signal(SIGPIPE, SIG_IGN);

	log_init(1, LOG_DAEMON);
	log_setverbose(1);

	/* prepare the global env */
	pushenv();

	add_builtin_proc("print", builtin_print, 1, 1);
	add_builtin_proc("debug", builtin_debug, 1, 1);
	add_builtin_proc("skip", builtin_skip, 0, 0);
	add_builtin_proc("iota", builtin_iota, 0, 0);
	add_builtin_proc("send", builtin_send, 2, 1);
	add_builtin_proc("recv", builtin_recv, 0, 0);

	while ((ch = getopt(argc, argv, "nT:vx:")) != -1) {
		switch (ch) {
		case 'n':
			syntaxcheck = 1;
			break;
		case 'T':
			assert(*optarg == 'c');
                        runclient = 1;
			break;
		case 'v':
			debug = 1;
			break;
		case 'x':
			pat = optarg;
			break;
		default:
			fprintf(stderr, "Usage: %s [-nv] [files...]\n",
			    *argv);
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (runclient)
		client(1, debug);

	if (pat == NULL)
		pat = ".*";

	if (regcomp(&reg, pat, REG_BASIC | REG_ICASE | REG_NOSUB) != 0)
		fatalx("invalid regexp: %s", pat);

	for (i = 0; i < argc; ++i)
		loadfile(argv[i]);

	if (syntaxcheck) {
		fprintf(stderr, "files OK\n");
		return 0;
	}

	/* Check for root privileges. */
        if (geteuid())
                fatalx("need root privileges");

	i = 0;
	TAILQ_FOREACH(t, &tests, entry) {
		if (regexec(&reg, t->name, 0, NULL, 0) != 0)
			continue;

		printf("===> [%d/%d] running test \"%s\"... ", i+1, ntests,
		    t->name);
		fflush(stdout);

		filler = "\n";
		r = run_test(t);
		if (filler == NULL)
			printf("=> test ");

		switch (r) {
		case EVAL_OK:
			printf("passed\n");
			passed++;
			break;
		case EVAL_ERR:
			failed++;
			printf("failed\n");
			break;
		case EVAL_SKIP:
			printf("skipped\n");
			skipped++;
			break;
		}

		if (filler == NULL)
			printf("\n");
		i++;
	}

	printf("\n");
	printf("%d/%d passed (%d skipped and %d failed)\n",
	    passed, i, skipped, failed);

	popenv();
	free(lastmsg);
	regfree(&reg);

	return failed != 0;
}
