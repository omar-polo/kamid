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

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "utils.h"
#include "script.h"
#include "log.h"

#define DEBUG 0

static struct procs procs = TAILQ_HEAD_INITIALIZER(procs);
static struct tests tests = TAILQ_HEAD_INITIALIZER(tests);

static struct opstacks blocks = TAILQ_HEAD_INITIALIZER(blocks);
static struct opstacks args   = TAILQ_HEAD_INITIALIZER(args);

#define STACK_HEIGHT 16
static struct value	vstack[STACK_HEIGHT];
static int		stackh;

static struct envs envs = TAILQ_HEAD_INITIALIZER(envs);

static struct value v_false = {.type = V_NUM, .v = {.num = 0}};
static struct value v_true  = {.type = V_NUM, .v = {.num = 1}};

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

	TAILQ_FOREACH_SAFE(b, &e->bindings, entry, tb) {
                free(b->name);
		switch (b->val.type) {
		case V_SYM:
		case V_STR:
			free(b->val.v.str);
			break;
		}
		free(b);
	}

	free(e);
}

static inline int
setvar(char *sym, struct op *op)
{
	struct binding	*b;
	struct env	*e;
	int		 ret;

	if ((ret = eval(op)) != EVAL_OK)
		return ret;

	b = xcalloc(1, sizeof(*b));
	b->name = sym;
	popv(&b->val);

	e = TAILQ_FIRST(&envs);
	TAILQ_INSERT_HEAD(&e->bindings, b, entry);

	return EVAL_OK;
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

	fprintf(stderr, "unbound variable %s\n", sym);
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
free_op(struct op *op)
{
	/* TODO: probably more... */
	free(op);
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

void
ppf_val(FILE *f, struct value *val)
{
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

int
val_trueish(struct value *a)
{
	return a->type == V_NUM && a->v.num;
}

static inline int
val_isnum(struct value *a)
{
	return a->type == V_NUM
		|| a->type == V_U8
		|| a->type == V_U16
		|| a->type == V_U32;
}

static inline int64_t
val_tonum(struct value *a)
{
	switch (a->type) {
	case V_NUM: return a->v.num;
	case V_U8:  return a->v.u8;
	case V_U16: return a->v.u16;
	case V_U32: return a->v.u32;
	default:
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
			fprintf(stderr, "can't cast %"PRIu64		\
			    " to %s\n", val, pp_totype(totype));	\
			return EVAL_ERR;				\
		}							\
		a->type = totype;					\
		a->v.t = (c)val;					\
		return EVAL_OK;						\
	} while (0)

	if (!val_isnum(a)) {
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
		fprintf(stderr, "can't cast %"PRIu64" to %s\n",
		    v, pp_totype(totype));
		return EVAL_ERR;
	}

#undef NUMCAST
}

void
pp_op(struct op *op)
{
	struct op	*aux;

	switch (op->type) {
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
	struct op	*t;
	int		 i, ret;

#if DEBUG
        pp_op(op);
	printf("\n");
#endif

	switch (op->type) {
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
			/* push arguments on the stack */
			t = op->v.funcall.argv;
			if (t != NULL && (ret = eval(t)) != EVAL_OK)
				return ret;
			if ((ret = proc->nativefn(op->v.funcall.argc))
			    != EVAL_OK)
				return ret;
		} else {
			pushenv();

			for (t = op->v.funcall.argv, i = 0;
			     t != NULL;
			     t = t->next, i++) {
				if ((ret = setvar(proc->args[i], t))
				    != EVAL_OK)
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

	default:
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
add_builtin_proc(const char *name, int (*fn)(int), int argc)
{
	struct proc *proc;

	proc = xcalloc(1, sizeof(*proc));
	proc->name = xstrdup(name);
	proc->nativefn = fn;
	proc->minargs = argc;

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
		 * TODO: should free the whole list but.., we're gonna
		 * exit real soon(tm)!
		 */
		if (op->type != OP_VAR)
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
		proc->args[i] = xstrdup(op->v.var);

		next = op->next;
		free_op(op);
		op = next;
	}
	assert(i == argc);

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
test_done(char *name, char *dir)
{
	struct test	*test;

	test = xcalloc(1, sizeof(*test));
	test->name = name;
	test->dir = dir;
	test->body = finalize(&blocks, NULL);

	if (TAILQ_EMPTY(&tests))
		TAILQ_INSERT_HEAD(&tests, test, entry);
	else
		TAILQ_INSERT_TAIL(&tests, test, entry);
}

static int
builtin_pp(int argc)
{
	struct value v;

	popv(&v);
	pp_val(&v);
	printf("\n");

	return EVAL_OK;
}

static int
builtin_skip(int argc)
{
	return EVAL_SKIP;
}

static int
run_test(struct test *t)
{
#if DEBUG
	puts("=====================");
	pp_block(t->body);
	puts("=====================");
#endif

	return eval(t->body);
}

int
main(int argc, char **argv)
{
	struct env	*e;
	struct test	*t;
	int		 i, passed = 0, failed = 0, skipped = 0;

	log_init(1, LOG_DAEMON);
	log_setverbose(1);

	/* prepare the global env */
	pushenv();

	add_builtin_proc("pp", builtin_pp, 1);
	add_builtin_proc("skip", builtin_skip, 0);

	for (i = 1; i < argc; ++i)
		loadfile(argv[i]);

	i = 0;
	TAILQ_FOREACH(t, &tests, entry) {
		printf("===> running test \"%s\"... ", t->name);
		fflush(stdout);

		switch (run_test(t)) {
		case EVAL_OK:
			printf("ok!\n");
			passed++;
			break;
		case EVAL_ERR:
			failed++;
			/* we've already printed the failure */
			printf("\n");
			break;
		case EVAL_SKIP:
			printf("skipped!\n");
			skipped++;
			break;
		}

		i++;
	}

	printf("passed %d/%d\n", passed, i);
	printf("failed %d\n", failed);
	printf("skipped %d\n", skipped);

	popenv();

	return failed != 0;
}
