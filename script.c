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

static struct value v_false = {.type = V_NUM, .v = {.num = 0}};
static struct value v_true  = {.type = V_NUM, .v = {.num = 1}};

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

void
global_set(char *sym, struct op *op)
{
	assert(op->type == OP_LITERAL);
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
	op->v.literal.type = V_NUM;
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
	case V_U8:
	case V_U16:
	case V_U32:
		fprintf(f, "%"PRIu64, val->v.num);
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

int
val_eq(struct value *a, struct value *b)
{
	if (val_isnum(a) && val_isnum(b))
		return a->v.num == b->v.num;

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
	uint64_t v;

#define NUMCAST(v, totype, max) do {				\
		if (v >= max) {					\
			fprintf(stderr, "Can't cast %"PRIu64	\
			    " to %s\n", v, pp_totype(totype));	\
			return EVAL_ERR;			\
		}						\
		a->type = totype;				\
		return EVAL_OK;					\
	} while (0)

	if (!val_isnum(a)) {
		fprintf(stderr, "Can't cast ");
		ppf_val(stderr, a);
		fprintf(stderr, " to type %s\n", pp_totype(totype));
		return EVAL_ERR;
	}

	v = a->v.num;
	switch (totype) {
	case V_U8:  NUMCAST(v, totype, UINT8_MAX);
	case V_U16: NUMCAST(v, totype, UINT16_MAX);
	case V_U32: NUMCAST(v, totype, UINT32_MAX);
	default:
		fprintf(stderr, "Can't cast %"PRIu64" to %s\n",
		    v, pp_totype(totype));
		return EVAL_ERR;
	}

#undef NUMCAST
}

void
pp_op(struct op *op)
{
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
		printf("funcall()");
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
		printf("TODO: assignment\n");
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
		/* TODO: arity check! */

		for (i = 0; i < op->v.funcall.argc; ++i) {
			t = &op->v.funcall.argv[i];
			if ((ret = eval(t)) != EVAL_OK)
				return ret;
		}

                proc = op->v.funcall.proc;
		if (proc->nativefn != NULL)
			proc->nativefn(i);
		else if ((ret = eval(proc->body)) != EVAL_OK)
				return ret;
		break;

	case OP_LITERAL:
		pushv(&op->v.literal);
		break;

	case OP_VAR:
		printf("TODO: load variable\n");
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
add_builtin_proc(const char *name, int (*fn)(int))
{
	struct proc *proc;

	proc = xcalloc(1, sizeof(*proc));
	proc->name = xstrdup(name);
	proc->nativefn = fn;

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
builtin_dummy(int argc)
{
	printf("dummy! yay!\n");
	return EVAL_OK;
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
	struct test	*t;
	int		 i, passed = 0, failed = 0, skipped = 0;

	log_init(1, LOG_DAEMON);
	log_setverbose(1);

	add_builtin_proc("dummy", builtin_dummy);

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

	return failed != 0;
}
