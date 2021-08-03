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

static struct proc	*curr_proc;
static struct test	*curr_test;

static struct op	*curr_block;

static struct op	*curr_argv;
static int		 curr_argc;

#define STACK_HEIGHT 16
static struct value	vstack[STACK_HEIGHT];
static int		stackh;

static struct value v_false = {.type = V_NUM, .v = {.num = 0}};
static struct value v_true  = {.type = V_NUM, .v = {.num = 1}};

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
pp_val(struct value *val)
{
	switch (val->type) {
	case V_SYM:
		printf("%s", val->v.str);
		break;
	case V_STR:
		printf("\"%s\"", val->v.str);
		break;
	case V_NUM:
	case V_U8:
	case V_U16:
	case V_U32:
		printf("%"PRIu64, val->v.num);
		break;
	default:
		printf("<unknown value>");
		break;
	}
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
		if ((ret = eval(op->v.assert)) != TEST_PASSED)
			return ret;
                popv(&a);
                if (!val_trueish(&a)) {
			printf("assertion failed: ");
			pp_op(op->v.assert);
			printf("\n");
			return TEST_FAILED;
		}
		break;

	case OP_FUNCALL:
		/* TODO: arity check! */

		for (i = 0; i < op->v.funcall.argc; ++i) {
			t = &op->v.funcall.argv[i];
			if ((ret = eval(t)) != TEST_PASSED)
				return ret;
		}

                proc = op->v.funcall.proc;
		if (proc->nativefn != NULL)
			proc->nativefn(i);
		else if ((ret = eval(proc->body)) != TEST_PASSED)
				return ret;
		break;

	case OP_LITERAL:
		pushv(&op->v.literal);
		break;

	case OP_VAR:
		printf("TODO: load variable\n");
		break;

	case OP_CAST:
		printf("TODO: cast value\n");
		break;

	case OP_CMP_EQ:
		if ((ret = eval(op->v.cmp_eq.a)) != TEST_PASSED)
			return ret;
		if ((ret = eval(op->v.cmp_eq.b)) != TEST_PASSED)
			return ret;

		popv(&b);
		popv(&a);
		pushbool(val_eq(&a, &b));

		break;

	default:
		abort();
	}

	if (op->next)
		return eval(op->next);
	return TEST_PASSED;
}

void
prepare_funcall(struct op *base)
{
	if (curr_argv != NULL)
		err(1, "can't funcall during funcall");

	curr_argv = base;
	curr_argc = 0;
}

void
push_arg(struct op *op)
{
	curr_argv->next = op;
	curr_argv = op;
	curr_argc++;
}

struct op *
op_funcall(struct proc *proc, struct op *base)
{
	struct op *op;

	op = newop(OP_FUNCALL);
	op->v.funcall.proc = proc;
	op->v.funcall.argv = base->next;
	op->v.funcall.argc = curr_argc;

	curr_argv = NULL;

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
prepare_proc(char *name)
{
	if (curr_proc != NULL)
		err(1, "can't recursively create a proc!");

	curr_proc = xcalloc(1, sizeof(*curr_proc));
	curr_proc->name = name;

	curr_argv = &curr_proc->tmp_args;

	curr_argv = NULL;
	curr_argc = 0;
}

void
proc_setup_body(void)
{
	struct op *next, *op = curr_proc->tmp_args.next;
	int i;

	i = 0;
	while (op != NULL) {
		if (op->type != OP_VAR)
			errx(1, "invalid argument in proc definition: "
			    "got type %d but want OP_VAR", op->type);
		assert(i < curr_argc && curr_argc < MAXWELEM);
		curr_proc->args[i] = xstrdup(op->v.var);
		next = op->next;
		free_op(op);
	}

	curr_proc->minargs = curr_argc;
}

void
proc_done(void)
{
	TAILQ_INSERT_HEAD(&procs, curr_proc, entry);

	curr_proc = NULL;
}

void
block_push(struct op *op)
{
	if (curr_block == NULL) {
		curr_proc->body = op;
		curr_block = op;
	} else {
		curr_block->next = op;
		curr_block = op;
	}
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
prepare_test(char *name, char *dir)
{
	assert(curr_test == NULL);

	prepare_proc(xstrdup("<test-internal>"));

	curr_test = xcalloc(1, sizeof(*curr_test));
	curr_test->name = name;
	curr_test->dir = dir;
	curr_test->proc = curr_proc;
}

void
test_done(void)
{
	TAILQ_INSERT_HEAD(&tests, curr_test, entry);
	curr_test = NULL;
}

static int
builtin_dummy(int argc)
{
	printf("dummy! yay!\n");
	return 0;
}

static int
run_test(struct test *t)
{
#if DEBUG
	puts("=====================");
	pp_block(t->proc->body);
	puts("=====================");
#endif

	return eval(t->proc->body);
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

	TAILQ_FOREACH(t, &tests, entry) {
                switch (run_test(t)) {
		case TEST_PASSED: passed++; break;
		case TEST_FAILED: failed++; break;
		case TEST_SKIPPED: skipped++; break;
		}
	}

	printf("passed = %d\n", passed);
	printf("failed = %d\n", failed);
	printf("skipped = %d\n", skipped);

	return failed != 0;
}
