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

#ifndef SCRIPT_H
#define SCRIPT_H

#include "compat.h"

#include <stdio.h>

#include "kamid.h"

enum {
	/* literals */
	V_SYM,
	V_STR,
	V_NUM,

	/* foreign */
	V_QID,

	/* casted */
	V_U8,
	V_U16,
	V_U32,
};

struct value {
	int type;
	union {
		char		*str;
		int64_t		 num;
		uint8_t		 u8;
		uint16_t	 u16;
		uint32_t	 u32;
		uint8_t		 qid[QIDSIZE];
	} v;
};

enum {
	OP_ASSIGN,
	OP_ASSERT,
	OP_FUNCALL,
	OP_LITERAL,
	OP_VAR,
	OP_CAST,
	OP_CMP_EQ,
};

struct proc;

struct op {
	struct op	*next;
	int		 type;
	union {
		struct {
			char		*name;
			struct op	*expr;
		} assign;
		struct op		*assert;
		struct {
			struct proc	*proc;
			struct op	*argv;
			int		 argc;
		} funcall;
		struct value literal;
		char *var;
		struct {
			struct op	*expr;
			int		 totype;
		} cast;
		struct {
			struct op	*a;
			struct op	*b;
		} cmp_eq;
	} v;
};

TAILQ_HEAD(bindings, binding);
struct binding {
	char			*name;
	struct value		 val;
	TAILQ_ENTRY(binding)	 entry;
};

TAILQ_HEAD(envs, env);
struct env {
	TAILQ_ENTRY(env)	 entry;
	struct bindings		 bindings;
};

TAILQ_HEAD(opstacks, opstack);
struct opstack {
	TAILQ_ENTRY(opstack)	 entry;
	struct op		 base;
	struct op		*last;
	int			 counter;
};

TAILQ_HEAD(procs, proc);
struct proc {
	TAILQ_ENTRY(proc)	 entry;
	char			*name;
	int			 minargs;
	int			 vararg;
	char			*args[MAXWELEM];
	struct op		*body;
	int			(*nativefn)(int);
};

TAILQ_HEAD(tests, test);
struct test {
	TAILQ_ENTRY(test)	 entry;
	char			*name;
	char			*dir;
	struct op		*body;
};

enum {
	EVAL_OK,
	EVAL_ERR,
	EVAL_SKIP,
};

int		 global_set(char *, struct op *);

struct op	*newop(int);
void		 free_op(struct op *);
struct op	*op_assign(char *, struct op *);
struct op	*op_assert(struct op *);
struct op	*op_var(char *);
struct op	*op_lit_str(char *);
struct op	*op_lit_num(uint64_t);
struct op	*op_cmp_eq(struct op *, struct op *);
struct op	*op_cast(struct op *, int);

void		 ppf_val(FILE *, struct value *);
void		 pp_val(struct value *);
int		 val_trueish(struct value *);
int		 val_eq(struct value *, struct value *);
int		 val_cast(struct value *, int);
void		 pp_op(struct op *);
void		 pp_block(struct op *);
int		 eval(struct op *);

/* funcall */
void		 prepare_funcall(void);
void		 push_arg(struct op *);
struct op	*op_funcall(struct proc *);

/* proc */
void		 add_builtin_proc(const char *name, int (*)(int), int, int);
void		 prepare_proc(void);
/* push_arg works on procs too */
int		 proc_setup_body(void);
void		 proc_done(char *name);
void		 block_push(struct op *);
struct proc	*proc_by_name(const char *);

/* testing */
void		 prepare_test(void);
void		 test_done(char *, char *);

/* np.y */
void		 loadfile(const char *);

#endif
