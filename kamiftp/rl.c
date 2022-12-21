/*
 * Copyright (c) 2022 Omar Polo <op@omarpolo.com>
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

#if !HAVE_READLINE

#include <stdio.h>
#include <string.h>

char *
readline(const char *prompt)
{
	char *ch, *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;

	printf("%s", prompt);
	fflush(stdout);

	linelen = getline(&line, &linesize, stdin);
	if (linelen == -1)
		return NULL;

	if ((ch = strchr(line, '\n')) != NULL)
		*ch = '\0';
	return line;
}

void
add_history(const char *line)
{
	return;
}

void
compl_setup(void)
{
	return;
}

#else /* HAVE_READLINE */

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "kami.h"
#include "kamiftp.h"

struct compl_state {
	size_t		  size;
	size_t		  len;
	char		**entries;
};

static struct compl_state compl_state;
static char compl_prfx[PATH_MAX];

static void
compl_state_reset(void)
{
	size_t i;

	for (i = 0; i < compl_state.len; ++i)
		free(compl_state.entries[i]);
	free(compl_state.entries);

	memset(&compl_state, 0, sizeof(compl_state));
}

static int
compl_add_entry(const struct np_stat *st)
{
	const char	*sufx = "";
	char		*dup;
	int		 r;

	if (compl_state.len == compl_state.size) {
		size_t newsz = compl_state.size * 1.5;
		void *t;

		if (newsz == 0)
			newsz = 16;

		/* one for the NULL entry at the end */
		t = recallocarray(compl_state.entries, compl_state.size,
		    newsz + 1, sizeof(char *));
		if (t == NULL)
			return -1;
		compl_state.entries = t;
		compl_state.size = newsz;
	}

	if (st->qid.type & QTDIR)
		sufx = "/";

	if (asprintf(&dup, "%s%s%s", compl_prfx, st->name, sufx) == -1)
		return -1;
	compl_state.entries[compl_state.len++] = dup;
	return 0;
}

static void
cleanword(char *buf, int brkspc)
{
	char	*cmd;
	int	 escape, quote;

	while (brkspc && isspace((unsigned char)*buf))
		memmove(buf, buf + 1, strlen(buf));

	escape = quote = 0;
	for (cmd = buf; *cmd != '\0'; ++cmd) {
		if (escape) {
			escape = 0;
			continue;
		}
		if (*cmd == '\\')
			goto skip;
		if (*cmd == quote) {
			quote = 0;
			goto skip;
		}
		if (*cmd == '\'' || *cmd == '"') {
			quote = *cmd;
			goto skip;
		}
		if (quote)
			continue;
		if (brkspc && isspace((unsigned char)*cmd))
			break;
		continue;

	skip:
		memmove(cmd, cmd + 1, strlen(cmd));
		cmd--;
	}
	*cmd = '\0';
}

static int
tellcmd(char *buf)
{
	size_t i;

	cleanword(buf, 1);
	for (i = 0; i < nitems(cmds); ++i) {
		if (!strcmp(cmds[i].name, buf))
			return cmds[i].cmdtype;
	}

	return CMD_UNKNOWN;
}

static int
tell_argno(const char *cmd, int *cmdtype)
{
	char		 cmd0[64];	/* plenty of space */
	const char	*start = cmd;
	int		 escape, quote;
	int		 argno = 0;

	*cmdtype = CMD_UNKNOWN;

	/* find which argument needs to be completed */
	while (*cmd) {
		while (isspace((unsigned char)*cmd))
			cmd++;
		if (*cmd == '\0')
			break;

		escape = quote = 0;
		for (; *cmd; ++cmd) {
			if (escape) {
				escape = 0;
				continue;
			}
			if (*cmd == '\\') {
				escape = 1;
				continue;
			}
			if (*cmd == quote) {
				quote = 0;
				continue;
			}
			if (*cmd == '\'' || *cmd == '\"') {
				quote = *cmd;
				continue;
			}
			if (quote)
				continue;
			if (isspace((unsigned char)*cmd))
				break;
		}
		if (isspace((unsigned char)*cmd))
			argno++;

		if (argno == 1 && strlcpy(cmd0, start, sizeof(cmd0)) <
		    sizeof(cmd0))
			*cmdtype = tellcmd(cmd0);
	}

	return argno;
}

static char *
ftp_cmdname_generator(const char *text, int state)
{
	static size_t	 i, len;
	struct cmd	*cmd;

	if (state == 0) {
		i = 0;
		len = strlen(text);
	}

	while (i < nitems(cmds)) {
		cmd = &cmds[i++];
		if (strncmp(text, cmd->name, len) == 0)
			return strdup(cmd->name);
	}

	return NULL;
}

static char *
ftp_bool_generator(const char *text, int state)
{
	static const char	*toks[] = { "on", "off" };
	static size_t		 i, len;
	const char		*tok;

	if (state == 0) {
		i = 0;
		len = strlen(text);
	}

	while ((tok = toks[i++]) != NULL) {
		if (strncmp(text, tok, len) == 0)
			return strdup(tok);
	}
	return NULL;
}

static char *
ftp_dirent_generator(const char *text, int state)
{
	static size_t	 i, len;
	const char	*entry;

	if (state == 0) {
		i = 0;
		len = strlen(text);
	}

	while (i < compl_state.len) {
		entry = compl_state.entries[i++];
		if (strncmp(text, entry, len) == 0)
			return strdup(entry);
	}
	return NULL;
}

static char **
ftp_remote_files(const char *text, int start, int end)
{
	const char	*dir;
	char		 t[PATH_MAX];
	char		*s, *e;

	strlcpy(t, text, sizeof(t));
	cleanword(t, 0);

	if (!strcmp(t, "..")) {
		char **cs;
		if ((cs = calloc(2, sizeof(*cs))) == NULL)
			return NULL;
		cs[0] = strdup("../");
		return cs;
	}

	s = t;
	if (!strncmp(s, "./", 2)) {
		s++;
		while (*s == '/')
			s++;
	}

	if ((e = strrchr(s, '/')) != NULL)
		e[1] = '\0';
	dir = t;

	if (!strcmp(dir, "."))
		strlcpy(compl_prfx, "", sizeof(compl_prfx));
	else
		strlcpy(compl_prfx, dir, sizeof(compl_prfx));

	compl_state_reset();
	if (dir_listing(dir, compl_add_entry, 0) == -1)
		return NULL;
	return rl_completion_matches(text, ftp_dirent_generator);
}

static char **
ftp_completion(const char *text, int start, int end)
{
	int	 argno, cmdtype;
	char	*line;

	/* don't fall back on the default completion system by default */
	rl_attempted_completion_over = 1;

	if ((line = rl_copy_text(0, start)) == NULL)
		return NULL;

	argno = tell_argno(line, &cmdtype);
	free(line);
	if (argno == 0)
		return rl_completion_matches(text, ftp_cmdname_generator);

	switch (cmdtype) {
	case CMD_BELL:
	case CMD_HEXDUMP:
	case CMD_VERBOSE:
		if (argno != 1)
			return NULL;
		return rl_completion_matches(text, ftp_bool_generator);

	case CMD_BYE:
	case CMD_LPWD:
		/* no args */
		return NULL;

	case CMD_CD:
	case CMD_EDIT:
	case CMD_LS:
	case CMD_PAGE:
		if (argno != 1)
			return NULL;
		/* fallthrough */
	case CMD_RM:
		return ftp_remote_files(text, start, end);

	case CMD_GET:
		if (argno > 2)
			return NULL;
		if (argno == 2)
			return ftp_remote_files(text, start, end);
		/* try local */
		rl_attempted_completion_over = 0;
		return NULL;

	case CMD_LCD:
		if (argno != 1)
			return NULL;
		/* try local  */
		rl_attempted_completion_over = 0;
		return NULL;

	case CMD_PIPE:
		if (argno > 2)
			return NULL;
		if (argno == 1)
			return ftp_remote_files(text, start, end);
		/* try local */
		rl_attempted_completion_over = 0;
		return NULL;

	case CMD_PUT:
		if (argno > 2)
			return NULL;
		if (argno == 1) {
			/* try local */
			rl_attempted_completion_over = 0;
			return NULL;
		}
		return ftp_remote_files(text, start, end);

	case CMD_RENAME:
		if (argno > 2)
			return NULL;
		return ftp_remote_files(text, start, end);
	}

	return NULL;
}

static int
ftp_quoted(char *line, int index)
{
	if (index > 0 && line[index - 1] == '\\')
		return !ftp_quoted(line, index - 1);
	return 0;
}

void
compl_setup(void)
{
	rl_attempted_completion_function = ftp_completion;
	rl_completer_word_break_characters = "\t ";
	rl_completer_quote_characters = "\"'";
	rl_char_is_quoted_p = ftp_quoted;
}

#endif
