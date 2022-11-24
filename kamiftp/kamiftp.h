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

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

enum ftp_cmd {
	CMD_UNKNOWN,
	CMD_BELL,
	CMD_BYE,
	CMD_CD,
	CMD_EDIT,
	CMD_GET,
	CMD_HEXDUMP,
	CMD_LCD,
	CMD_LPWD,
	CMD_LS,
	CMD_PAGE,
	CMD_PIPE,
	CMD_PUT,
	CMD_RENAME,
	CMD_RM,
	CMD_VERBOSE,
};

void	 compl_setup(void);

#if !HAVE_READLINE
char	*readline(const char *);
void	 add_history(const char *);
#endif

int	 dir_listing(const char *, int (*)(const struct np_stat *), int);

void	 cmd_bell(int, const char **);
void	 cmd_bye(int, const char **);
void	 cmd_cd(int, const char **);
void	 cmd_edit(int, const char **);
void	 cmd_get(int, const char **);
void	 cmd_hexdump(int, const char **);
void	 cmd_lcd(int, const char **);
void	 cmd_lpwd(int, const char **);
void	 cmd_ls(int, const char **);
void	 cmd_page(int, const char **);
void	 cmd_pipe(int, const char **);
void	 cmd_put(int, const char **);
void	 cmd_rename(int, const char **);
void	 cmd_rm(int, const char **);
void	 cmd_verbose(int, const char **);

struct cmd {
	const char	*name;
	int		 cmdtype;
	void		(*fn)(int, const char **);
};

static struct cmd cmds[] = {
	{"bell",	CMD_BELL,	cmd_bell},
	{"bye",		CMD_BYE,	cmd_bye},
	{"cd",		CMD_CD,		cmd_cd},
	{"edit",	CMD_EDIT,	cmd_edit},
	{"get",		CMD_GET,	cmd_get},
	{"hexdump",	CMD_HEXDUMP,	cmd_hexdump},
	{"lcd",		CMD_LCD,	cmd_lcd},
	{"lpwd",	CMD_LPWD,	cmd_lpwd},
	{"ls",		CMD_LS,		cmd_ls},
	{"page",	CMD_PAGE,	cmd_page},
	{"pipe",	CMD_PIPE,	cmd_pipe},
	{"put",		CMD_PUT,	cmd_put},
	{"quit",	CMD_BYE,	cmd_bye},	/* alias */
	{"rename",	CMD_RENAME,	cmd_rename},
	{"rm",		CMD_RM,		cmd_rm},
	{"verbose",	CMD_VERBOSE,	cmd_verbose},
};
