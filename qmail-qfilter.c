/*
 * $Id: qmail-qfilter.c,v 1.25 2024-05-09 22:03:17+05:30 mbhangui Exp mbhangui $
 *
 * Copyright (C) 2001,2004-2005 Bruce Guenter <bruceg@em.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "substdio.h"
#include "env.h"
#include "scan.h"
#include "alloc.h"
#include "str.h"
#include "fmt.h"
#include "byte.h"
#include "wait.h"
#include "error.h"
#include "custom_error.h"

#ifndef TMPDIR
#define TMPDIR "/tmp"
#endif

#ifndef BUFSIZE
#define BUFSIZE 4096
#endif

#ifndef QMAIL_QUEUE
#define QMAIL_QUEUE "bin/qmail-queue"
#endif

#define QQ_OOM 51
#define QQ_PERM_MSG_REJECT 31
#define QQ_WRITE_ERROR 53
#define QQ_READ_ERROR 54
#define QQ_TEMP_MSG_REJECT 71
#define QQ_INTERNAL 81
#define QQ_BAD_ENV 91
#define QQ_DROP_MSG 99
#define QQ_WAITPID_SURPRISE  122

#define MSGIN  0
#define MSGOUT 1
#define ENVIN  3
#define ENVOUT 4
#define QQFD   5

#define memcpy(x,y,z)      byte_copy((x), (z), (y))

static const char* qqargv[2] = { QMAIL_QUEUE, 0 };

static size_t   env_len;
static size_t   msg_len;
char            strnum[FMT_ULONG];

/*
 * Parse the sender address into user and host portions
 */
size_t
parse_sender(char *env)
{
	char           *ptr = env;
	int             at, len;

	for (len = 0; *ptr != 'F' && len < env_len; len++, ptr++);
	if (*ptr != 'F')
		custom_error("qmail-qfilter", "Z", "bad envelope", 0, "X.3.0");
	ptr++;
	len++;
	if (!env_unset("QMAILNAME"))
		_exit(QQ_OOM);
	if (!*ptr) {
		if (!env_put("QMAILUSER=") || !env_put("QMAILHOST="))
			_exit(QQ_OOM);
		return 2;
	}
	at = str_rchr(ptr, '@');
	if (ptr[at]) {
		if (!env_put2("QMAILHOST", ptr + at + 1))
			_exit(QQ_OOM);
		ptr[at] = 0;
		if (!env_put2("QMAILUSER", ptr))
			_exit(QQ_OOM);
		ptr[at] = '@';
	} else {
		if (!env_put2("QMAILUSER", ptr))
			_exit(QQ_OOM);
		if (!env_put("QMAILHOST="))
			_exit(QQ_OOM);
	}
	for (; *ptr; len++, ptr++);
	return (len + 1);
}

void
parse_rcpts(char *env, int offset)
{
	size_t          len = env_len - offset;
	char           *ptr = env + offset;
	char           *buf = alloc(len);
	char           *tmp = buf;
	unsigned long   count;

	count = 0;
	while (ptr < env + env_len && *ptr == 'T') {
		size_t          rcptlen = str_len(++ptr);
		memcpy(tmp, ptr, rcptlen);
		tmp[rcptlen] = '\n';
		tmp += rcptlen + 1;
		ptr += rcptlen + 1;
		++count;
	}
	*tmp = 0;
	if (!env_put2("QMAILRCPTS", buf))
		_exit(QQ_OOM);
	strnum[fmt_ulong(strnum, count)] = 0;
	if (!env_put2("NUMRCPTS", strnum))
		_exit(QQ_OOM);
	alloc_free(buf);
}

void
parse_envelope(void)
{
	char           *env;
	size_t          offset;

	if ((env = mmap(0, env_len, PROT_READ|PROT_WRITE, MAP_PRIVATE, ENVIN, 0)) == MAP_FAILED)
		custom_error("qmail-qfilter", "Z", "mmap failed", 0, "X.3.0");
	offset = parse_sender(env);
	parse_rcpts(env, offset);
	munmap((void *) env, env_len);
}

/*
 * Create a temporary invisible file opened for read/write
 */
int
mktmpfile()
{
	char            filename[sizeof (TMPDIR) + 19] = TMPDIR "/fixheaders.XXXXXX";
	int             fd = mkstemp(filename);

	if (fd == -1)
		custom_error("qmail-qfilter", "Z", "unable to create temp file", 0, "X.3.0");
	/*
	 * The following makes the temporary file disappear immediately on
	 * program exit.
	 */
	if (unlink(filename) == -1) {
		close(fd);
		custom_error("qmail-qfilter", "Z", "unable to unlink temp file", 0, "X.3.0");
	}
	return fd;
}

/*
 * Renumber from one FD to another
 */
void
move_fd(int currfd, int newfd)
{
	if (currfd == newfd)
		return;
	if (dup2(currfd, newfd) != newfd)
		custom_error("qmail-qfilter", "Z", "move_fd: dup2 failed", 0, "X.3.0");
	if (close(currfd) != 0)
		custom_error("qmail-qfilter", "Z", "move_fd: close failed", 0, "X.3.0");
}

/*
 * Copy from one FD to a temporary FD
 */
void
copy_fd(int fdin, int fdout, size_t *var)
{
	unsigned long   bytes;
	int             tmp = mktmpfile();

	/*
	 * Copy the message into the temporary file
	 */
	for (bytes = 0;;) {
		char            buf[BUFSIZE];
		ssize_t         rd = read(fdin, buf, BUFSIZE);

		if (rd == -1)
			exit(QQ_READ_ERROR);
		if (rd == 0)
			break;
		if (write(tmp, buf, rd) != rd)
			exit(QQ_WRITE_ERROR);
		bytes += rd;
	}
	close(fdin);
	if (lseek(tmp, 0, SEEK_SET) != 0)
		custom_error("qmail-qfilter", "Z", "unable to lseek", 0, "X.3.0");
	move_fd(tmp, fdout);
	*var = bytes;
}

struct command {
	char          **argv;
	struct command *next;
};
typedef struct command command;

/*
 * Split up the command line into a linked list of separate commands
 */
command        *
parse_args(int argc, char *argv[])
{
	command        *tail = NULL;
	command        *head = NULL;

	while (argc > 0) {
		command        *cmd;
		int             end = 0;
		while (end < argc && str_diff(argv[end], "--"))
			++end;
		if (end == 0)
			_exit(QQ_INTERNAL);
		argv[end] = 0;
		cmd = (command *) alloc(sizeof (command));
		cmd->argv = argv;
		cmd->next = 0;
		if (tail)
			tail->next = cmd;
		else
			head = cmd;
		tail = cmd;
		++end;
		argv += end;
		argc -= end;
	}
	return head;
}

static void
move_unless_empty(int src, int dst, const void *reopen, size_t *var)
{
	struct stat     st;

	if (fstat(src, &st) != 0)
		_exit(QQ_INTERNAL);
	if (st.st_size > 0) {
		move_fd(src, dst);
		*var = st.st_size;
		if (reopen) {
			move_fd(mktmpfile(), src);
			if (src == ENVOUT)
				parse_envelope();
		}
	} else
	if (!reopen)
		close(src);
	if (lseek(dst, 0, SEEK_SET) != 0)
		custom_error("qmail-qfilter", "Z", "unable to lseek", 0, "X.3.0");
}

void
read_qqfd(void)
{
	struct stat     st;
	char           *buf;

	if (fstat(QQFD, &st) != 0)
		_exit(QQ_INTERNAL);
	if (st.st_size > 0) {
		if ((buf = alloc(st.st_size + 1)) == 0)
			_exit(QQ_OOM);
		if (read(QQFD, buf, st.st_size) != st.st_size)
			_exit(QQ_READ_ERROR);
		buf[st.st_size] = 0;
		qqargv[0] = buf;
	}
	close(QQFD);
}

/*
 * Run each of the filters in sequence
 */
void
run_filters(const command *first)
{
	const command  *c;
	int             i;

	move_fd(mktmpfile(), MSGOUT);
	move_fd(mktmpfile(), ENVOUT);

	for (c = first; c; c = c->next) {
		pid_t           pid;
		int             status;

		strnum[fmt_ulong(strnum, env_len)] = 0;
		if (!env_put2("ENVSIZE", strnum))
			_exit(QQ_OOM);
		strnum[fmt_ulong(strnum, msg_len)] = 0;
		if (!env_put2("MSGSIZE", strnum))
			_exit(QQ_OOM);
		if (lseek(1, 0, SEEK_SET) != 0)
			custom_error("qmail-qfilter", "Z", "unable to lseek envelope", 0, "X.3.0");
		switch ((pid = fork()))
		{
			case -1:
				_exit(121);
			case 0:
				execvp(c->argv[0], c->argv);
				_exit(QQ_INTERNAL);
		}
		if ((i = waitpid(pid, &status, 0)) == -1) {
			strnum[fmt_ulong(strnum, errno)] = 0;
			custom_error("qmail-qfilter", "Z", "waitpid error", strnum, "X.3.0");
		}
		if (i != pid)
			_exit(QQ_WAITPID_SURPRISE);
		if (wait_signaled(status)) {
			strnum[fmt_ulong(strnum, wait_termsig(status))] = 0;
			custom_error("qmail-qfilter", "Z", "killed by signal", strnum, "X.3.0");
		}
		if (!wait_exited(status))
			custom_error("qmail-qfilter", "Z", "invalid exit status", 0, "X.3.0");
		switch (i = wait_exitcode(status))
		{
			case 0:
				break;
			case QQ_DROP_MSG:
				_exit(0);
			case QQ_PERM_MSG_REJECT:
			case 100:
				_exit(QQ_PERM_MSG_REJECT);
			case QQ_TEMP_MSG_REJECT:
			case 111:
				_exit(QQ_TEMP_MSG_REJECT);
			default:
				_exit(i);
		}
		move_unless_empty(MSGOUT, MSGIN, c->next, &msg_len);
		move_unless_empty(ENVOUT, ENVIN, c->next, &env_len);
		if (lseek(QQFD, 0, SEEK_SET) != 0)
			custom_error("qmail-qfilter", "Z", "unable to lseek qqfd", 0, "X.3.0");
	}
}

int
main(int argc, char *argv[])
{
	const command  *filters;
	const char *qqq;

	filters = parse_args(argc - 1, argv + 1);

	if ((qqq = getenv("QQF_QMAILQUEUE")) != 0)
		qqargv[0] = qqq;
   
	copy_fd(0, 0, &msg_len);
	copy_fd(1, ENVIN, &env_len);
	parse_envelope();
	move_fd(mktmpfile(), QQFD);
   
	run_filters(filters);
   
	read_qqfd();
	move_fd(ENVIN, 1);
	execv(qqargv[0], (char**)qqargv);
	return QQ_INTERNAL;
}

#ifndef lint
void
getversion_qmail_qfilter_c()
{
	const char     *x = "$Id: qmail-qfilter.c,v 1.25 2024-05-09 22:03:17+05:30 mbhangui Exp mbhangui $";

	x++;
}
#endif

/*
 * $Log: qmail-qfilter.c,v $
 * Revision 1.25  2024-05-09 22:03:17+05:30  mbhangui
 * fix discarded-qualifier compiler warnings
 *
 * Revision 1.24  2024-02-20 22:25:37+05:30  Cprogrammer
 * added exit code 2 (blackhole) for compatibility with qmail-multi
 *
 * Revision 1.23  2024-02-19 22:48:22+05:30  Cprogrammer
 * exit with exit code of filter
 *
 * Revision 1.22  2024-01-23 01:22:51+05:30  Cprogrammer
 * include buffer_defs.h for buffer size definitions
 *
 * Revision 1.21  2023-09-08 00:57:21+05:30  Cprogrammer
 * BUG FIX: qmail-multi, qmail-queue wasn't getting executed
 *
 * Revision 1.20  2023-03-26 08:22:44+05:30  Cprogrammer
 * fixed code for wait_handler
 *
 * Revision 1.19  2022-12-18 11:50:05+05:30  Cprogrammer
 * handle wait status with details
 *
 * Revision 1.18  2022-10-17 19:44:50+05:30  Cprogrammer
 * use exit codes defines from qmail.h
 *
 * Revision 1.17  2022-03-08 22:59:54+05:30  Cprogrammer
 * use custom_error() from custom_error.c
 *
 * Revision 1.16  2021-10-25 09:13:01+05:30  Cprogrammer
 * eliminated mktmpfd() function
 *
 * Revision 1.15  2021-06-12 18:25:31+05:30  Cprogrammer
 * removed #include "auto_qmail.h"
 *
 * Revision 1.14  2021-06-09 19:36:38+05:30  Cprogrammer
 * use qmulti() instead of exec of qmail-multi
 *
 * Revision 1.13  2021-05-29 23:49:54+05:30  Cprogrammer
 * replace str_chr with str_rchr to get domain correctly from email address
 *
 * Revision 1.12  2020-12-07 16:09:42+05:30  Cprogrammer
 * use exit code 79 for envelope format error
 *
 * Revision 1.11  2019-02-17 11:40:14+05:30  Cprogrammer
 * fixed indentation
 *
 * Revision 1.10  2016-06-03 09:58:12+05:30  Cprogrammer
 * moved qmail-multi to sbin
 *
 * Revision 1.9  2011-07-13 20:56:18+05:30  Cprogrammer
 * removed useless close()
 *
 * Revision 1.8  2011-02-17 22:11:19+05:30  Cprogrammer
 * lseek envelope fd
 *
 * Revision 1.7  2009-04-24 23:50:47+05:30  Cprogrammer
 * version 2.1 of qmail-qfilter
 *
 * Revision 1.6  2009-04-22 20:04:30+05:30  Cprogrammer
 * added customized error messages
 *
 * Revision 1.5  2009-04-21 20:43:38+05:30  Cprogrammer
 * use bin/qmail-multi instead of absolute path
 *
 * Revision 1.4  2009-04-02 20:35:42+05:30  Cprogrammer
 * call qmail-multi instead of qmail-queue
 *
 * Revision 1.3  2004-10-22 20:28:40+05:30  Cprogrammer
 * added RCS id
 *
 * Revision 1.2  2004-06-20 17:33:08+05:30  Cprogrammer
 * use setenv() for mysetenv()
 * use mkstemp() instead of tempnam()
 *
 * Revision 1.1  2004-05-23 20:28:44+05:30  Cprogrammer
 * Initial revision
 *
 */
