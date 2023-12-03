/*
 * netqmail-version without spam filter
 *
 * $Log: spawn-filter.c,v $
 * Revision 1.41  2009-04-03 11:42:48+05:30  Cprogrammer
 * create pipe for error messages
 *
 * Revision 1.40  2009-04-02 15:17:54+05:30  Cprogrammer
 * unset QMAILLOCAL in qmail-remote and unset QMAILREMOTE in qmail-local
 *
 * Revision 1.39  2008-06-12 08:40:55+05:30  Cprogrammer
 * added rulesfile argument
 *
 * Revision 1.38  2008-05-25 17:16:43+05:30  Cprogrammer
 * made message more readable by adding a blank space
 *
 * Revision 1.37  2007-12-20 13:51:54+05:30  Cprogrammer
 * avoid loops with FILTERARGS, SPAMFILTERARGS
 * removed compiler warning
 *
 * Revision 1.36  2006-06-07 14:11:28+05:30  Cprogrammer
 * added SPAMEXT, SPAMHOST, SPAMSENDER, QQEH environment variable
 * unset FILTERARGS before calling filters
 *
 * Revision 1.35  2006-01-22 10:14:45+05:30  Cprogrammer
 * BUG fix for spam mails wrongly getting blackholed
 *
 * Revision 1.34  2005-08-23 17:36:48+05:30  Cprogrammer
 * gcc 4 compliance
 * delete sender in spam notification
 *
 * Revision 1.33  2005-04-02 19:07:47+05:30  Cprogrammer
 * use internal wildmat version
 *
 * Revision 1.32  2004-11-22 19:50:53+05:30  Cprogrammer
 * include regex.h after sys/types.h to avoid compilation prob on RH 7.3
 *
 * Revision 1.31  2004-10-22 20:30:35+05:30  Cprogrammer
 * added RCS id
 *
 * Revision 1.30  2004-10-21 21:56:21+05:30  Cprogrammer
 * change for two additional arguments to strerr_die()
 *
 * Revision 1.29  2004-10-11 14:06:14+05:30  Cprogrammer
 * use control_readulong instead of control_readint
 *
 * Revision 1.28  2004-09-22 23:14:20+05:30  Cprogrammer
 * replaced atoi() with scan_int()
 *
 * Revision 1.27  2004-09-08 10:54:49+05:30  Cprogrammer
 * incorrect exit code in report() function for remote
 * mails. Caused qmail-rspawn to report "Unable to run qmail-remote"
 *
 * Revision 1.26  2004-07-17 21:23:31+05:30  Cprogrammer
 * change qqeh code in qmail-remote
 *
 * Revision 1.25  2004-07-15 23:40:46+05:30  Cprogrammer
 * fixed compilation warning
 *
 * Revision 1.24  2004-07-02 16:15:25+05:30  Cprogrammer
 * override control files rejectspam, spamredirect by
 * environment variables REJECTSPAM and SPAMREDIRECT
 * allow patterns in domain specification in the control files
 * spamfilterargs, filterargs, rejectspam and spamredirect
 *
 * Revision 1.23  2004-06-03 22:58:34+05:30  Cprogrammer
 * fixed compilation problem without indimail
 *
 * Revision 1.22  2004-05-23 22:18:17+05:30  Cprogrammer
 * added envrules filename as argument
 *
 * Revision 1.21  2004-05-19 23:15:07+05:30  Cprogrammer
 * added comments
 *
 * Revision 1.20  2004-05-12 22:37:47+05:30  Cprogrammer
 * added check DATALIMIT check
 *
 * Revision 1.19  2004-05-03 22:17:36+05:30  Cprogrammer
 * use QUEUE_BASE instead of auto_qmail
 *
 * Revision 1.18  2004-02-13 14:51:24+05:30  Cprogrammer
 * added envrules
 *
 * Revision 1.17  2004-01-20 06:56:56+05:30  Cprogrammer
 * unset FILTERARGS for notifications
 *
 * Revision 1.16  2004-01-20 01:52:08+05:30  Cprogrammer
 * report string length corrected
 *
 * Revision 1.15  2004-01-10 09:44:36+05:30  Cprogrammer
 * added comment for exit codes of bogofilter
 *
 * Revision 1.14  2004-01-08 00:32:49+05:30  Cprogrammer
 * use TMPDIR environment variable for temporary directory
 * send spam reports to central spam logger
 *
 * Revision 1.13  2003-12-30 00:44:42+05:30  Cprogrammer
 * set argv[0] from spamfilterprog
 *
 * Revision 1.12  2003-12-22 18:34:25+05:30  Cprogrammer
 * replaced spfcheck() with address_match()
 *
 * Revision 1.11  2003-12-20 01:35:06+05:30  Cprogrammer
 * added wait_pid to prevent zombies
 *
 * Revision 1.10  2003-12-17 23:33:39+05:30  Cprogrammer
 * improved logic for getting remote/local tokens
 *
 * Revision 1.9  2003-12-16 10:38:24+05:30  Cprogrammer
 * fixed incorrect address being returned if filterargs contained local: or
 * remote: directives
 *
 * Revision 1.8  2003-12-15 20:46:19+05:30  Cprogrammer
 * added case 100 to bounce mail
 *
 * Revision 1.7  2003-12-15 13:51:44+05:30  Cprogrammer
 * code to run additional filters using /bin/sh
 *
 * Revision 1.6  2003-12-14 11:36:18+05:30  Cprogrammer
 * added option to blackhole spammers
 *
 * Revision 1.5  2003-12-13 21:08:46+05:30  Cprogrammer
 * extensive rewrite
 * common report() function for local/remote mails to report errors
 *
 * Revision 1.4  2003-12-12 20:20:55+05:30  Cprogrammer
 * use -a option to prevent using header addresses
 *
 * Revision 1.3  2003-12-09 23:37:16+05:30  Cprogrammer
 * change for spawn-filter to be called as qmail-local or qmail-remote
 *
 * Revision 1.2  2003-12-08 23:48:23+05:30  Cprogrammer
 * new function getDomainToken() to retrieve domain specific values
 * read rejectspam and spamredirect only if SPAMEXITCODE is set
 *
 * Revision 1.1  2003-12-07 13:02:00+05:30  Cprogrammer
 * Initial revision
 *
 */
#include "fmt.h"
#include "str.h"
#include "strerr.h"
#include "env.h"
#include "substdio.h"
#include "subfd.h"
#include "stralloc.h"
#include "error.h"
#include "control.h"
#include "wait.h"
#include "qregex.h"
#include "getDomainToken.h"
#include "auto_qmail.h"
#include <regex.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#define REGCOMP(X,Y)    regcomp(&X, Y, REG_EXTENDED|REG_ICASE)
#define REGEXEC(X,Y)    regexec(&X, Y, (size_t) 0, (regmatch_t *) 0, (int) 0)

static int      mkTempFile(int);
static void     report(int, char *, char *, char *, char *, char *, char *);
static int      run_mailfilter(char *, char *, char **);
int             wildmat_internal(char *, char *);

static int      remotE;
stralloc        sender = { 0 };
stralloc        recipient = { 0 };

static void
report(int errCode, char *s1, char *s2, char *s3, char *s4, char *s5, char *s6)
{
	if (!remotE) /*- strerr_die does not return */
		strerr_die(errCode, s1, s2, s3, s4, s5, s6, 0, 0, (struct strerr *) 0);
	/*- h - hard, s - soft */
	if (substdio_put(subfdoutsmall, errCode == 111 ? "s" : "h", 1) == -1)
		_exit(111);
	if (s1 && substdio_puts(subfdoutsmall, s1) == -1)
		_exit(111);
	if (s2 && substdio_puts(subfdoutsmall, s2) == -1)
		_exit(111);
	if (s3 && substdio_puts(subfdoutsmall, s3) == -1)
		_exit(111);
	if (s4 && substdio_puts(subfdoutsmall, s4) == -1)
		_exit(111);
	if (s5 && substdio_puts(subfdoutsmall, s5) == -1)
		_exit(111);
	if (s6 && substdio_puts(subfdoutsmall, s6) == -1)
		_exit(111);
	if (substdio_put(subfdoutsmall, "\0", 1) == -1)
		_exit(111);
	if (substdio_puts(subfdoutsmall, 
		errCode == 111 ?  "Zspawn-filter said: Message deferred" : "DGiving up on spawn-filter\n") == -1)
		_exit(111);
	if (substdio_put(subfdoutsmall, "\0", 1) == -1)
		_exit(111);
	substdio_flush(subfdoutsmall);
	/*- For qmail-rspawn to stop complaining unable to run qmail-remote */
	_exit(0);
}

void
set_environ(char *host, char *sender, char *recipient)
{
	if (!env_put2("DOMAIN", host)) 
		report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	if (!env_put2("_SENDER", sender))
		report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	if (!env_put2("_RECIPIENT", recipient))
		report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	return;
}

static int
run_mailfilter(char *domain, char *mailprog, char **argv)
{
	char            strnum[FMT_ULONG];
	pid_t           filt_pid;
	int             pipefd[2], pipefe[2];
	int             wstat, filt_exitcode, len = 0;
	char           *filterargs;
	static stralloc filterdefs = { 0 };
	static char     errstr[1024];
	char            inbuf[1024];
	char            ch;
	static substdio errbuf;

	if (!(filterargs = env_get("FILTERARGS")))
	{
		if (control_readfile(&filterdefs, "control/filterargs", 0) == -1)
			report(111, "spawn-filter: Unable to read filterargs: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		filterargs = getDomainToken(domain, &filterdefs);
	}
	if (!filterargs)
	{
		execv(mailprog, argv);
		report(111, "spawn-filter: could not exec ", mailprog, ": ", error_str(errno), ". (#4.3.0)", 0);
		_exit(111); /*- To make compiler happy */
	}
	if (pipe(pipefd) == -1)
		report(111, "spawn-filter: Trouble creating pipes: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	if (pipe(pipefe) == -1)
		report(111, "spawn-filter: Trouble creating pipes: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	switch ((filt_pid = fork()))
	{
	case -1:
		report(111, "spawn-filter: Trouble creating child filter: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	case 0: /*- Filter Program */
		set_environ(domain, sender.s, recipient.s);
		/*- Mail content read from fd 0 */
		if (mkTempFile(0))
			report(111, "spawn-filter: lseek error: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		/*- stdout will go here */
		if (dup2(pipefd[1], 1) == -1 || close(pipefd[0]) == -1)
			report(111, "spawn-filter: dup2 error: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		if (pipefd[1] != 1)
			close(pipefd[1]);
		/*- stderr will go here */
		if (dup2(pipefe[1], 2) == -1 || close(pipefe[0]) == -1)
			report(111, "spawn-filter: dup2 error: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		if (pipefe[1] != 2)
			close(pipefe[1]);
		/*- Avoid loop if program(s) defined by FILTERARGS call qmail-inject, etc */
		if (!env_unset("FILTERARGS") || !env_unset("SPAMFILTER"))
			report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		execl("/bin/sh", "/bin/sh", "-c", filterargs, (char *) 0);
		report(111, "spawn-filter: could not exec /bin/sh: ",  filterargs, ": ", error_str(errno), ". (#4.3.0)", 0);
	default:
		close(pipefe[1]);
		close(pipefd[1]);
		if (dup2(pipefd[0], 0))
		{
			close(pipefd[0]);
			close(pipefe[0]);
			wait_pid(&wstat, filt_pid);
			report(111, "spawn-filter: dup2 error: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		}
		if (pipefd[0] != 0)
			close(pipefd[0]);
		if (mkTempFile(0))
		{
			close(0);
			close(pipefe[0]);
			wait_pid(&wstat, filt_pid);
			report(111, "spawn-filter: lseek error: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		}
		break;
	}
	/*- Process message if exit code is 0, bounce if 100 */
	if (wait_pid(&wstat, filt_pid) != filt_pid)
	{
		close(0);
		close(pipefe[0]);
		report(111, "spawn-filter: waitpid surprise: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	}
	if (wait_crashed(wstat))
	{
		close(0);
		close(pipefe[0]);
		report(111, "spawn-filter: filter crashed: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	}
	switch (filt_exitcode = wait_exitcode(wstat))
	{
	case 0:
		execv(mailprog, argv);
		report(111, "spawn-filter: could not exec ", mailprog, ": ", error_str(errno), ". (#4.3.0)", 0);
	case 100:
		report(100, "Mail Rejected (#5.7.1)", 0, 0, 0, 0, 0);
	default:
		substdio_fdbuf(&errbuf, read, pipefe[0], inbuf, sizeof(inbuf));
		for (len = 0; substdio_bget(&errbuf, &ch, 1) && len < (sizeof(errstr) - 1); len++)
			errstr[len] = ch;
		errstr[len] = 0;
		strnum[fmt_ulong(strnum, filt_exitcode)] = 0;
		report(111, filterargs, ": (spawn-filter) exit code: ", strnum, *errstr ? ": " : 0, *errstr ? errstr : 0, ". (#4.3.0)");
	}
	/*- Not reached */
	return(111);
}

int
mkTempFile(int seekfd)
{
	char            inbuf[2048], outbuf[2048], strnum[FMT_ULONG];
	char           *tmpdir;
	static stralloc tmpFile = {0};
	struct substdio _ssin;
	struct substdio _ssout;
	int             fd;

	if (lseek(seekfd, 0, SEEK_SET) == 0)
		return (0);
	if (errno == EBADF)
	{
		strnum[fmt_ulong(strnum, seekfd)] = 0;
		report(111, "spawn-filter: fd ", strnum, ": ", error_str(errno), ". (#4.3.0)", 0);
	}
	if (!(tmpdir = env_get("TMPDIR")))
		tmpdir = "/tmp";
	if (!stralloc_copys(&tmpFile, tmpdir))
		report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	if (!stralloc_cats(&tmpFile, "/qmailFilterXXX"))
		report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	if (!stralloc_catb(&tmpFile, strnum, fmt_ulong(strnum, (unsigned long) getpid())))
		report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	if (!stralloc_0(&tmpFile))
		report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	if ((fd = open(tmpFile.s, O_RDWR | O_EXCL | O_CREAT, 0600)) == -1)
		report(111, "spawn-filter: ", tmpFile.s, ": ", error_str(errno), ". (#4.3.0)", 0);
	unlink(tmpFile.s);
	substdio_fdbuf(&_ssout, write, fd, outbuf, sizeof(outbuf));
	substdio_fdbuf(&_ssin, read, seekfd, inbuf, sizeof(inbuf));
	switch (substdio_copy(&_ssout, &_ssin))
	{
	case -2: /*- read error */
		report(111, "spawn-filter: read error: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	case -3: /*- write error */
		report(111, "spawn-filter: write error: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	}
	if (substdio_flush(&_ssout) == -1)
		report(111, "spawn-filter: write error: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	if (dup2(fd, seekfd) == -1)
		report(111, "spawn-filter: dup2 error: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	if (lseek(seekfd, 0, SEEK_SET) != 0)
		report(111, "spawn-filter: lseek: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	return (0);
}

int
main(int argc, char **argv)
{
	char           *ptr, *mailprog, *domain, *ext;
	int             len;

	len = str_len(argv[0]);
	for (ptr = argv[0] + len;*ptr != '/' && ptr != argv[0];ptr--);
	if (*ptr && *ptr == '/')
		ptr++;
	ptr += 6;
	if (*ptr == 'l') /*- qmail-local Filter */
	{
		mailprog = "bin/qmail-local";
		ext = argv[6];
		domain = argv[7];
		remotE = 0;
		if (!env_unset("QMAILREMOTE"))
			report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		/*- sender */
		if (!stralloc_copys(&sender, argv[8]))
			report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		if (!stralloc_0(&sender))
			report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		/*- recipient */
		if (*ext) { /*- EXT */
			if (!stralloc_copys(&recipient, ext))
				report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		} else /*- user */
		if (!stralloc_copys(&recipient, argv[2]))
			report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		if (!stralloc_cats(&recipient, "@"))
			report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		if (!stralloc_cats(&recipient, domain))
			report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		if (!stralloc_0(&recipient))
			report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	} else
	if (*ptr == 'r') /*- qmail-remote Filter */
	{
		mailprog = "bin/qmail-remote";
		domain = argv[1];
		remotE = 1;
		if (!env_unset("QMAILLOCAL"))
			report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		/*- sender */
		if (!stralloc_copys(&sender, argv[2]))
			report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		if (!stralloc_0(&sender))
			report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		/*- recipient */
		if (!stralloc_copys(&recipient, argv[3]))
			report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
		if (!stralloc_0(&recipient))
			report(111, "spawn-filter: out of mem: ", error_str(errno), ". (#4.3.0)", 0, 0, 0);
	} else
	{
		report(111, "spawn-filter: Incorrect usage. ", argv[0], " (#4.3.0)", 0, 0, 0);
		_exit(111);
	}
	if (chdir(auto_qmail) == -1)
		report(111, "spawn-filter: Unable to switch to ", auto_qmail, ": ", error_str(errno), ". (#4.3.0)", 0);
	run_mailfilter(domain, mailprog, argv);
	report(111, "spawn-filter: could not exec ", mailprog, ": ", error_str(errno), ". (#4.3.0)", 0);
	/*- Not reached */
	return(0);
}

void
getversion_qmail_spawn_filter_c()
{
	static char    *x = "$Id: spawn-filter.c,v 1.41 2009-04-03 11:42:48+05:30 Cprogrammer Stab mbhangui $";

	x++;
}
