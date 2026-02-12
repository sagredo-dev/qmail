/*
 * $Id: custom_error.c,v 1.4 2025-01-22 00:30:36+05:30 Cprogrammer Exp mbhangui $
 */
#include <unistd.h>
#include "substdio.h"
#include "env.h"
#include "scan.h"
#include "custom_error.h"
#include "qmail.h"

void
custom_error(const char *program, const char *type, const char *message, const char *extra, const char *code)
{
	const char     *c;
	char            errbuf[256];
	int             errfd;
	struct substdio sserr;

	if (!(c = env_get("ERROR_FD")))
		errfd = CUSTOM_ERR_FD;
	else
		scan_int(c, &errfd);
	substdio_fdbuf(&sserr, (ssize_t (*)(int,  char *, size_t)) write, errfd, errbuf, sizeof(errbuf));
	if (substdio_put(&sserr, type, 1) == -1 ||
			substdio_puts(&sserr, program) == -1 ||
			substdio_put(&sserr, ": ", 2) ||
			substdio_puts(&sserr, message) == -1)
		_exit(53);
	if (extra && (substdio_put(&sserr, ": ", 2) == -1 || substdio_puts(&sserr, extra) == -1))
		_exit(53);
	if (code) {
		if (substdio_put(&sserr, " (#", 3) == -1)
			_exit(53);
		c = (*type == 'D') ? "5" : "4";
		if (substdio_put(&sserr, c, 1) == -1 ||
				substdio_put(&sserr, code + 1, 4) == -1 ||
				substdio_put(&sserr, ")", 1) == -1)
			_exit(53);
	}
	if (substdio_flush(&sserr) == -1)
		_exit(53);
	_exit(88);
}

/*
 * $Log: custom_error.c,v $
 * Revision 1.4  2025-01-22 00:30:36+05:30  Cprogrammer
 * Fixes for gcc14
 *
 * Revision 1.3  2024-05-09 22:03:17+05:30  mbhangui
 * fix discarded-qualifier compiler warnings
 *
 * Revision 1.2  2023-04-25 22:41:34+05:30  Cprogrammer
 * removed use of static variables as function is noreturn
 *
 * Revision 1.1  2022-03-08 22:56:41+05:30  Cprogrammer
 * Initial revision
 *
 */
