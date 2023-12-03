/*
** Copyright 1998 - 2000 Double Precision, Inc.
** See COPYING for distribution information.
*/

#include	"maildirgetquota.h"
#include	"maildirmisc.h"
#if	HAVE_UNISTD_H
#include	<unistd.h>
#endif
#include	<stdlib.h>
#include	<string.h>
#include	<fcntl.h>
#include	<sys/types.h>
#include	<sys/stat.h>

int	maildir_getquota(const char *dir, char buf[QUOTABUFSIZE])
{
char	*p;
struct	stat	stat_buf;
int	n;
int	l;

	p=(char *)malloc(strlen(dir)+sizeof("/maildirfolder"));
	if (!p)	return (-1);

	strcat(strcpy(p, dir), "/maildirfolder");
	if (stat(p, &stat_buf) == 0)
	{
		strcat(strcpy(p, dir), "/..");
		n=maildir_getquota(p, buf);
		free(p);
		return (n);
	}

	strcat(strcpy(p, dir), "/maildirsize");
	n=maildir_safeopen(p, O_RDONLY, 0);
	free(p);
	if (n < 0)	return (n);
	if ((l=read(n, buf, QUOTABUFSIZE-1)) < 0)
	{
		close(n);
		return (-1);
	}
	close(n);
	for (n=0; n<l; n++)
		if (buf[n] == '\n')	break;
	buf[n]=0;
	return (0);
}
