/*
** Copyright 1998 - 2002 Double Precision, Inc.
** See COPYING for distribution information.
*/

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
/* #if HAVE_DIRENT_H */
#include <dirent.h>
#define NAMLEN(dirent) strlen((dirent)->d_name)
/* #else
#define dirent direct
#define NAMLEN(dirent) (dirent)->d_namlen
#if HAVE_SYS_NDIR_H
#include <sys/ndir.h>
#endif
#if HAVE_SYS_DIR_H
#include <sys/dir.h>
#endif
#if HAVE_NDIR_H
#include <ndir.h>
#endif
#endif */
#include	<sys/types.h>
/* #if	HAVE_SYS_STAT_H */
#include	<sys/stat.h>
/* #endif */
#include	<sys/uio.h>

#include	"maildirquota.h"
#include	"maildirmisc.h"
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
/* #if	HAVE_FCNTL_H */
#include	<fcntl.h>
/* #endif */
#if	HAVE_UNISTD_H
#include	<unistd.h>
#endif
#include	<time.h>
#include	"numlib.h"

static const char rcsid[]="$Id: qmail-maildir++.patch,v 1.1.1.1.2.1 2005/01/19 23:35:23 tomcollins Exp $";

/* Read the maildirsize file */

int maildirsize_read(const char *filename,	/* The filename */
	int *fdptr,	/* Keep the file descriptor open */
	off_t *sizeptr,	/* Grand total of maildir size */
	unsigned *cntptr, /* Grand total of message count */
	unsigned *nlines, /* # of lines in maildirsize */
	struct stat *statptr)	/* The stats on maildirsize */
{
char buf[5120];
int f;
char *p;
unsigned l;
int n;
int first;

	if ((f=maildir_safeopen(filename, O_RDWR|O_APPEND, 0)) < 0)
		return (-1);
	p=buf;
	l=sizeof(buf);

	while (l)
	{
		n=read(f, p, l);
		if (n < 0)
		{
			close(f);
			return (-1);
		}
		if (n == 0)	break;
		p += n;
		l -= n;
	}
	if (l == 0 || fstat(f, statptr))	/* maildir too big */
	{
		close(f);
		return (-1);
	}

	*sizeptr=0;
	*cntptr=0;
	*nlines=0;
	*p=0;
	p=buf;
	first=1;
	while (*p)
	{
	long n=0;
	int c=0;
	char	*q=p;

		while (*p)
			if (*p++ == '\n')
			{
				p[-1]=0;
				break;
			}

		if (first)
		{
			first=0;
			continue;
		}
		sscanf(q, "%ld %d", &n, &c);
		*sizeptr += n;
		*cntptr += c;
		++ *nlines;
	}
	*fdptr=f;
	return (0);
}

static char *makenewmaildirsizename(const char *, int *);
static int countcurnew(const char *, time_t *, off_t *, unsigned *);
static int countsubdir(const char *, const char *,
		time_t *, off_t *, unsigned *);
static int statcurnew(const char *, time_t *);
static int statsubdir(const char *, const char *, time_t *);

#define	MDQUOTA_SIZE	'S'	/* Total size of all messages in maildir */
#define	MDQUOTA_BLOCKS	'B'	/* Total # of blocks for all messages in
				maildir -- NOT IMPLEMENTED */
#define	MDQUOTA_COUNT	'C'	/* Total number of messages in maildir */

static int qcalc(off_t s, unsigned n, const char *quota, int *percentage)
{
off_t i;
int	spercentage=0;
int	npercentage=0;

	errno=ENOSPC;
	while (quota && *quota)
	{
		int x=1;

		if (*quota < '0' || *quota > '9')
		{
			++quota;
			continue;
		}
		i=0;
		while (*quota >= '0' && *quota <= '9')
			i=i*10 + (*quota++ - '0');
		switch (*quota)	{
		default:
			if (i < s)
			{
				*percentage=100;
				return (-1);
			}

			/*
			** For huge quotas, over 20mb,
			** divide numerator & denominator by 1024 to prevent
			** an overflow when multiplying by 100
			*/

			x=1;
			if (i > 20000000) x=1024;

			spercentage = i ? (s/x) * 100 / (i/x):100;
			break;
		case 'C':

			if (i < n)
			{
				*percentage=100;
				return (-1);
			}

			/* Ditto */

			x=1;
			if (i > 20000000) x=1024;

			npercentage = i ? ((off_t)n/x) * 100 / (i/x):100;
			break;
		}
	}
	*percentage = spercentage > npercentage ? spercentage:npercentage;
	return (0);
}

static int	doaddquota(const char *, int, const char *, long, int, int);

static int docheckquota(const char *dir,
	int *maildirsize_fdptr,
	const char *quota_type,
	long xtra_size,
	int xtra_cnt, int *percentage);


int maildir_checkquota(const char *dir,
	int *maildirsize_fdptr,
	const char *quota_type,
	long xtra_size,
	int xtra_cnt)
{
int	dummy;

	return (docheckquota(dir, maildirsize_fdptr, quota_type,
		xtra_size, xtra_cnt, &dummy));
}

int maildir_readquota(const char *dir, const char *quota_type)
{
int	percentage=0;
int	fd=-1;

	(void)docheckquota(dir, &fd, quota_type, 0, 0, &percentage);
	if (fd >= 0)
		close(fd);
	return (percentage);
}

static int docheckquota(const char *dir,
	int *maildirsize_fdptr,
	const char *quota_type,
	long xtra_size,
	int xtra_cnt,
	int *percentage)
{
char	*checkfolder=(char *)malloc(strlen(dir)+sizeof("/maildirfolder"));
char	*newmaildirsizename;
struct stat stat_buf;
int	maildirsize_fd;
off_t	maildirsize_size;
unsigned maildirsize_cnt;
unsigned maildirsize_nlines;
int	n;
time_t	tm;
time_t	maxtime;
DIR	*dirp;
struct dirent *de;

	if (checkfolder == 0)	return (-1);
	*maildirsize_fdptr= -1;
	strcat(strcpy(checkfolder, dir), "/maildirfolder");
	if (stat(checkfolder, &stat_buf) == 0)	/* Go to parent */
	{
		strcat(strcpy(checkfolder, dir), "/..");
		n=docheckquota(checkfolder, maildirsize_fdptr,
			quota_type, xtra_size, xtra_cnt, percentage);
		free(checkfolder);
		return (n);
	}
	if (!quota_type || !*quota_type)	return (0);

	strcat(strcpy(checkfolder, dir), "/maildirsize");
	time(&tm);
	if (maildirsize_read(checkfolder, &maildirsize_fd,
		&maildirsize_size, &maildirsize_cnt,
		&maildirsize_nlines, &stat_buf) == 0)
	{
		n=qcalc(maildirsize_size+xtra_size, maildirsize_cnt+xtra_cnt,
			quota_type, percentage);

		if (n == 0)
		{
			free(checkfolder);
			*maildirsize_fdptr=maildirsize_fd;
			return (0);
		}
		close(maildirsize_fd);

		if (maildirsize_nlines == 1 && tm < stat_buf.st_mtime + 15*60)
			return (n);
	}

	maxtime=0;
	maildirsize_size=0;
	maildirsize_cnt=0;

	if (countcurnew(dir, &maxtime, &maildirsize_size, &maildirsize_cnt))
	{
		free(checkfolder);
		return (-1);
	}

	dirp=opendir(dir);
	while (dirp && (de=readdir(dirp)) != 0)
	{
		if (countsubdir(dir, de->d_name, &maxtime, &maildirsize_size,
			&maildirsize_cnt))
		{
			free(checkfolder);
			closedir(dirp);
			return (-1);
		}
	}
	if (dirp)
	{
#if	CLOSEDIR_VOID
		closedir(dirp);
#else
		if (closedir(dirp))
		{
			free(checkfolder);
			return (-1);
		}
#endif
	}

	newmaildirsizename=makenewmaildirsizename(dir, &maildirsize_fd);
	if (!newmaildirsizename)
	{
		free(checkfolder);
		return (-1);
	}

	*maildirsize_fdptr=maildirsize_fd;

	if (doaddquota(dir, maildirsize_fd, quota_type, maildirsize_size,
		maildirsize_cnt, 1))
	{
		unlink(newmaildirsizename);
		free(newmaildirsizename);
		close(maildirsize_fd);
		*maildirsize_fdptr= -1;
		free(checkfolder);
		return (-1);
	}

	strcat(strcpy(checkfolder, dir), "/maildirsize");

	if (rename(newmaildirsizename, checkfolder))
	{
		/* free(checkfolder); */
		unlink(newmaildirsizename);
		close(maildirsize_fd);
		*maildirsize_fdptr= -1;
	}
	free(checkfolder);
	free(newmaildirsizename);

	tm=0;

	if (statcurnew(dir, &tm))
	{
		close(maildirsize_fd);
		*maildirsize_fdptr= -1;
		return (-1);
	}

	dirp=opendir(dir);
	while (dirp && (de=readdir(dirp)) != 0)
	{
		if (statsubdir(dir, de->d_name, &tm))
		{
			close(maildirsize_fd);
			*maildirsize_fdptr= -1;
			closedir(dirp);
			return (-1);
		}
	}
	if (dirp)
	{
#if	CLOSEDIR_VOID
		closedir(dirp);
#else
		if (closedir(dirp))
		{
			close(maildirsize_fd);
			*maildirsize_fdptr= -1;
			return (-1);
		}
#endif
	}

	if (tm != maxtime)	/* Race condition, someone changed something */
	{
		errno=EAGAIN;
		return (-1);
	}

	return (qcalc(maildirsize_size+xtra_size, maildirsize_cnt+xtra_cnt,
		quota_type, percentage));
}

int	maildir_addquota(const char *dir, int maildirsize_fd,
	const char *quota_type, long maildirsize_size, int maildirsize_cnt)
{
	if (!quota_type || !*quota_type)	return (0);
	return (doaddquota(dir, maildirsize_fd, quota_type, maildirsize_size,
			maildirsize_cnt, 0));
}

static int doaddquota(const char *dir, int maildirsize_fd,
	const char *quota_type, long maildirsize_size, int maildirsize_cnt,
	int isnew)
{
union	{
	char	buf[100];
	struct stat stat_buf;
	} u;				/* Scrooge */
char	*newname2=0;
char	*newmaildirsizename=0;
struct	iovec	iov[3];
int	niov;
struct	iovec	*p;
int	n;

	niov=0;
	if ( maildirsize_fd < 0)
	{
		newname2=(char *)malloc(strlen(dir)+sizeof("/maildirfolder"));
		if (!newname2)	return (-1);
		strcat(strcpy(newname2, dir), "/maildirfolder");
		if (stat(newname2, &u.stat_buf) == 0)
		{
			strcat(strcpy(newname2, dir), "/..");
			n=doaddquota(newname2, maildirsize_fd, quota_type,
					maildirsize_size, maildirsize_cnt,
					isnew);
			free(newname2);
			return (n);
		}

		strcat(strcpy(newname2, dir), "/maildirsize");

		if ((maildirsize_fd=maildir_safeopen(newname2,
			O_RDWR|O_APPEND, 0644)) < 0)
		{
			newmaildirsizename=makenewmaildirsizename(dir, &maildirsize_fd);
			if (!newmaildirsizename)
			{
				free(newname2);
				return (-1);
			}

			maildirsize_fd=maildir_safeopen(newmaildirsizename,
				O_CREAT|O_RDWR|O_APPEND, 0644);

			if (maildirsize_fd < 0)
			{
				free(newname2);
				return (-1);
			}
			isnew=1;
		}
	}

	if (isnew)
	{
		iov[0].iov_base=(caddr_t)quota_type;
		iov[0].iov_len=strlen(quota_type);
		iov[1].iov_base=(caddr_t)"\n";
		iov[1].iov_len=1;
		niov=2;
	}


	sprintf(u.buf, "%ld %d\n", maildirsize_size, maildirsize_cnt);
	iov[niov].iov_base=(caddr_t)u.buf;
	iov[niov].iov_len=strlen(u.buf);

	p=iov;
	++niov;
	n=0;
	while (niov)
	{
		if (n)
		{
			if (n < p->iov_len)
			{
				p->iov_base=
					(caddr_t)((char *)p->iov_base + n);
				p->iov_len -= n;
			}
			else
			{
				n -= p->iov_len;
				++p;
				--niov;
				continue;
			}
		}

		n=writev( maildirsize_fd, p, niov);

		if (n <= 0)
		{
			if (newname2)
			{
				close(maildirsize_fd);
				free(newname2);
			}
			return (-1);
		}
	}
	if (newname2)
	{
		close(maildirsize_fd);

		if (newmaildirsizename)
		{
			rename(newmaildirsizename, newname2);
			free(newmaildirsizename);
		}
		free(newname2);
	}
	return (0);
}

/* New maildirsize is built in the tmp subdirectory */

static char *makenewmaildirsizename(const char *dir, int *fd)
{
char	hostname[256];
struct	stat stat_buf;
time_t	t;
char	*p;

	hostname[0]=0;
	hostname[sizeof(hostname)-1]=0;
	gethostname(hostname, sizeof(hostname)-1);
	p=(char *)malloc(strlen(dir)+strlen(hostname)+130);
	if (!p)	return (0);

	for (;;)
	{
	char	tbuf[NUMBUFSIZE];
	char	pbuf[NUMBUFSIZE];

		time(&t);
		strcat(strcpy(p, dir), "/tmp/");
		sprintf(p+strlen(p), "%s.%s_NeWmAiLdIrSiZe.%s",
			str_time_t(t, tbuf),
			str_pid_t(getpid(), pbuf), hostname);

		if (stat( (const char *)p, &stat_buf) < 0 &&
			(*fd=maildir_safeopen(p,
				O_CREAT|O_RDWR|O_APPEND, 0644)) >= 0)
			break;
		sleep(3);
	}
	return (p);
}

static int statcurnew(const char *dir, time_t *maxtimestamp)
{
char	*p=(char *)malloc(strlen(dir)+5);
struct	stat	stat_buf;

	if (!p)	return (-1);
	strcat(strcpy(p, dir), "/cur");
	if ( stat(p, &stat_buf) == 0 && stat_buf.st_mtime > *maxtimestamp)
		*maxtimestamp=stat_buf.st_mtime;
	strcat(strcpy(p, dir), "/new");
	if ( stat(p, &stat_buf) == 0 && stat_buf.st_mtime > *maxtimestamp)
		*maxtimestamp=stat_buf.st_mtime;
	free(p);
	return (0);
}

static int statsubdir(const char *dir, const char *subdir, time_t *maxtime)
{
char	*p;
int	n;

	if ( *subdir != '.' || strcmp(subdir, ".") == 0 ||
		strcmp(subdir, "..") == 0 || strcmp(subdir, "." TRASH) == 0)
		return (0);

	p=(char *)malloc(strlen(dir)+strlen(subdir)+2);
	if (!p)	return (-1);
	strcat(strcat(strcpy(p, dir), "/"), subdir);
	n=statcurnew(p, maxtime);
	free(p);
	return (n);
}

static int docount(const char *, time_t *, off_t *, unsigned *);

static int countcurnew(const char *dir, time_t *maxtime,
	off_t *sizep, unsigned *cntp)
{
char	*p=(char *)malloc(strlen(dir)+5);
int	n;

	if (!p)	return (-1);
	strcat(strcpy(p, dir), "/new");
	n=docount(p, maxtime, sizep, cntp);
	if (n == 0)
	{
		strcat(strcpy(p, dir), "/cur");
		n=docount(p, maxtime, sizep, cntp);
	}
	free(p);
	return (n);
}

static int countsubdir(const char *dir, const char *subdir, time_t *maxtime,
	off_t *sizep, unsigned *cntp)
{
char	*p;
int	n;

	if ( *subdir != '.' || strcmp(subdir, ".") == 0 ||
		strcmp(subdir, "..") == 0 || strcmp(subdir, "." TRASH) == 0)
		return (0);

	p=(char *)malloc(strlen(dir)+strlen(subdir)+2);
	if (!p)	return (2);
	strcat(strcat(strcpy(p, dir), "/"), subdir);
	n=countcurnew(p, maxtime, sizep, cntp);
	free(p);
	return (n);
}

static int docount(const char *dir, time_t *dirstamp,
	off_t *sizep, unsigned *cntp)
{
struct	stat	stat_buf;
char	*p;
DIR	*dirp;
struct dirent *de;
unsigned long	s;

	if (stat(dir, &stat_buf))	return (0);	/* Ignore */
	if (stat_buf.st_mtime > *dirstamp)	*dirstamp=stat_buf.st_mtime;
	if ((dirp=opendir(dir)) == 0)	return (0);
	while ((de=readdir(dirp)) != 0)
	{
	const char *n=de->d_name;

		if (*n == '.')	continue;

		/* PATCH - do not count msgs marked as deleted */

		for ( ; *n; n++)
		{
			if (n[0] != ':' || n[1] != '2' ||
				n[2] != ',')	continue;
			n += 3;
			while (*n >= 'A' && *n <= 'Z')
			{
				if (*n == 'T')	break;
				++n;
			}
			break;
		}
		if (*n == 'T')	continue;
		n=de->d_name;


		if (maildir_parsequota(n, &s) == 0)
			stat_buf.st_size=s;
		else
		{
			p=(char *)malloc(strlen(dir)+strlen(n)+2);
			if (!p)
			{
				closedir(dirp);
				return (-1);
			}
			strcat(strcat(strcpy(p, dir), "/"), n);
			if (stat(p, &stat_buf))
			{
				free(p);
				continue;
			}
			free(p);
		}
		*sizep += stat_buf.st_size;
		++*cntp;
	}

#if	CLOSEDIR_VOID
	closedir(dirp);
#else
	if (closedir(dirp))
		return (-1);
#endif
	return (0);
}
