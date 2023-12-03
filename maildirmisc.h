#ifndef	maildirmisc_h
#define	maildirmisc_h

/*
** Copyright 2000 Double Precision, Inc.
** See COPYING for distribution information.
*/

#if	HAVE_CONFIG_H
#include	"config.h"
#endif

#ifdef  __cplusplus
extern "C" {
#endif

static const char maildirmisc_h_rcsid[]="$Id: qmail-maildir++.patch,v 1.1.1.1.2.1 2005/01/19 23:35:23 tomcollins Exp $";

/*
**
** Miscellaneous maildir-related code
**
*/

/* Some special folders */

#define	INBOX	"INBOX"
#define	DRAFTS	"Drafts"
#define	SENT	"Sent"
#define	TRASH	"Trash"

#define	SHAREDSUBDIR	"shared-folders"

char *maildir_folderdir(const char *,		/* maildir */
	const char *);				/* folder name */
	/* Returns the directory corresponding to foldername (foldername is
	** checked to make sure that it's a valid name, else we set errno
	** to EINVAL, and return (0).
	*/

char *maildir_filename(const char *,		/* maildir */
	const char *,				/* folder */
	const char *);				/* filename */
	/*
	** Builds the filename to this message, suitable for opening.
	** If the file doesn't appear to be there, search the maildir to
	** see if someone changed the flags, and return the current filename.
	*/

int maildir_safeopen(const char *,		/* filename */
	int,				/* mode */
	int);				/* perm */

/*
**	Same arguments as open().  When we're accessing a shared maildir,
**	prevent someone from playing cute and dumping a bunch of symlinks
**	in there.  This function will open the indicate file only if the
**	last component is not a symlink.
**	This is implemented by opening the file with O_NONBLOCK (to prevent
**	a DOS attack of someone pointing the symlink to a pipe, causing
**	the open to hang), clearing O_NONBLOCK, then stat-int the file
**	descriptor, lstating the filename, and making sure that dev/ino
**	match.
*/

int maildir_semisafeopen(const char *,	/* filename */
	int,				/* mode */
	int);				/* perm */

/*
** Same thing, except that we allow ONE level of soft link indirection,
** because we're reading from our own maildir, which points to the
** message in the sharable maildir.
*/

int maildir_mkdir(const char *);	/* directory */
/*
** Create maildir including all subdirectories in the path (like mkdir -p)
*/

void maildir_purgetmp(const char *);		/* maildir */
	/* purges old stuff out of tmp */

void maildir_purge(const char *,		/* directory */
	unsigned);				/* time_t to purge */

void maildir_getnew(const char *,		/* maildir */
	const char *);				/* folder */
	/* move messages from new to cur */

int maildir_deletefolder(const char *,		/* maildir */
	const char *);				/* folder */
	/* deletes a folder */

int maildir_mddelete(const char *);	/* delete a maildir folder by path */

void maildir_list_sharable(const char *,	/* maildir */
	void (*)(const char *, void *),		/* callback function */
	void *);				/* 2nd arg to callback func */
	/* list sharable folders */

int maildir_shared_subscribe(const char *,	/* maildir */
		const char *);			/* folder */
	/* subscribe to a shared folder */

void maildir_list_shared(const char *,		/* maildir */
	void (*)(const char *, void *),		/* callback function */
	void *);			/* 2nd arg to the callback func */
	/* list subscribed folders */

int maildir_shared_unsubscribe(const char *,	/* maildir */
		const char *);			/* folder */
	/* unsubscribe from a shared folder */

char *maildir_shareddir(const char *,		/* maildir */
	const char *);				/* folder */
	/*
	** Validate and return a path to a shared folder.  folderdir must be
	** a name of a valid shared folder.
	*/

void maildir_shared_sync(const char *);		/* maildir */
	/* "sync" the shared folder */

int maildir_sharedisro(const char *);		/* maildir */
	/* maildir is a shared read-only folder */

int maildir_unlinksharedmsg(const char *);	/* filename */
	/* Remove a message from a shared folder */

/* Internal function that reads a symlink */

char *maildir_getlink(const char *);

	/* Determine whether the maildir filename has a certain flag */

int maildir_hasflag(const char *filename, char);

#define	MAILDIR_DELETED(f)	maildir_hasflag((f), 'T')

#ifdef  __cplusplus
}
#endif

#endif
