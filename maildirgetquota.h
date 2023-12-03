#ifndef	maildirgetquota_h
#define	maildirgetquota_h

/*
** Copyright 1998 - 1999 Double Precision, Inc.
** See COPYING for distribution information.
*/

#if	HAVE_CONFIG_H
#include	"config.h"
#endif

#include	<sys/types.h>
#include	<stdio.h>

#ifdef  __cplusplus
extern "C" {
#endif

static const char maildirgetquota_h_rcsid[]="$Id: qmail-maildir++.patch,v 1.1.1.1.2.1 2005/01/19 23:35:23 tomcollins Exp $";

#define	QUOTABUFSIZE	256

int maildir_getquota(const char *, char [QUOTABUFSIZE]);

#ifdef  __cplusplus
}
#endif

#endif
