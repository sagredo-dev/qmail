/*
 * $Log: custom_error.h,v $
 * Revision 1.3  2024-05-09 22:03:17+05:30  mbhangui
 * fix discarded-qualifier compiler warnings
 *
 * Revision 1.2  2022-03-27 20:07:33+05:30  Cprogrammer
 * include extended error from errno if EXTENDED_ERROR env variable is defined
 *
 * Revision 1.1  2022-03-08 22:56:39+05:30  Cprogrammer
 * Initial revision
 *
 */
#ifndef _CUSTOM_ERROR_H
#define _CUSTOM_ERROR_H

void  custom_error(const char *, const char *, const char *, const char *, const char *);
char  *extended_err(const char *, const char *);

#endif
