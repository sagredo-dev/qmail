/*
 * $Log: str_cspn.c,v $
 * Revision 1.1  2011-07-12 20:42:00+05:30  Cprogrammer
 * Initial revision
 *
 */
#include "str.h"
/*
 * Span the complement of string s2.
 */
size_t
str_cspn(const char *s1, const char *s2)
{
	const char *p, *spanp;
	char c, sc;

	/*
	 * Stop as soon as we find any character from s2.  Note that there
	 * must be a NUL in s2; it suffices to stop when we find that, too.
	 */
	for (p = s1;;) {
		c = *p++;
		spanp = s2;
		do {
			if ((sc = *spanp++) == c)
				return (p - 1 - s1);
		} while (sc != 0);
	}
	/* NOTREACHED */
}

void
getversion_str_cspn_c()
{
	static char    *x = "$Id: str_cspn.c,v 1.1 2011-07-12 20:42:00+05:30 Cprogrammer Exp mbhangui $";

	x++;
}
