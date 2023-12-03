/*
 * $Log: dktrace.c,v $
 * Revision 1.1  2009-03-14 09:00:52+05:30  Cprogrammer
 * Initial revision
 *
 */
/*
 * $Id: dktrace.c,v 1.1 2009-03-14 09:00:52+05:30 Cprogrammer Stab mbhangui $ 
 */

#ifdef DOMAIN_KEYS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "str.h"
#include "case.h"
#include "dktrace.h"

#define strncasecmp(x,y,z) case_diffb((x), (z), (y))

static int     *
getPointer(DK_TRACE * dkp, DK_TRACE_TYPE type)
{
	switch (type) {
	case DKT_RAW_HEADER:
		return dkp->ccounts_h;
	case DKT_CANON_HEADER:
		return dkp->ccounts_H;
	case DKT_RAW_BODY:
		return dkp->ccounts_b;
	case DKT_CANON_BODY:
		return dkp->ccounts_B;
	default:
		return 0;
	}
}

//Modified version of dkparselist()
static int
dkt_parselist(char *list, char *letters, char *values[])
{
	char            key;
	int             i;
	char           *value;

	/*- start with all args unset */
	for (i = 0; letters[i]; i++) {
		values[i] = NULL;
	}
	key = 0;
	while (*list) {
		if ((*list == ' ') || (*list == '\t') || (*list == '\r') || (*list == '\n')) {
			list++;
		} else if (*list == '=') {
			char           *ws;

			++list;
			value = list;
			ws = list;
			while (1) {
			/*
			 * copy up to null or semicolon, deleting whitespace as we go 
			 */
				*ws = *list;
				if ((*list == ' ') || (*list == '\t') || (*list == '\r') || (*list == '\n')) {
				/*
				 * ignore 
				 */
				} else if (!*list) {
					break;
				} else if (*list == ';') {
					*ws = '\0';
					list++;
					break;
				} else {
					ws++;
				}
				list++;
			}
			if (!key) {
				return 0;		//No key
			}
		/*
		 * if we find a matching letter, remember the value 
		 */
			for (i = 0; letters[i]; i++) {
				if (key == letters[i]) {
					if (values[i]) {
						return 0;	/* no duplicate keys. TC23 */
					}
					values[i] = value;
				}
			}
			key = 0;
		} else {
			if (key) {
				return 0;		/* they already gave us a key. TC24 */
			}
			key = *list++;
		}
	}
	return 1;
}

extern void
dkt_add(DK_TRACE * dkp, DK_TRACE_TYPE type, const unsigned char *data, int dataLength)
{
	int            *ip;
	ip = getPointer(dkp, type);
	if (!ip)
		return;

	while (dataLength-- > 0)
		ip[*data++]++;
}

//useful for building table directly
extern void
dkt_quickadd(DK_TRACE * dkp, DK_TRACE_TYPE type, int index, int count)
{
	int            *ip;
	ip = getPointer(dkp, type);
	if (!ip)
		return;
	if ((index < 256) && (index >= 0))
		ip[index] = ip[index] + count;
}

//reverse of dkt_quickadd, reads data from table and returns the int count
extern int
dkt_getcount(DK_TRACE * dkp, DK_TRACE_TYPE type, int index, int count)
{
	int            *ip;
	ip = getPointer(dkp, type);
	if (!ip)
		return 0;
	if ((index < 256) && (index >= 0))
		return ip[index];
	return 0;
}


/*
 * Fills in DK_TRACE *diff_table with the differences between
 * *dka (before) and *dkb (after), (after - before = diff)
 */
extern int
dkt_diff(DK_TRACE * dka, DK_TRACE * dkb, DK_TRACE_TYPE type, DK_TRACE * diff_table)
{
	int            *inputa, *inputb, *output;
	int             i;
	inputa = getPointer(dka, type);
	if (!inputa)
		return 0;
	inputb = getPointer(dkb, type);
	if (!inputb)
		return 0;
	output = getPointer(diff_table, type);
	if (!output)
		return 0;

	for (i = 0; i < 256; i++) {
		output[i] = (inputb[i] - inputa[i]);
	}
	return 1;
}

/*
 * Generate the tag=value; data for a particular trace type
 * returns length of generated C string including ending '\0'
 */

extern int
dkt_generate(DK_TRACE * dkp, DK_TRACE_TYPE type, char *buffer, int maxBufferSize)
{
	int            *ip;
	char           *cp;
	int             ix;
	int             len;
	int             highest;

	if (maxBufferSize < 20)
		return 0;				/* Getting too close, you lose */
	cp = buffer;
	ip = getPointer(dkp, type);
	if (!ip)
		return 0;
	*buffer++ = (char) type;
	--maxBufferSize;
	*buffer++ = '=';
	--maxBufferSize;

/*
 * Only produce as many entries as needed, rather than the full 256 
 */

	for (ix = 0, highest = 0; ix < 256; ++ix) {
		if (ip[ix] != 0)
			highest = ix;
	}

	for (ix = 0; ix <= highest; ++ix) {
		if (ip[ix] != 0) {
			len = snprintf(buffer, maxBufferSize, "%d", ip[ix]);
			buffer += len;
			maxBufferSize -= len;
		}
		if (maxBufferSize < 10)
			return 0;			/* Getting too close, you lose */
		*buffer++ = ':';
		--maxBufferSize;
	}
	/*
	 * Finish up the tag with a semi-colon and turn it into a C string 
	 */
	--buffer;
	*buffer++ = ';'; //replace last ':'
	*buffer++ = '\0';
	--maxBufferSize;
	return buffer - cp;
}

//converts a header to to a DK_TRACE table
extern int
dkt_hdrtotrace(char *ptr, DK_TRACE * store)
{
	char           *values[4];	// hHbB
	int             idx;
	int             delim_count;
	char           *sptr, *eptr;
	DK_TRACE_TYPE   dk_trace_tag[4] = {
		DKT_RAW_HEADER,
		DKT_CANON_HEADER,
		DKT_RAW_BODY,
		DKT_CANON_BODY
	};
	int            *ip;

	if ((strncasecmp(ptr, "DomainKey-Trace:", 16)) || !store || (!dkt_parselist(ptr + 16, "hHbB", values))) {
		return 0;
	}
	for (idx = 0; idx < 4; idx++) {
		if (!values[idx])
			continue;
		ip = getPointer(store, dk_trace_tag[idx]);
		if (!ip)
			return 0;
		sptr = values[idx];
		for (delim_count = 0; ((delim_count < 256) && (*sptr != '\0')); sptr++) {
			if (*sptr == ':') {
				delim_count++;
				continue;
			}
		//find the end of the int
			for (eptr = sptr + 1; ((*eptr != ':') && (*eptr != '\0')); eptr++);
			if (*eptr == '\0') //if end of values for key finish up
			{
				ip[delim_count] = atoi(sptr);
				break;
			}
			*eptr = '\0';
			ip[delim_count] = atoi(sptr);
			delim_count++;
			sptr = eptr;
		}
	}
	return 1;
}
#endif

void
getversion_dktrace_c()
{
	static char    *x = "$Id: dktrace.c,v 1.1 2009-03-14 09:00:52+05:30 Cprogrammer Stab mbhangui $";

	x++;
}
