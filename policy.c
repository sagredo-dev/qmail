/*
 * Copyright (C) 2005 Inter7 Internet Technologies, Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 * <matt@inter7.com>
 * eMail Messaging Policy Framework
 * http://www.inter7.com/?page=empf
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _GNU_SOURCE
   #define _GNU_SOURCE
#endif
#ifndef FNM_CASEFOLD
   #include <ctype.h>
#endif
#include <fnmatch.h>
#include "stralloc.h"
#include "rcpthosts.h"
#include "policy.h"

/*
   Policy delivery flags
*/

#define POLICY_F_NONE 0
#define POLICY_F_ALLOW 1		/* Allow this delivery type   */
#define POLICY_F_DISALLOW 2		/* Do not allow this delivery */
#define POLICY_F_LOCAL 4		/* Local -> local delivery    */
#define POLICY_F_REMOTE 8		/* Local -> remote delivery   */
#define POLICY_F_EXTERNAL 16	/* Remote -> local delivery   */
#define POLICY_F_INTERNAL 32    /* Local -> local delivery    */

/*
   Policy
*/

typedef struct __policy_ {
   int flags,				/* Allow or disallow */
	   numargs;				/* Arguments read    */
   char **args;				/* Argument array    */

   struct __policy_ *next;
} policy_t;

/*
   Local delivery name
*/

typedef struct __local_ {
   char *local;						/* Local name */
   policy_t *policy;				/* Policy	  */

   struct __local_ *next;
} local_t;

/*
   Domain name
*/

typedef struct __domain_ {
   char *domain;					/* Domain name */
   policy_t *policy;				/* Policy	   */
   local_t *locals;					/* Locals      */

   struct __domain_ *next;
} domain_t;

extern char *remoteinfo;
extern stralloc mailfrom;
extern stralloc addr;
extern void out(char *);

static int policy_load(const char *);
static int policy_parse(const char *, char *);
static policy_t *policy_construct(char *);
static int policy_construct_parse_arguments(char **, const int, char *);
static int policy_match(const char *, const char *);
static int policy_applies_to(const policy_t *, const char *);
static int policy_flags(const char);
static policy_t *policy_find(const policy_t *, const int);
static int policy_forbids(void);
static domain_t *domain_find(const char *);
static local_t *local_find(const domain_t *, const char *);
static void policy_free(policy_t *);
static void local_free(local_t *);
static void domains_free(void);

static domain_t *domains = NULL, *s_domain = NULL, *r_domain = NULL;

/*
   Check policy for delivery restrictions
*/

int policy_check(void)
{
   int ret = 0;
   const char *p = NULL;
   
   s_domain = r_domain = NULL;

#ifdef POLICY_DEALLOCATE
   domains_free();
#endif

   if (remoteinfo)
	  p = remoteinfo;
   else
	  p = mailfrom.s;

   fprintf(stderr, "policy_check: %s %s -> %s %s (%s)\n", 
		 rcpthosts(p, strlen(p)) ? "local" : "remote", p, 
		 rcpthosts(addr.s, strlen(addr.s)) ? "local" : "remote", addr.s,
		 remoteinfo ? "AUTHENTICATED SENDER" : "UNAUTHENTICATED SENDER");

   /*
	  Load sender-related policy
   */

   for (; ((p) && (*p)); p++) {
	  if (*p == '@')
		 break;
   }

   if (*p) {
	  if (rcpthosts(remoteinfo ? remoteinfo : mailfrom.s,
			   remoteinfo ? strlen(remoteinfo) : strlen(mailfrom.s))) {
		 ret = policy_load(p + 1);
		 if (!ret) {
			fprintf(stderr, "policy_check: policy_load failed\n");
			return -1;
		 }

		 s_domain = domain_find(p + 1);

#ifdef POLICY_ENFORCE_AUTHENTICATION
		 /*
		    This check is done here in the event that there is
			no policy for a domain.  In that event, we do not
			wish to enforce policy rules
		 */

		 if ((s_domain) && (remoteinfo == NULL)) {
			fprintf(stderr, "policy_check: sender not authenticated\n");
			return 0;
		 }
#endif
	  }

#ifdef DEBUG
	  else
		 fprintf(stderr, "policy_check: %s is not local\n", p + 1);
#endif
   }

   /*
	  Load recipient-related policy
   */

   for (p = addr.s; ((p) && (*p)); p++) {
	  if (*p == '@')
		 break;
   }

   if (*p) {
	  if (rcpthosts(addr.s, strlen(addr.s))) {
		 ret = policy_load(p + 1);
		 if (!ret) {
			fprintf(stderr, "policy_check: policy_load failed\n");
			return -1;
		 }

		 r_domain = domain_find(p + 1);
	  }

#ifdef DEBUG
	  else
		 fprintf(stderr, "policy_check: %s is not local\n", p + 1);
#endif
   }

   /*
	  Policy enforcement
   */

   ret = policy_forbids();
   if (ret == 1) {
	  fprintf(stderr, "policy_check: policy forbids transmission\n");
	  return 0;
   }

   else if (ret == 0) {
	  fprintf(stderr, "policy_check: policy allows transmission\n");
	  return 1;
   }

   fprintf(stderr, "policy_check: policy_forbids failed\n");
   return -1;
}

/*
   Load policy from policy file
*/

static int policy_load(const char *domain)
{
   size_t line = 0;
   FILE *stream = NULL;
   char b[4096] = { 0 };
   int locald = 0, ret = 0;

   if (domain == NULL)
	  return 1;

   /*
	  See if we've already loaded this policy
   */

   if (domain_find(domain)) {
#ifdef DEBUG
	  fprintf(stderr, "policy_load(%s): already loaded\n", domain);
#endif
	  return 1;
   }

   stream = fopen(POLICY_FILENAME, "r");

   /*
	  If policy file doesnt exist, allow all messaging
	  Otherwise trigger error
   */

   if (stream == NULL) {
	  if (errno != ENOENT) {
		 fprintf(stderr, "policy_load(%s): cannot read policy\n", domain);
		 return 0;
	  }

#ifdef DEBUG
	  fprintf(stderr, "policy_load(%s): no policy\n", domain);
#endif
	  return 1;
   }

   /*
	  Run through policy line-by-line
   */

   line = 1;

   while(!(feof(stream))) {
	  memset(b, 0, sizeof(b));
	  fgets(b, sizeof(b), stream);

	  if ((*b == '#') || (*b == ';') || (*b == '\r') || (*b == '\n') || (*b == '\0'))
		 continue;

	  ret = policy_parse(domain, b);
	  if (ret == -1) {
		 fprintf(stderr, "policy_load(%s): policy_parse failed (line %d)\n", domain, line);
		 fclose(stream);
		 return 0;
	  }

	  else if (ret == 1)
		 break;

	  line++;
   }

   fclose(stream);

#ifdef DEBUG
   fprintf(stderr, "policy_load(%s): loaded\n", domain);
#endif

   return 1;
}

/*
   Parse policy data
*/

static int policy_parse(const char *domain, char *data)
{
   int ia = 0;
   domain_t *d = NULL;
   policy_t *p = NULL, *lp = NULL;
   local_t *l_list = NULL, *l = NULL;
   char *h = NULL, *t = NULL, *pp = NULL;

   if ((domain == NULL) || (data == NULL))
	  return -1;

   /*
	  Seperate out domain part
   */

   for (h = t = data; *h; h++) {
	  if (*h == ':')
		 break;
   }

   if (*h != ':') {
	  fprintf(stderr, "policy_parse: syntax error: no domain seperator\n");
	  return -1;
   }

   *h = '\0';

   /*
	  Determine if this is the correct policy
   */

   if (strcasecmp(domain, t)) 
	  return 0;

   /*
	  Seperate domain policy
   */

   for (ia = 0, t = ++h; *h; h++) {
	  if ((*h == '(') && (ia == 0))
		 ia = 1;

	  else if ((*h == ')') && (ia == 1))
		 ia = 0;

	  else if ((*h == ',') && (ia == 0))
		 break;
   }

   if (*h != ',') {
	  fprintf(stderr, "policy_parse: syntax error: no domain policy seperator\n");
	  return -1; 
   }

   *h = '\0';

   p = policy_construct(t);
   if (p == NULL) {
	  fprintf(stderr, "policy_parse: policy_construct failed\n");
	  return -1;
   }

   /*
	  Parse locals
   */

   h++;
   l_list = l = NULL;

   while(*h) {
	  if ((*h == '\n') || (*h == '\r'))
		 break;

	  for (ia = 0, t = h; *h; h++) {
		 if ((*h == '(') && (ia == 0))
			ia = 1;

		 else if ((*h == ')') && (ia == 1))
			ia = 0;

		 else if ((*h == ',') && (ia == 0))
			break;
	  }

	  if (*h != ',') {
		 policy_free(p);
		 fprintf(stderr, "policy_parse: syntax error: no local policy seperator\n");
		 return -1; 
	  }

	  *h = '\0';

	  /*
	     Seperate local name from local policy 
	  */

	  for (pp = t; *pp; pp++) {
		 if (*pp == ':')
			break;
	  }

	  if (*pp != ':') {
		 policy_free(p);
		 fprintf(stderr, "policy_parse: syntax error: no local name, policy seperator\n");
		 return -1;
	  }

	  *pp++ = '\0';

	  if (!(*t)) {
		 policy_free(p);
		 fprintf(stderr, "policy_parse: syntax error: empty local name\n");
		 return -1;
	  }

	  if ((!(*pp)) || (*pp == ',')) {
		 policy_free(p);
		 fprintf(stderr, "policy_parse: syntax error: empty local policy\n");
		 return -1;
	  }

	  /*
	     Load local policy
	  */

	  lp = policy_construct(pp);
	  if (lp == NULL) {
		 policy_free(p);
		 fprintf(stderr, "policy_parse: policy_construct failed\n");
		 return -1;
	  }

	  l = (local_t *)malloc(sizeof(local_t));
	  if (l == NULL) {
		 policy_free(p);
		 policy_free(lp);
		 fprintf(stderr, "policy_parse: malloc failed\n");
		 return -1;
	  }

	  memset(l, 0, sizeof(local_t));

	  ia = strlen(t);

	  l->local = (char *)malloc(ia + 1 + strlen(domain) + 1);
	  if (l->local == NULL) {
		 policy_free(p);
		 policy_free(lp);
		 free(l);
		 fprintf(stderr, "policy_parse: malloc failed\n");
		 return -1;
	  }

	  memset(l->local, 0, ia + 1 + strlen(domain) + 1);
	  memcpy(l->local, t, ia);
	  memcpy(l->local + ia, "@", 1);
	  memcpy(l->local + ia + 1, domain, strlen(domain));

	  l->policy = lp;
	  l->next = NULL;

	  l->next = l_list;
	  l_list = l;

	  t = ++h;
   }

   /*
	  Allocate and fill domain structure
   */

   d = (domain_t *)malloc(sizeof(domain_t));
   if (d == NULL) {
	  policy_free(p);
	  local_free(l_list);
	  fprintf(stderr, "policy_parse: malloc failed\n");
	  return -1;
   }

   memset(d, 0, sizeof(domain_t));

   ia = strlen(domain);

   d->domain = (char *)malloc(ia + 1);
   if (d->domain == NULL) {
	  policy_free(p);
	  local_free(l_list);
	  free(d);
	  fprintf(stderr, "policy_parse: malloc failed\n");
	  return -1;
   }

   memset(d->domain, 0, ia + 1);
   memcpy(d->domain, domain, ia);

   d->locals = l_list;
   d->policy = p;

   d->next = domains;
   domains = d;

   return 1;
}

/*
   Parse policy data into a policy structure
*/

static policy_t *policy_construct(char *data)
{
   char pc = 0, **args = NULL;
   policy_t *p_list = NULL, *p = NULL;
   char *h = NULL, *t = NULL, *hp = NULL;
   int flags = POLICY_F_NONE, numargs = 0, i = 0, ret = 0;

   if (data == NULL)
	  return 0;

   pc = 0;

   for (h = data; *h; h++) {
	  pc = *h;

	  flags = policy_flags(*h);
	  if (flags == POLICY_F_NONE) {
		 fprintf(stderr, "policy_construct: unknown identifier\n");
		 return NULL;
	  }

	  args = NULL;

	  /*
	     Count, parse and allocate addresses
	  */

	  if (*(h + 1) == '(') {
		 t = (h + 2);

		 for (h += 2; *h; h++) {
			if (*h == ')')
			   break;
		 }

		 if (*h != ')') {
			fprintf(stderr, "policy_construct: no terminating ')'\n");
			return 0;
		 }

		 numargs = 1;

		 for (hp = t; hp < h; hp++) {
			if (*hp == ',') 
			   numargs++;
		 }

		 /*
		    No arguments
		 */

		 if (hp == t) {
			fprintf(stderr, "policy_construct: empty argument\n");
			return NULL;
		 }

		 args = (char **)malloc(sizeof(char *) * numargs);
		 if (args == NULL) {
			fprintf(stderr, "policy_construct: malloc failed\n");
			return NULL;
		 }

		 for (i = 0; i < numargs; i++)
			args[i] = NULL;

		 *h = '\0';

		 ret = policy_construct_parse_arguments(args, numargs, t);
		 if (!ret) {
			fprintf(stderr, "policy_construct: policy_construct_parse_arguments failed\n");
			free(args);
			return NULL;
		 }
	  }

	  /*
	     Allocate policy structure,
		 add to linked list
	  */

	  p = (policy_t *)malloc(sizeof(policy_t));
	  if (p == NULL) {
		 for (i = 0; i < numargs; i++)
			free(args[i]);

		 free(args);

		 fprintf(stderr, "policy_construct: malloc failed\n");
		 return NULL;
	  }

	  memset(p, 0, sizeof(policy_t));

	  p->numargs = numargs;
	  p->args = args;
	  p->flags = flags;
	  p->next = NULL;

	  p->next = p_list;
	  p_list = p;
   }

   return p_list;
}

/*
   Parse policy arguments,
   fill array
*/

static int policy_construct_parse_arguments(char **args, const int numargs, char *data)
{
   int len = 0, i = 0;
   char *h = NULL, *t = NULL;

   i = 0;

   for (i = 0, h = t = data;;h++) {
	 if ((*h == ',') || (*h == '\0')) {
		len = (h - t);

		 if (*h == '\0')
			h = NULL;
		 else
			*h = '\0';

		 if (!(*t)) {
			for (; i >= 0; i--)
			   free(args[i]);

			fprintf(stderr, "policy_construct_parse_arguments: empty argument value\n");
			return 0;
		 }

		 if (i >= numargs) {
			for (; i >= 0; i--)
			   free(args[i]);

			fprintf(stderr, "policy_construct_parse_arguments: too many arguments\n");
			return 0;
		 }

		 args[i] = (char *)malloc(len + 1);
		 if (args[i] == NULL) {
			for (; i >= 0; i--)
			   free(args[i]);

			fprintf(stderr, "policy_construct_parse_arguments: malloc failed\n");
			return 0;
		 }

		 memset(args[i], 0, len + 1);
		 memcpy(args[i], t, len);

		 i++;

		 if (!h) 
			break;

		 t = (h + 1);
	  }
   }

   if (i != numargs) {
	  fprintf(stderr, "policy_construct_parse_arguments: post argument count failed (%d/%d)\n",
			i, numargs);

	  for (; i >= 0; i--)
		 free(args[i]);

	  return 0;
   }

   return 1;
}

/*
   Match a filter against an address string
*/

static int policy_match(const char *filter, const char *address)
{
   int ret = 0;

   if ((filter == NULL) || (address == NULL))
	  return 0;

#ifndef FNM_CASEFOLD
   int len = 0, flags = 0;
   char filt[POLICY_MAX_FILTER] = { 0 }, addr[POLICY_MAX_ADDRESS] = { 0 },
		*p = NULL;

   memset(filt, 0, sizeof(filt));

   len = strlen(filter);
   if (len >= POLICY_MAX_FILTER)
	  len = (POLICY_MAX_FILTER - 1);

   memcpy(filt, filter, len);
   
   for (p = filt; *p; p++)
	  *p = tolower(*p);
   
   memset(addr, 0, sizeof(addr));

   len = strlen(address);
   if (len >= POLICY_MAX_ADDRESS)
	  len = (POLICY_MAX_ADDRESS - 1);

   memcpy(addr, address, len);
   
   for (p = addr; *p; p++)
	  *p = tolower(*p);

   filter = filt;
   address = addr;
#else
   int flags = FNM_CASEFOLD;
#endif
   
   ret = fnmatch(filter, address, flags);
   if (ret == 0)
	  return 1;

   return 0;
}

/*
   See if a given policy applies to a particular
   address
*/

static int policy_applies_to(const policy_t *p, const char *addr)
{
   int i = 0;

   if ((p == NULL) || (addr == NULL))
	  return 0;

   if (p->numargs == 0) {
#ifdef DEBUG
	  fprintf(stderr, "policy_applies_to: no arguments (yes)\n");
#endif
	  return 1;
   }

   if (p->args == NULL) {
#ifdef DEBUG
	  fprintf(stderr, "policy_applies_to: broken arguments (no)\n");
#endif
	  return 0;
   }

   for (i = 0; i < p->numargs; i++) {
	  if (policy_match(p->args[i], addr)) {
#ifdef DEBUG
		 fprintf(stderr, "policy_applies_to: match (yes)\n");
#endif
		 return 1;
	  }
   }

#ifdef DEBUG
   fprintf(stderr, "policy_applies_to: no match (no)\n");
#endif
   return 0;
}

/*
   Return flags for policy identifier
*/

static int policy_flags(const char c)
{
   int flags = POLICY_F_NONE;

   switch(c) {
	  case 'l':
		 flags = (POLICY_F_LOCAL|POLICY_F_DISALLOW);
		 break;

	  case 'r':
		 flags = (POLICY_F_REMOTE|POLICY_F_DISALLOW);
		 break;

	  case 'e':
		 flags = (POLICY_F_EXTERNAL|POLICY_F_DISALLOW);
		 break;

	  case 'i':
		 flags = (POLICY_F_INTERNAL|POLICY_F_DISALLOW);
		 break;

	  case 'L':
		 flags = (POLICY_F_LOCAL|POLICY_F_ALLOW);
		 break;

	  case 'R':
		 flags = (POLICY_F_REMOTE|POLICY_F_ALLOW);
		 break;

	  case 'E':
		 flags = (POLICY_F_EXTERNAL|POLICY_F_ALLOW);
		 break;

	  case 'I':
		 flags = (POLICY_F_INTERNAL|POLICY_F_ALLOW);
		 break;
   
	  default:
		 break;
   };

   return flags;
}

/*
   Find a policy definition
*/

static policy_t *policy_find(const policy_t *sp, const int flag)
{
   for (; sp; sp = sp->next) {
	  if (sp->flags & flag)
		 return (policy_t *)sp;
   }

   return NULL;
}

/*
   Compare policies and determine
   if messaging is forbidden
*/

static int policy_forbids(void)
{
   policy_t *pl = NULL, *p = NULL;
   local_t *s_local = NULL, *r_local = NULL;
   int dtype = 0, s_forbid = 0, r_forbid = 0;

   /*
	  Find local policy if any
   */

   if (s_domain) 
	  s_local = local_find(s_domain, remoteinfo ? remoteinfo : mailfrom.s);

   if (r_domain)
	  r_local = local_find(r_domain, addr.s);

   /*
	  Determine type of delivery
	  (local, remote, external)
   */

   if ((s_domain) && (r_domain) && (s_domain == r_domain))
	  dtype = POLICY_F_LOCAL;

   else if ((s_domain == NULL) && (r_domain))
	  dtype = POLICY_F_EXTERNAL;

   else if ((s_domain) && (r_domain == NULL))
	  dtype = POLICY_F_REMOTE;

   else if ((s_domain) && (r_domain) && (s_domain != r_domain))
	  dtype = POLICY_F_REMOTE;

   else if ((s_domain == NULL) && (r_domain == NULL)) {
#ifdef DEBUG
	  fprintf(stderr, "policy_forbids: no policies for this delivery\n");
#endif
	  return 0;
   }

   else {
	  fprintf(stderr, "policy_forbids: unknown delivery type\n");
	  return -1;
   }

   p = NULL;
   s_forbid = r_forbid = 0;

   /*
	  If there is a local rule for sender, use that to
	  determine if able to send.  If not, check domain
   */

   if (s_local) {
	  p = policy_find(s_local->policy, dtype);
	  if (p) {
		 /*
		    See if policy matches
		 */

		 if (p->flags & POLICY_F_DISALLOW) {
			if (policy_applies_to(p, addr.s)) {
#ifdef DEBUG
			   fprintf(stderr, "*** sender local policy disallows\n");
#endif
			   s_forbid = 1;
			}

#ifdef DEBUG
			else
			   fprintf(stderr, "*** sender local policy allows\n");
#endif
		 }

		 else {
#ifdef DEBUG
			if (policy_applies_to(p, addr.s))
			   fprintf(stderr, "*** sender local policy allows\n");

			else {
			   fprintf(stderr, "*** sender local policy denies\n");
			   s_forbid = 1;
			}
#else
			if (!(policy_applies_to(p, addr.s)))
				  s_forbid = 1;
#endif
		 }
	  }

#ifdef DEBUG
	  else
		 fprintf(stderr, "*** no sender local policy\n");
#endif
   }

   if ((p == NULL) && (s_domain)) {
	  p = policy_find(s_domain->policy, dtype);
	  if (p) {
		 if (p->flags & POLICY_F_DISALLOW) {
			s_forbid = 1;
#ifdef DEBUG
			fprintf(stderr, "--- sender domain policy disallows\n");
#endif
		 }
	  }

#ifdef DEBUG
	  else
		 fprintf(stderr, "--- no sender domain policy\n");
#endif
   }

   /*
	  Deny messaging
   */

   if (s_forbid) {
#ifdef DEBUG
	  fprintf(stderr, "policy_forbids: sender policy denies messaging\n");
#endif
	  return 1;
   }

   /*
	  Reverse delivery type, and check same above
	  for recipient unless the recipient is of the
	  same domain
   */

   /*
	  A local user to local user delivery is an 'internal'
	  delivery for the recipient user.
   */

   if (dtype == POLICY_F_LOCAL) 
	  dtype = POLICY_F_INTERNAL;

   /*
	  Sender on same system, different domain.
	  This is considered an 'external' delivery
	  to the recipient
   */

   else if (dtype == POLICY_F_REMOTE)
	  dtype = POLICY_F_EXTERNAL;

   /*
	  Sender from off-system remains
	  as external
   */

   else if (dtype != POLICY_F_EXTERNAL) {
	  fprintf(stderr, "policy_forbids: unknown recipient delivery type\n");
	  return -1;
   }

   p = NULL;
   r_forbid = 0;

   if (r_local) {
	  p = policy_find(r_local->policy, dtype);
	  if (p) {
		 /*
		    See if policy matches
		 */

		 if (p->flags & POLICY_F_DISALLOW) {
			if (policy_applies_to(p, remoteinfo ? remoteinfo : mailfrom.s)) {
#ifdef DEBUG
			   fprintf(stderr, "*** recipient local policy disallows\n");
#endif
			   r_forbid = 1;
			}

#ifdef DEBUG
			else
			   fprintf(stderr, "*** recipient local policy allows\n");
#endif
		 }

		 else {
#ifdef DEBUG
			if (policy_applies_to(p, remoteinfo ? remoteinfo : mailfrom.s))
			   fprintf(stderr, "*** recipient local policy allows\n");

			else {
			   fprintf(stderr, "*** recipient local policy denies\n");
			   r_forbid = 1;
			}
#else
			if (!(policy_applies_to(p, remoteinfo ? remoteinfo : mailfrom.s)))
				  r_forbid = 1;
#endif
		 }
	  }

#ifdef DEBUG
	  else
		 fprintf(stderr, "*** no recipient local policy\n");
#endif
   }

   if ((p == NULL) && (r_domain)) {
	  p = policy_find(r_domain->policy, dtype);
	  if (p) {
		 if (p->flags & POLICY_F_DISALLOW) {
			r_forbid = 1;
#ifdef DEBUG
			fprintf(stderr, "--- recipient domain policy disallows\n");
#endif
		 }
	  }

#ifdef DEBUG
	  else
		 fprintf(stderr, "--- no recipient domain policy\n");
#endif

   }

   /*
	  Deny messaging
   */

   if (r_forbid) {
#ifdef DEBUG
	  fprintf(stderr, "policy_forbids: recipient policy denies messaging\n");
#endif
	  return 1;
   }

   /*
	  Accept message
   */

   return 0;
}

/*
   Search for a domain in the linked list of domains
*/

static domain_t *domain_find(const char *domain)
{
   domain_t *d = NULL;

   if (domain == NULL)
	  return NULL;

   for (d = domains; d; d = d->next) {
	  if (!(strcasecmp(d->domain, domain)))
		 return d;
   }

   return NULL;
}

/*
   Search for a local under a domain in the locals linked list
*/

static local_t *local_find(const domain_t *d, const char *local)
{
   local_t *l = NULL;

   if ((d == NULL) || (local == NULL)) {
	  fprintf(stderr, "local_find: null argument\n");
	  return NULL;
   }

   for (l = d->locals; l; l = l->next) {
	  if (policy_match(l->local, local))
		 return l;
   }

   return NULL;
}

/*
   Deallocate a policy
*/

static void policy_free(policy_t *policy)
{
   int i = 0;
   policy_t *p = NULL, *op = NULL;

   if (policy == NULL)
	  return;

   p = policy;

   while(p) {
	  op = p;
	  p = p->next;

	  if (op->args) {
		 if (op->numargs) {
			for (i = 0; i < op->numargs; i++) 
			   free(op->args[i]);

			free(op->args);
		 }

		 else
			fprintf(stderr, "policy_free: no argument count\n");
	  }

	  free(op);
   }
}

/*
   Deallocate a local
*/

static void local_free(local_t *local)
{
   local_t *l = NULL, *ol = NULL;

   if (local == NULL)
	  return;

   l = local;

   while(l) {
	  ol = l;
	  l = l->next;

	  if (ol->policy)
		 policy_free(ol->policy);

	  if (ol->local)
		 free(ol->local);

	  free(ol);
   }
}

/*
   Deallocate all domains
*/

static void domains_free(void)
{
   domain_t *d = NULL, *od = NULL;

   d = domains;

   while(d) {
	  od = d;
	  d = d->next;

	  if (od->policy)
		 policy_free(od->policy);

	  if (od->locals)
		 local_free(od->locals);

	  if (od->domain)
		 free(od->domain);

	  free(od);
   }

   domains = NULL;
}
