/*
 *
 * 'chkuser.c' v.2.0.9
 * for qmail/netqmail > 1.0.3 and vpopmail > 5.3.x
 *
 * Author: Antonio Nati tonix@interazioni.it
 * All rights on this software and
 * the identifying words chkusr and chkuser reserved by the author
 *
 * This software may be freely used, modified and distributed,
 * but this lines must be kept in every original or derived version.
 * Original author "Antonio Nati" and the web URL
 * "http://www.interazioni.it/opensource"
 * must be indicated in every related work or web page
 *
 */

#include <pwd.h>

/* required by vpopmail */
#include <stdio.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "case.h"
#include "dns.h"
#include "env.h"
#include "ipme.h"
#include "now.h"
#include "str.h"
#include "open.h"
#include "subfd.h"
#include "substdio.h"
#include "stralloc.h"

#include "vpopmail.h"
#include "vauth.h"
#include "vpopmail_config.h"

#include "chkuser.h"
#include "chkuser_settings.h"

#if defined _exit
#undef _exit
#endif

extern void flush();
extern void out (char *s);
extern int  addrallowed();
extern unsigned int byte_rchr();
extern int vmaildir_readquota(const char *dir,  const char *quota);

extern char *remotehost;
extern char *remoteip;
extern char *remoteinfo;
extern char *relayclient;
extern char *fakehelo;

extern void die_nomem();

#define DIE_NOMEM() die_nomem()

#if defined CHKUSER_DEBUG

#if defined CHKUSER_DEBUG_STDERR

#define CHKUSER_DBG(a) write (STDERR_FILENO, a, strlen (a))
#define CHKUSER_DBG_INT(a) { int x; char str[30]; sprintf (str, "%d", a); write (STDERR_FILENO, str, strlen (str));}

#else

#define CHKUSER_DBG(a) write (STDOUT_FILENO, a, strlen (a))
#define CHKUSER_DBG_INT(a) { int x; char str[30]; sprintf (str, "%d", a); write (STDOUT_FILENO, str, strlen (str));}

#endif
#else

#define CHKUSER_DBG(a) /* DBG dummy */
#define CHKUSER_DBG_INT(a) /* DBG dummy */

#endif

static int intrusion_threshold_reached = 0;
static int first_time_init_flag = 1;

static int recipients = 0;
static int wrong_recipients = 0;

static stralloc user = {0};
static stralloc domain = {0};
static stralloc domain_path = {0};
static stralloc tmp_path = {0};
static stralloc alias_path = {0};

#if defined CHKUSER_IDENTIFY_REMOTE_VARIABLE
 static char *identify_remote;
#endif

#if defined CHKUSER_ENABLE_EXTENSIONS
#define CHKUSER_ENABLE_USERS_EXTENSIONS
#endif

#if defined CHKUSER_ENABLE_LISTS
#define CHKUSER_ENABLE_EZMLM_LISTS
#endif

#if defined CHKUSER_EXTENSION_DASH
#define CHKUSER_USERS_DASH CHKUSER_EXTENSION_DASH
#endif


#if defined CHKUSER_ENABLE_VALIAS
#error  "chkuser setting error: CHKUSER_ENABLE_VALIAS has been substituted by VALIAS (within vpopmail includes); you don't need anymore this define"
#endif

#if defined CHKUSER_ENABLE_VAUTH_OPEN
#error  "chkuser setting error: CHKUSER_ENABLE_VAUTH_OPEN has been substituted by CHKUSER_ENABLE_VAUTH_OPEN_CALL; edit chkuser_settings.h and change your settings"
#endif

#if defined CHKUSER_ENABLE_VAUTH_OPEN_CALL
 static int db_already_open = 0;
#endif

#if defined CHKUSER_ALWAYS_ON && defined CHKUSER_STARTING_VARIABLE
#error	"chkuser setting error: CHKUSER_ALWAYS_ON and CHKUSER_STARTING_VARIABLE are mutually esclusive. Edit your chkuser_settings.h and disable one of them"
#endif

  static int starting_value = 0;

#if defined CHKUSER_STARTING_VARIABLE
  static char *starting_string = 0;
#endif

#if defined CHKUSER_EXTRA_MUSTAUTH_VARIABLE
  static int mustauth_value = 0;
#endif


#if defined CHKUSER_RCPT_LIMIT_VARIABLE
  static char *maxrcpt_string = 0;
  static int maxrcpt_limit = 0;
  static int maxrcpt_limit_reached = 0;
#endif

#if defined CHKUSER_DISABLE_VARIABLE
  static char *chkuser_disable_variable = 0;
#endif

#if defined CHKUSER_WRONGRCPT_LIMIT_VARIABLE
  static char *maxwrongrcpt_string = 0;
  static int maxwrongrcpt_limit = 0;
  static int maxwrongrcpt_limit_reached = 0;
#endif

#if defined CHKUSER_MBXQUOTA_VARIABLE
  static char *maxmbxquota_string = 0;
  static int maxmbxquota_limit = 0;
#endif

  static unsigned int sender_nocheck = 0;
  static char *sender_nocheck_variable = 0;

#if defined CHKUSER_SENDER_FORMAT || defined CHKUSER_SENDER_MX
static stralloc sender_user = {0};
static stralloc sender_domain = {0};
#endif

#if defined CHKUSER_ENABLE_DOUBLEBOUNCE_VARIABLE
static unsigned int enable_doublebounce = 0;
#endif

#if defined CHKUSER_ERROR_DELAY

  static int chkuser_delay_interval = CHKUSER_ERROR_DELAY * 1000;

#define CHKUSER_DELAY()	chkuser_delay()

void chkuser_delay (void) {

        usleep (chkuser_delay_interval);

#if defined CHKUSER_ERROR_DELAY_INCREASE
        chkuser_delay_interval += CHKUSER_ERROR_DELAY_INCREASE * 1000;
#endif
}

#if defined CHKUSER_RCPT_DELAY_ANYERROR
#define CHKUSER_RCPT_DELAY_ANY() chkuser_delay()
#else
#define CHKUSER_RCPT_DELAY_ANY() /* no delay for any error */
#endif

#if defined CHKUSER_SENDER_DELAY_ANYERROR
#define CHKUSER_SENDER_DELAY_ANY() chkuser_delay()
#else
#define CHKUSER_SENDER_DELAY_ANY() /* no delay for any error */
#endif


#else
#define CHKUSER_DELAY() /* no delay */
#define CHKUSER_RCPT_DELAY_ANY() /* no delay */
#define CHKUSER_SENDER_DELAY_ANY() /* no delay */
#endif

#if defined CHKUSER_ENABLE_LOGGING

static stralloc logstr = { 0 };

static void chkuser_commonlog (char *sender, char *rcpt, char *title, char *description) {

  substdio_puts (subfderr, "CHKUSER ");
  substdio_puts (subfderr, title);
  substdio_puts (subfderr, ": from <");
  substdio_puts (subfderr, sender);
  substdio_puts (subfderr, "|remoteinfo/auth:" );
  if (remoteinfo) {
	substdio_puts (subfderr, remoteinfo);
  }
  substdio_puts (subfderr, "|chkuser-identify:" );
#if defined CHKUSER_IDENTIFY_REMOTE_VARIABLE
  if (identify_remote) substdio_puts (subfderr, identify_remote);
#endif
  substdio_puts (subfderr, "> remote <helo:");
  if (fakehelo) substdio_puts (subfderr, fakehelo);
  substdio_puts (subfderr, "|remotehostname:" );
  if (remotehost) substdio_puts (subfderr, remotehost);
  substdio_puts (subfderr, "|remotehostip:" );
  if (remoteip) substdio_puts (subfderr, remoteip);
  substdio_puts (subfderr, "> rcpt <");
  substdio_puts (subfderr, rcpt);
  substdio_puts (subfderr, "> : ");
  substdio_puts (subfderr, description);
  substdio_puts (subfderr, "\n");
  substdio_flush (subfderr);
}

#else
#define chkuser_commonlog(a,b,c,d) /* no log */
#endif

#if defined CHKUSER_SENDER_FORMAT

static int check_sender_address_format (stralloc *user, stralloc *domain) {

        int x;

        for (x = 0; x < (user->len -1); ++x) {
                if ((!isalnum (user->s[x])) 

#if defined CHKUSER_ALLOW_SENDER_SRS
		&& (user->s[x] != '#')
		&& (user->s[x] != '+')
#endif
#if defined CHKUSER_ALLOW_SENDER_CHAR_1
		&& (user->s[x] != CHKUSER_ALLOW_SENDER_CHAR_1)
#endif
#if defined CHKUSER_ALLOW_SENDER_CHAR_2
		&& (user->s[x] != CHKUSER_ALLOW_SENDER_CHAR_2)
#endif
#if defined CHKUSER_ALLOW_SENDER_CHAR_3
		&& (user->s[x] != CHKUSER_ALLOW_SENDER_CHAR_3)
#endif
#if defined CHKUSER_ALLOW_SENDER_CHAR_4
		&& (user->s[x] != CHKUSER_ALLOW_SENDER_CHAR_4)
#endif
#if defined CHKUSER_ALLOW_SENDER_CHAR_5
		&& (user->s[x] != CHKUSER_ALLOW_SENDER_CHAR_5)
#endif
#if defined CHKUSER_ALLOW_SENDER_CHAR_6
                && (user->s[x] != CHKUSER_ALLOW_SENDER_CHAR_6)
#endif
#if defined CHKUSER_ALLOW_SENDER_CHAR_7
                && (user->s[x] != CHKUSER_ALLOW_SENDER_CHAR_7)
#endif
#if defined CHKUSER_ALLOW_SENDER_CHAR_8
                && (user->s[x] != CHKUSER_ALLOW_SENDER_CHAR_8)
#endif
#if defined CHKUSER_ALLOW_SENDER_CHAR_9
                && (user->s[x] != CHKUSER_ALLOW_SENDER_CHAR_9)
#endif
#if defined CHKUSER_ALLOW_SENDER_CHAR_10
                && (user->s[x] != CHKUSER_ALLOW_SENDER_CHAR_10)
#endif
#if defined CHKUSER_ALLOW_SENDER_CHAR_11
                && (user->s[x] != CHKUSER_ALLOW_SENDER_CHAR_11)
#endif
#if defined CHKUSER_ALLOW_SENDER_CHAR_12
                && (user->s[x] != CHKUSER_ALLOW_SENDER_CHAR_12)
#endif
		&& (user->s[x] != '_') && (user->s[x] != '-') && (user->s[x] != '.') && (user->s[x] != '=')) {
                        return 0;
                }
        }

/*
 * Be careful, this is a base check
 *      Minimum is x.xx + ending \0
 *      Minimum characters needed are 5
 */
#if defined CHKUSER_MIN_DOMAIN_LEN
        if (domain->len < (CHKUSER_MIN_DOMAIN_LEN +1)) {
                return 0;
        }
#endif

/*
 *      This is a safety check
 */
#if defined CHKUSER_MIN_DOMAIN_LEN
        if (domain->len < 2) {
                return 0;
        }
#endif

        for (x = 0; x < (domain->len -1); ++x) {
                if ((!isalnum (domain->s[x])) && (domain->s[x] != '-') && (domain->s[x] != '.')) {
                        return 0;
                }
        }

        if ((domain->s[0] == '-') || (domain->s[domain->len -2] == '-') || (domain->s[0] == '.') || (domain->s[domain->len -2] == '.')) {
                return 0;
        }
        if (strstr (domain->s, "..") != NULL) {
                return 0;
        }
	if (strncmp (domain->s, "xn--", 4) == 0) {
		if (strstr (&domain->s[4], "--") != NULL)
			return 0;
/* allowing domains with hyphens like y--s.co.jp
	} else {
		if (strstr (domain->s, "--") != NULL)
			return 0;
*/
	}
        if (strstr (domain->s, ".-") != NULL) {
                return 0;
        }
        if (strstr (domain->s, "-.") != NULL) {
                return 0;
        }
        if (strchr (domain->s, '.') == NULL) {
                return 0;
        }

        return 1;
}

#endif

#if defined CHKUSER_RCPT_FORMAT

static int check_rcpt_address_format (stralloc *user, stralloc *domain) {

        int x;

        for (x = 0; x < (user->len -1); ++x) {
                if ((!isalnum (user->s[x])) 
#if defined CHKUSER_ALLOW_RCPT_SRS
                && (user->s[x] != '#')
                && (user->s[x] != '+')
#endif
#if defined CHKUSER_ALLOW_RCPT_CHAR_1
                && (user->s[x] != CHKUSER_ALLOW_RCPT_CHAR_1)
#endif
#if defined CHKUSER_ALLOW_RCPT_CHAR_2
                && (user->s[x] != CHKUSER_ALLOW_RCPT_CHAR_2)
#endif
#if defined CHKUSER_ALLOW_RCPT_CHAR_3
                && (user->s[x] != CHKUSER_ALLOW_RCPT_CHAR_3)
#endif
#if defined CHKUSER_ALLOW_RCPT_CHAR_4
                && (user->s[x] != CHKUSER_ALLOW_RCPT_CHAR_4)
#endif
#if defined CHKUSER_ALLOW_RCPT_CHAR_5
                && (user->s[x] != CHKUSER_ALLOW_RCPT_CHAR_5)
#endif
#if defined CHKUSER_ALLOW_RCPT_CHAR_6
                && (user->s[x] != CHKUSER_ALLOW_RCPT_CHAR_6)
#endif
#if defined CHKUSER_ALLOW_RCPT_CHAR_7
                && (user->s[x] != CHKUSER_ALLOW_RCPT_CHAR_7)
#endif
#if defined CHKUSER_ALLOW_RCPT_CHAR_8
                && (user->s[x] != CHKUSER_ALLOW_RCPT_CHAR_8)
#endif
#if defined CHKUSER_ALLOW_RCPT_CHAR_9
                && (user->s[x] != CHKUSER_ALLOW_RCPT_CHAR_9)
#endif
#if defined CHKUSER_ALLOW_RCPT_CHAR_10
                && (user->s[x] != CHKUSER_ALLOW_RCPT_CHAR_10)
#endif
#if defined CHKUSER_ALLOW_RCPT_CHAR_11
                && (user->s[x] != CHKUSER_ALLOW_RCPT_CHAR_11)
#endif
#if defined CHKUSER_ALLOW_RCPT_CHAR_12
                && (user->s[x] != CHKUSER_ALLOW_RCPT_CHAR_12)
#endif
		&& (user->s[x] != '_') && (user->s[x] != '-') && (user->s[x] != '.') && (user->s[x] != '=')) {
                        return 0;
                }
        }

/*
 * Be careful, this is a base check
 *      Minimum is x.xx + ending \0
 *      Minimum characters needed are 5
 */
#if defined CHKUSER_MIN_DOMAIN_LEN
        if (domain->len < (CHKUSER_MIN_DOMAIN_LEN +1)) {
                return 0;
        }
#endif

/*
 *      This is a safety check
 */
#if defined CHKUSER_MIN_DOMAIN_LEN
        if (domain->len < 2) {
                return 0;
        }
#endif
        for (x = 0; x < (domain->len -1); ++x) {
                if ((!isalnum (domain->s[x])) && (domain->s[x] != '-') && (domain->s[x] != '.')) {
                        return 0;
                }
        }

        if ((domain->s[0] == '-') || (domain->s[domain->len -2] == '-') || (domain->s[0] == '.') || (domain->s[domain->len -2] == '.')) {
                return 0;
        }
        if (strstr (domain->s, "..") != NULL) {
                return 0;
        }
	if (strncmp (domain->s, "xn--", 4) == 0) {
		if (strstr (&domain->s[4], "--") != NULL)
			return 0;
/* allowing domains with hyphens like y--s.co.jp
	} else {
		if (strstr (domain->s, "--") != NULL)
			return 0;
*/
	}
        if (strstr (domain->s, ".-") != NULL) {
                return 0;
        }
        if (strstr (domain->s, "-.") != NULL) {
                return 0;
        }
        if (strchr (domain->s, '.') == NULL) {
                return 0;
        }

        return 1;
}

#endif

#if defined CHKUSER_SENDER_MX || defined CHKUSER_RCPT_MX

static   unsigned long mx_random;
static  ipalloc mx_ip = {0};

static int chkuser_mx_lookup (stralloc *domain) {

  int status;

	mx_random = now() + getpid();
	dns_init(0);
	status = dns_mxip (&mx_ip, domain, mx_random);

	if (status == DNS_MEM) DIE_NOMEM();

	return status;
}

#endif


void chkuser_cleanup (int exit_value) {

#if defined CHKUSER_DB_CLEANUP
	vclose ();
#endif
	_exit (exit_value);
}

static void first_time_init (void) {

  starting_value = 0;

#if defined CHKUSER_ALWAYS_ON
	starting_value = 1;
#endif

#if defined CHKUSER_STARTING_VARIABLE
        starting_string = env_get (CHKUSER_STARTING_VARIABLE);
        if (starting_string) {
                if (strcasecmp(starting_string, "ALWAYS") == 0) {
                        starting_value = 1;
                } else if (strcasecmp(starting_string, "DOMAIN") == 0) {
                        starting_value = 0;
/*
  Edit by Roberto Puzzanghera
  It seems like any other definition of starting_string ends up as "DOMAIN".
  Instead, if starting_string is otherwise defined, we want to turn off chkuser,
  just like if the starting_string is "NONE".
 */
                } else {
					starting_value = -1;
				}
		} else {
			starting_string = "";
			starting_value = -1;
        }
#endif

#if defined CHKUSER_DISABLE_VARIABLE 
        chkuser_disable_variable = env_get("CHKUSER_DISABLE_VARIABLE");
        if (chkuser_disable_variable) {
          if (env_get (chkuser_disable_variable)) {
            starting_value = -1;
          }
        }
    	else if (env_get (CHKUSER_DISABLE_VARIABLE)) { 
	      starting_value = -1; 
	    }
#endif

#if defined CHKUSER_EXTRA_MUSTAUTH_VARIABLE
        if (env_get (CHKUSER_EXTRA_MUSTAUTH_VARIABLE)) {
		if (relayclient) {
			mustauth_value = 0;
		} else {
			mustauth_value = 1;
		}
        }
#endif


#if defined CHKUSER_RCPT_LIMIT_VARIABLE
        maxrcpt_string = env_get (CHKUSER_RCPT_LIMIT_VARIABLE);
        if (maxrcpt_string) {
                maxrcpt_limit = atoi (maxrcpt_string);
                if (maxrcpt_limit < 1) {
                        maxrcpt_limit = 0;
                }
        } else {
                maxrcpt_string = "";;
        }
#endif

#if defined CHKUSER_WRONGRCPT_LIMIT_VARIABLE
        maxwrongrcpt_string = env_get (CHKUSER_WRONGRCPT_LIMIT_VARIABLE);
        if (maxwrongrcpt_string) {
                maxwrongrcpt_limit = atoi (maxwrongrcpt_string);
                if (maxwrongrcpt_limit < 1) {
                        maxwrongrcpt_limit = 0;
                }
        } else {
                maxwrongrcpt_string = "";
        }
#endif

#if defined CHKUSER_MBXQUOTA_VARIABLE
        maxmbxquota_string = env_get (CHKUSER_MBXQUOTA_VARIABLE);
        if (maxmbxquota_string) {
                maxmbxquota_limit = atoi (maxmbxquota_string);
                if (maxmbxquota_limit < 1) {
                	maxmbxquota_limit = 0;
                }
	} else {
               	maxmbxquota_string = "";
	}
#endif

#if defined CHKUSER_SENDER_NOCHECK_VARIABLE
        sender_nocheck_variable = env_get("CHKUSER_SENDER_NOCHECK_VARIABLE");
        if (sender_nocheck_variable) {
          if (env_get (sender_nocheck_variable)) {
            sender_nocheck = 1;
          }
          else {
            sender_nocheck = 0;
          }
        } else {
          if (env_get (CHKUSER_SENDER_NOCHECK_VARIABLE)) {
  		sender_nocheck = 1;
          } else {
  		sender_nocheck = 0;
          }
        }
#endif

#if defined CHKUSER_IDENTIFY_REMOTE_VARIABLE

        identify_remote = env_get (CHKUSER_IDENTIFY_REMOTE_VARIABLE);
#endif


#if defined CHKUSER_ENABLE_DOUBLEBOUNCE_VARIABLE

        if (env_get (CHKUSER_ENABLE_DOUBLEBOUNCE_VARIABLE)) {
                enable_doublebounce = 1;
        } else {
                enable_doublebounce = 0;
        }
#endif

        if (!stralloc_ready (&user, 300)) DIE_NOMEM();
        if (!stralloc_ready (&domain, 500)) DIE_NOMEM();
        if (!stralloc_ready (&domain_path, 1000)) DIE_NOMEM();
        if (!stralloc_ready (&tmp_path, 1000)) DIE_NOMEM();
        if (!stralloc_ready (&alias_path, 1000)) DIE_NOMEM();

	first_time_init_flag = 0;

}

/*
 * realrcpt ()
 *
 * Returns:
 *
 *	CHKUSER_OK = 1 = Ok, recipients does exists
 *
 *	0 = Not in rcpthosts
 *
 *	< 0 various errors
 *
 *
 * Parameters:
 *	stralloc *sender = sender address
 *	stralloc *rcpt = rcpt address to check
 *
 *
*/

static int realrcpt (stralloc *sender, stralloc *rcpt)
{
  int count;
  int retstat = CHKUSER_KO;
  struct vqpasswd *user_passwd = NULL;
  int fd_file = -1;
  int read_char;
  int offset;
  char read_buf[1024];

#if defined CHKUSER_ENABLE_UIDGID
  uid_t eff_uid;
  gid_t eff_gid;
#endif

#if defined CHKUSER_EXTRA_MUSTAUTH_VARIABLE
  if (mustauth_value == 1) {
	return CHKUSER_ERR_MUSTAUTH;
  }
#endif

  if (starting_value == -1) {
	if (addrallowed()) {
		return CHKUSER_OK_NOCHECKALL;
	} else {
		if (relayclient) {
			return CHKUSER_RELAYING;
		}
		return CHKUSER_NORCPTHOSTS;
	}
  }

  if (intrusion_threshold_reached == 1) {
	return CHKUSER_ERR_INTRUSION_THRESHOLD;
  }

#if defined CHKUSER_RCPT_LIMIT_VARIABLE

  ++recipients;
  if ((maxrcpt_limit > 0) && (recipients >= maxrcpt_limit)) {
	chkuser_commonlog (sender->s, rcpt->s, "intrusion threshold", "max number of allowed rcpt");
	intrusion_threshold_reached = 1;
        return CHKUSER_ERR_MAXRCPT;
  }
#endif

/* Search the '@' character */
  count = byte_rchr(rcpt->s,rcpt->len,'@');

  if (count < rcpt->len) {
    if (!stralloc_copyb (&user, rcpt->s, count)) DIE_NOMEM();
    if (!stralloc_copys (&domain, rcpt->s + count + 1)) DIE_NOMEM();
  }
  else {
    if (!stralloc_copys (&user, rcpt->s)) DIE_NOMEM();
    domain.len = 0;
  }
  if (!stralloc_0 (&user)) DIE_NOMEM();
  if (!stralloc_0 (&domain)) DIE_NOMEM();

#if defined CHKUSER_ENABLE_UIDGID

/* qmail-smtpd is running now as (effective) qmaild:nofiles */
/* Save the effective UID & GID (qmaild:nofiles) */
  eff_uid = geteuid ();
  eff_gid = getegid ();

/* Now set new effective UID & GID, getting it from real UID & GID (vpopmail:vchkpw) */
  setegid (getgid());
  seteuid (getuid());

/* qmail-smtpd is running now as effective vpopmail:vchkpw */
#endif


/*
 * 
 * Now let's start the test/setting suite
 *
 **/

	switch (0) {

	case 0:
/* These are some preliminary settings */
  		case_lowers (user.s);
  		case_lowers (domain.s);

	case 1:

                if (domain.len == 1) {
#if defined CHKUSER_DOMAIN_WANTED
                        retstat = CHKUSER_ERR_DOMAIN_MISSING;
			break;
#else
                        if (!stralloc_copys (&domain, DEFAULT_DOMAIN)) DIE_NOMEM();
  			if (!stralloc_0 (&domain)) DIE_NOMEM();
#endif
                }

	case 2:

#if defined CHKUSER_RCPT_FORMAT
              if (!env_get ("CHKUSER_RCPT_FORMAT_NOCHECK")) {
                if (check_rcpt_address_format (&user, &domain) == 0) {
                        retstat = CHKUSER_ERR_RCPT_FORMAT;
                        break;
                }
              }
#endif

	case 3:

                if (!addrallowed()) {

#if defined CHKUSER_RCPT_MX
                      if  (!env_get ("CHKUSER_RCPT_MX_NOCHECK")) {
			switch (chkuser_mx_lookup(&domain)) {

				case DNS_HARD:
					retstat = CHKUSER_ERR_RCPT_MX;
					break;

				case DNS_SOFT:
					retstat = CHKUSER_ERR_RCPT_MX_TMP;
					break;
			}

			if (retstat != CHKUSER_KO) {
				break;
			}
                      }
#endif
  			if (relayclient) {
				retstat = CHKUSER_RELAYING;
				break;
  			}

                        retstat = CHKUSER_NORCPTHOSTS;
                        break;
                }

	case 4:

#if defined CHKUSER_ENABLE_VGET_REAL_DOMAIN
/* Check if domain is a real domain */

                vget_real_domain(domain.s, domain.a);

                domain.len = strlen (domain.s) +1;
                if (domain.len > (domain.a - 1)) DIE_NOMEM();
#endif

/* Let's get domain's real path */
                if (vget_assign(domain.s, domain_path.s, domain_path.a -1, NULL, NULL) == NULL) {
			retstat = CHKUSER_OK;
			break;
		}
	
		domain_path.len = strlen (domain_path.s);

	case 5:

/* Check if domain has bouncing enabled */

		if (starting_value == 0) {

	                if (!stralloc_copy (&tmp_path, &domain_path)) DIE_NOMEM();

#if defined CHKUSER_SPECIFIC_BOUNCING
	  		if (!stralloc_cats (&tmp_path, "/")) DIE_NOMEM();
	  		if (!stralloc_cats (&tmp_path, CHKUSER_SPECIFIC_BOUNCING)) DIE_NOMEM();
			if (!stralloc_0 (&tmp_path)) DIE_NOMEM();
	  		fd_file = open_read (tmp_path.s);	
	  		if (fd_file != -1) {
	      			close (fd_file);
			} else {
				retstat = CHKUSER_OK_NOCHECKDOMAIN;
				break;
			}
#else
	  		if (!stralloc_cats (&tmp_path, "/.qmail-default")) DIE_NOMEM();
			if (!stralloc_0 (&tmp_path)) DIE_NOMEM();

	  		read_char = 0;
	  		fd_file = open_read (tmp_path.s);	
	  		if (fd_file != -1) {
	      			read_char = read (fd_file, read_buf, sizeof(read_buf) - 1);
	      			close (fd_file);
	      			if (read_char < 0) read_char = 0;
	  			}
	  		read_buf[read_char] = 0;

	  		if ( strstr(read_buf, CHKUSER_BOUNCE_STRING) == NULL ) {
				retstat = CHKUSER_OK_NOCHECKDOMAIN;
				break;
	  		}
#endif
		}


        case 6:

#if defined CHKUSER_ENABLE_VAUTH_OPEN_CALL
                if (db_already_open != 1) {
                        if (CHKUSER_VAUTH_OPEN_CALL () == 0) {
                                db_already_open == 1;
                        } else {
                                retstat = CHKUSER_ERR_AUTH_RESOURCE;
				break;
                        }
                }
#endif


	case 7:
#if defined VALIAS
/* Check for aliases/forwards - valias*/

		if (valias_select (user.s, domain.s) != NULL) {
			retstat = CHKUSER_OK;
			break;
		}
#endif

	case 8:
#if defined CHKUSER_ENABLE_ALIAS
/* Check for aliases/forwards - .qmail.x files */

		if (!stralloc_copy (&tmp_path, &user)) DIE_NOMEM();
                /* Change all '.' in ':' before continuing on aliases */
                for (count = 0; count < tmp_path.len; ++count)
        	        if (*(tmp_path.s + count) == '.') *(tmp_path.s + count) = ':';

                if (!stralloc_copy (&alias_path, &domain_path)) DIE_NOMEM();
                if (!stralloc_cats (&alias_path, "/.qmail-")) DIE_NOMEM();
                if (!stralloc_cats (&alias_path, tmp_path.s)) DIE_NOMEM();
                if (!stralloc_0 (&alias_path)) DIE_NOMEM();

		fd_file = open_read (alias_path.s);
		if (fd_file != -1) {
			close (fd_file);
			retstat = CHKUSER_OK;
			break;
		}
#endif

	case 9:

#if defined CHKUSER_ENABLE_ALIAS_DEFAULT

		if (!stralloc_copy (&tmp_path, &user)) DIE_NOMEM();
                /* Change all '.' in ':' before continuing on aliases */
                for (count = 0; count < tmp_path.len; ++count)
        	        if (*(tmp_path.s + count) == '.') *(tmp_path.s + count) = ':';

                /* Search for the outer '-' character */
                for (offset = user.len - 1; offset > 0; --offset) {
                        if (*(user.s + offset) == CHKUSER_USERS_DASH)  {
                                if (!stralloc_copy (&alias_path, &domain_path)) die_nomem();
                                if (!stralloc_cats (&alias_path, "/.qmail-")) die_nomem();
                                if (!stralloc_catb (&alias_path, user.s, offset)) die_nomem();
                                if (!stralloc_cats (&alias_path, "-default")) die_nomem();
                                if (!stralloc_0 (&alias_path)) die_nomem();

                                fd_file = open_read (alias_path.s);
                                if (fd_file != -1) {
                                        close (fd_file);
                                        retstat = CHKUSER_OK;
                                        break;
                                }
                        }
		}
	        if (retstat != CHKUSER_KO) {
	        	break;
                }

#endif

        case 10:
#if defined CHKUSER_ENABLE_USERS
/* User control: check the existance of a real user */

                user_passwd = vauth_getpw (user.s, domain.s);

#if defined CHKUSER_ENABLE_USERS_EXTENSIONS
                if (user_passwd == NULL) {
                       count = 0;
                       while ((count < (user.len -1)) && (user_passwd == NULL)) {
                               count += byte_chr(&user.s[count], user.len - count, CHKUSER_USERS_DASH);
                               if (count < user.len) {
                                       if (!stralloc_copyb (&tmp_path, user.s, count)) DIE_NOMEM();
                                       if (!stralloc_0 (&tmp_path)) DIE_NOMEM();
                                       user_passwd = vauth_getpw (tmp_path.s, domain.s);
                                         ++count;
                               }
                        }
                }

#endif
                if (user_passwd != NULL) {

                /* If user exists check if he has BOUNCE_MAIL flag set */

                        if (user_passwd->pw_gid & BOUNCE_MAIL)
                                retstat = CHKUSER_KO;
                        else {
                                retstat = CHKUSER_OK;
#if defined CHKUSER_MBXQUOTA_VARIABLE
                                if ((maxmbxquota_limit > 0) && (strcasecmp(user_passwd->pw_shell, "NOQUOTA") != 0)) {
                                        if (!stralloc_copys (&tmp_path, user_passwd->pw_dir)) DIE_NOMEM();
                                        if (!stralloc_cats (&tmp_path, "/Maildir")) DIE_NOMEM();
                                        if (!stralloc_0 (&tmp_path)) DIE_NOMEM();

                                        if (vmaildir_readquota(tmp_path.s,format_maildirquota(user_passwd->pw_shell))
                                                >= maxmbxquota_limit) {
                                                retstat = CHKUSER_ERR_MBXFULL;
                                        }
                                }
#endif
                        }
                        break;
                }
#endif

	case 11:
#if defined CHKUSER_ENABLE_EZMLM_LISTS
/* Let's check for mailing lists */

		/* Search for the outer CHKUSER_EZMLM_DASH character */
	      	for (offset = user.len - 2; offset > 0; --offset) {
			if (*(user.s + offset) == CHKUSER_EZMLM_DASH)  {
				if (!stralloc_copy (&tmp_path, &domain_path)) DIE_NOMEM();
	      			if (!stralloc_cats (&tmp_path, "/")) DIE_NOMEM();
	      			if (!stralloc_catb (&tmp_path, user.s, offset)) DIE_NOMEM();
	      			if (!stralloc_cats (&tmp_path, "/editor")) DIE_NOMEM();
	      			if (!stralloc_0 (&tmp_path)) DIE_NOMEM();
				fd_file = open_read (tmp_path.s);
				if (fd_file != -1) {
					close (fd_file);
					retstat = CHKUSER_OK;
					break;
				}
	        	}
		}
		if (retstat != CHKUSER_KO) {
			break;
		}
#endif

        case 12:
#if defined CHKUSER_ENABLE_MAILMAN_LISTS
/* Let's check for mailing lists */

                /* Search for the outer CHKUSER_MAILMAN_DASH character */
                for (offset = user.len - 2; offset > 0; --offset) {
                        if (*(user.s + offset) == CHKUSER_MAILMAN_DASH)  {
                                if (!stralloc_copy (&tmp_path, &domain_path)) DIE_NOMEM();
                                if (!stralloc_cats (&tmp_path, "/")) DIE_NOMEM();
				if (!stralloc_cats (&alias_path, "/.qmail-")) DIE_NOMEM();
                                if (!stralloc_catb (&tmp_path, user.s, offset)) DIE_NOMEM();
                                if (!stralloc_0 (&tmp_path)) DIE_NOMEM();
                                fd_file = open_read (tmp_path.s);
	                        read_char = 0;
        	                if (fd_file != -1) {
                	                read_char = read (fd_file, read_buf, sizeof(read_buf) - 1);
                        	        close (fd_file);
                                	if (read_char < 0) read_char = 0;
                                }
	                        read_buf[read_char] = 0;

        	                if ( strstr(read_buf, CHKUSER_MAILMAN_STRING) == NULL ) {
	                                retstat = CHKUSER_OK;
	                                break;
	                        }

                        }
                }
                if (retstat != CHKUSER_KO) {
                        break;
                }
#endif

/*
 * Add this code if another case is following
	case xx:
		code ....
		code ....
		code ....
		code ....

		if (xxxxxxxx) {
			retstat != CHKUSER_KO)
			break;
		}
*/
	    
        default:
                retstat = CHKUSER_KO;

	} /* end switch */

#if defined CHKUSER_ENABLE_UIDGID
/* Now switch back effective to saved UID & GID (qmaild:nofiles) */

  setegid (eff_gid);
  seteuid (eff_uid);

/* qmail-smtpd is running again as (effective) qmaild:nofiles */
#endif

  return retstat;

}



/*
 * chkuser_realrcpt ()
 *
 * Returns a simple status:
 *
 *      CHKUSER_OK = 1 = Ok, recipients does exists
 *
 *      CHKUSER_NORCPTHOSTS = Not in rcpthosts
 *
 *      CHKUSER_KO = ERROR
 *
 *
 * Parameters:
 *      stralloc *sender = sender address
 *      stralloc *rcpt = rcpt address to check
 *
 *
*/

int chkuser_realrcpt (stralloc *sender, stralloc *rcpt) {

int retstat;

  if (first_time_init_flag) {
        first_time_init ();
  }

  retstat = realrcpt (sender, rcpt);

	switch (retstat) {

		case CHKUSER_OK:
#if defined CHKUSER_LOG_VALID_RCPT
			chkuser_commonlog (sender->s, rcpt->s, "accepted rcpt", "found existing recipient");
#endif
			return CHKUSER_OK;
			break;

		case CHKUSER_OK_NOCHECKALL:
#if defined CHKUSER_LOG_VALID_RCPT
                        chkuser_commonlog (sender->s, rcpt->s, "accepted any rcpt", "accepted any recipient for any rcpt domain");
#endif
                        return CHKUSER_OK;
                        break;

                case CHKUSER_OK_NOCHECKDOMAIN:
#if defined CHKUSER_LOG_VALID_RCPT
                        chkuser_commonlog (sender->s, rcpt->s, "accepted any rcpt", "accepted any recipient for this domain");
#endif
                        return CHKUSER_OK;
                        break;

                case CHKUSER_RELAYING:
#if defined CHKUSER_LOG_VALID_RCPT
                        chkuser_commonlog (sender->s, rcpt->s, "relaying rcpt", "client allowed to relay");
#endif
                        return CHKUSER_RELAYING;
                        break;

		case CHKUSER_NORCPTHOSTS:
                        chkuser_commonlog (sender->s, rcpt->s, "rejected relaying", "client not allowed to relay");
		        CHKUSER_RCPT_DELAY_ANY();
			out(CHKUSER_NORELAY_STRING);
			break;

		case CHKUSER_KO:
			chkuser_commonlog (sender->s, rcpt->s, "rejected rcpt", "not existing recipient");
		        CHKUSER_DELAY();
 			out(CHKUSER_NORCPT_STRING);
			break;

		case CHKUSER_ERR_AUTH_RESOURCE:
			chkuser_commonlog (sender->s, rcpt->s, "no auth resource", "no auth resource available");
		        CHKUSER_RCPT_DELAY_ANY();
			out(CHKUSER_RESOURCE_STRING);
			break;

                case CHKUSER_ERR_MUSTAUTH:
                        chkuser_commonlog (sender->s, rcpt->s, "must auth", "sender not authenticated/authorized");
                        CHKUSER_RCPT_DELAY_ANY();
                        out(CHKUSER_MUSTAUTH_STRING);
                        break;

		case CHKUSER_ERR_MBXFULL:
			chkuser_commonlog (sender->s, rcpt->s, "mbx overquota", "rcpt mailbox is overquota");
		        CHKUSER_RCPT_DELAY_ANY();
			out(CHKUSER_MBXFULL_STRING);
			break;

		case CHKUSER_ERR_MAXRCPT:
			chkuser_commonlog (sender->s, rcpt->s, "rejected rcpt", "max number of recipients");
		        CHKUSER_DELAY ();
			out(CHKUSER_MAXRCPT_STRING);
			break;

		case CHKUSER_ERR_MAXWRONGRCPT:
			chkuser_commonlog (sender->s, rcpt->s, "rejected rcpt", "max number of invalid recipients");
		        CHKUSER_DELAY ();
			out(CHKUSER_MAXWRONGRCPT_STRING);
			break;

		case CHKUSER_ERR_INTRUSION_THRESHOLD:
			chkuser_commonlog (sender->s, rcpt->s, "rejected intrusion", "rcpt ignored, session over intrusion threshold");
			CHKUSER_DELAY ();
			out(CHKUSER_INTRUSIONTHRESHOLD_STRING);
			break;

		case CHKUSER_ERR_DOMAIN_MISSING:
		        CHKUSER_DELAY ();
			out(CHKUSER_DOMAINMISSING_STRING);
			break;

                case CHKUSER_ERR_RCPT_FORMAT:
                        chkuser_commonlog (sender->s, rcpt->s, "rejected rcpt", "invalid rcpt address format");
		        CHKUSER_RCPT_DELAY_ANY();
			out(CHKUSER_RCPTFORMAT_STRING);
                        break;

                case CHKUSER_ERR_RCPT_MX:
			chkuser_commonlog (sender->s, rcpt->s, "rejected rcpt", "invalid rcpt MX domain");
		        CHKUSER_RCPT_DELAY_ANY();
			out(CHKUSER_RCPTMX_STRING);
                        break;

                case CHKUSER_ERR_RCPT_MX_TMP:
                        chkuser_commonlog (sender->s, rcpt->s, "rejected rcpt", "temporary DNS problem");
                        CHKUSER_RCPT_DELAY_ANY();
                        out(CHKUSER_RCPTMX_TMP_STRING);
                        break;
	}



#if defined CHKUSER_WRONGRCPT_LIMIT_VARIABLE
	if ((retstat == CHKUSER_KO) || (retstat == CHKUSER_ERR_DOMAIN_MISSING)) {
        	++wrong_recipients;
        	if ((intrusion_threshold_reached == 0) && (maxwrongrcpt_limit > 0) && (wrong_recipients >= maxwrongrcpt_limit)) {
        	        chkuser_commonlog (sender->s, rcpt->s, "intrusion threshold", "max number of allowed invalid rcpt");
        	        intrusion_threshold_reached = 1;
        	}
	}
#endif

	return retstat;
}


/*
 *
 * This routine checks for sender format and MX
 *
 */


int chkuser_sender (stralloc *sender) {

int count;

	if (first_time_init_flag) {
		first_time_init ();
	}

#if defined CHKUSER_EXTRA_MUSTAUTH_VARIABLE
	if (mustauth_value == 1) {
		out(CHKUSER_MUSTAUTH_STRING);
#if defined CHKUSER_LOG_VALID_SENDER
                        chkuser_commonlog (sender->s, "", "must auth", "sender not authenticated/authorized");
                        CHKUSER_SENDER_DELAY_ANY();
#endif
		return CHKUSER_ERR_MUSTAUTH;
	}
#endif

        if (sender->len <= 1) {
#if defined CHKUSER_LOG_VALID_SENDER
                chkuser_commonlog (sender->s, "", "accepted sender", "accepted null sender always");
#endif
                return CHKUSER_OK;
        }

	if ((starting_value == -1) || (sender_nocheck == 1)) {
#if defined CHKUSER_LOG_VALID_SENDER
                        chkuser_commonlog (sender->s, "", "accepted sender", "accepted any sender always");
#endif
		return CHKUSER_OK;
	}

#if defined CHKUSER_ENABLE_DOUBLEBOUNCE_VARIABLE
	if ((enable_doublebounce) && str_equal(sender->s,"#@[]")) {
#if defined CHKUSER_LOG_VALID_SENDER
                chkuser_commonlog (sender->s, "", "accepted doublebounce", "accepted qmail doublebounce #@[]");
#endif
                return CHKUSER_OK;
	}
#endif

#if defined CHKUSER_SENDER_FORMAT || defined CHKUSER_SENDER_MX
        count = byte_rchr(sender->s,sender->len,'@');
        if (count < sender->len) {
                if (!stralloc_copyb (&sender_user, sender->s, count)) DIE_NOMEM();
                if (!stralloc_copys (&sender_domain, sender->s + count + 1)) DIE_NOMEM();
        } else {
                if (!stralloc_copys (&sender_user, sender->s)) DIE_NOMEM();
                sender_domain.len = 0;
        }
        if (!stralloc_0 (&sender_user)) DIE_NOMEM();
        if (!stralloc_0 (&sender_domain)) DIE_NOMEM();

#if defined CHKUSER_SENDER_FORMAT
      if (!env_get ("CHKUSER_SENDER_FORMAT_NOCHECK")) {
        if (check_sender_address_format (&sender_user, &sender_domain) == 0) {
                chkuser_commonlog (sender->s, "", "rejected sender", "invalid sender address format");
		CHKUSER_SENDER_DELAY_ANY();
		out(CHKUSER_SENDERFORMAT_STRING);
	        return CHKUSER_ERR_SENDER_FORMAT;
        }
      }
#endif

#if defined CHKUSER_SENDER_MX
      if (!env_get ("CHKUSER_SENDER_MX_NOCHECK")) {
	switch (chkuser_mx_lookup(&sender_domain)) {

		case DNS_HARD:
			CHKUSER_SENDER_DELAY_ANY();
			out(CHKUSER_SENDERMX_STRING);
			chkuser_commonlog (sender->s, "", "rejected sender", "invalid sender MX domain");
			return CHKUSER_ERR_SENDER_MX;
			break;

		case DNS_SOFT:
			CHKUSER_SENDER_DELAY_ANY();
			out(CHKUSER_SENDERMX_TMP_STRING);
			chkuser_commonlog (sender->s, "", "rejected sender", "temporary DNS problem");
			return CHKUSER_ERR_SENDER_MX_TMP;
			break;
	}
     }
#endif
#endif

#if defined CHKUSER_LOG_VALID_SENDER
                        chkuser_commonlog (sender->s, "", "accepted sender", "sender accepted");
#endif

	return CHKUSER_OK;

}


