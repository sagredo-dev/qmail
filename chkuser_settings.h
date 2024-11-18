/*
 *
 * 'chkuser_settings.h' v.2.0.9
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

/************************************************************************************************
 *
 * Changes as of November 2024 (Roberto Puzzanghera)
 *
 * - dropped variables CHKUSER_ALLOW_SENDER_CHAR_xx CHKUSER_ALLOW_RCPT_CHAR_xx
 *   (replaced by CHKUSER_ALLOWED_CHARS)
 * - dropped variables CHKUSER_ALLOW_SENDER_SRS and CHKUSER_ALLOW_RCPT_SRS, as we are always
 *   accepting '+' and '#' characters
 * - added variables CHKUSER_INVALID_UTF8_CHARS and CHKUSER_ALLOWED_CHARS
 *
 ***********************************************************************************************/

/*
 * the following line enables debugging of chkuser
 */
#define CHKUSER_DEBUG

/*
 * The following line moves DEBUG output from STDOUT (default) to STDERR
 * Example of usage within sh: ./qmail-smtpd 2> /var/log/smtpd-debug.log
 */
#define CHKUSER_DEBUG_STDERR

/*
 * Uncomment the following define if you want chkuser ALWAYS enabled.
 * If uncommented, it will check for rcpt existance despite any .qmail-default
 * setting.
 * So, uncomment this if you are aware that ALL rcpt in all domains will be
 * ALWAYS checked.
 */
/* #define CHKUSER_ALWAYS_ON */

/*
 * The following defines which virtual manager is used.
 * Up to now, only vpopmail, but versions with pure qmail are in the mind.
 */
#define CHKUSER_VPOPMAIL

/*
 * Uncomment the following line if you want chkuser to work depending on a VARIABLE setting
 * VALUE HERE DEFINED is the name of the variable
 * Values admitted inside the variable: NONE | ALWAYS | DOMAIN
 * 		NONE 	= chkuser will not work
 *		ALWAYS	= chkuser will work always
 *		DOMAIN	= chkuser will work depending by single domain settings
 * CHKUSER_STARTING_VARIABLE cannot be defined together with CHKUSER_ALWAYS_ON
 * if CHKUSER_STARTING_VARIABLE is defined, and no variable or no value is set, then chkuser is disabled
 */
#define CHKUSER_STARTING_VARIABLE "CHKUSER_START"

/*
 * Uncomment this to enable uid/gid changing
 * (switching UID/GID is NOT compatible with TLS; you may keep this commented if you have TLS)
 */
/* #define CHKUSER_ENABLE_UIDGID */

/*
 * Uncomment this to check if a domain is ALWAYS specified in rcpt addresses
 */
#define CHKUSER_DOMAIN_WANTED

/*
 * Uncomment this to check for vpopmail users
 */
#define CHKUSER_ENABLE_USERS

/*
 * Uncomment this to check for alias
 */
#define CHKUSER_ENABLE_ALIAS

/*
 * The following #define set the character used for lists extensions
 * be careful: this is a  single char '-' definition, not a "string"
 */
#define CHKUSER_EZMLM_DASH '-'

/*
 * Uncomment this to set an alternative way to check for bouncing enabling;
 * with this option enabled, the file here defined
 * will be searched, inside the domain dir, in order to check if bouncing is enabled
 * The content of this file is not important, just it's existence is enough
 */
/* #define CHKUSER_SPECIFIC_BOUNCING ".qmailchkuser-bouncing" */

/*
 * This is the string to look for inside .qmail-default
 * Be careful, chkuser looks within the first 1023 characters of .qmail-default for
 * this string (despite the line containing the string is working or commented).
 */
#define CHKUSER_BOUNCE_STRING "bounce-no-mailbox"


/*
 * Uncomment to enable logging of rejected recipients and variuos limits reached
 */
#define CHKUSER_ENABLE_LOGGING

/*
 * Uncomment to enable logging of "good" rcpts
 * valid only if CHKUSER_ENABLE_LOGGING is defined
 */
#define CHKUSER_LOG_VALID_RCPT

/*
 * Uncomment to enable usage of a variable escluding any check on the sender.
 * The variable should be set in tcp.smtp for clients, with static IP, whose mailer
 * is composing bad sender addresses
 * Defining it as "RELAYCLIENT" will avoid sender checking for authenticated/authorized users.
 *	Senders will be logged anyway if CHKUSER_LOG_VALID_SENDER is defined.
 */
#define CHKUSER_SENDER_NOCHECK_VARIABLE "RELAYCLIENT"

/*
 * The following #define sets the minimum length of a domain:
 * as far as I know, "k.st" is the shortest domain, so 4 characters is the
 * minimum length.
 * This value is used to check formally a domain name validity.
 * if CHKUSER_SENDER_FORMAT is undefined, no check on length is done.
 * If you comment this define, no check on length is done.
 */
#define CHKUSER_MIN_DOMAIN_LEN 4

/*
 * Uncomment to enable logging of "good" senders
 * valid only if CHKUSER_ENABLE_LOGGING is defined
 */
#define CHKUSER_LOG_VALID_SENDER

/*
 * Uncomment to define a variable which contains the max recipients number
 * this will return always error if total recipients exceed this limit.
 * The first reached, between CHKUSER_RCPT_LIMIT_VARIABLE and CHKUSER_WRONGRCPT_LIMIT_VARIABLE,
 * makes chkuser rejecting everything else
 */
#define CHKUSER_RCPT_LIMIT_VARIABLE "CHKUSER_RCPTLIMIT"

/*
 * Uncomment to define a variable which contains the max unknown recipients number
 * this will return always error if not existing recipients exceed this limit.
 * The first reached, between CHKUSER_RCPT_LIMIT_VARIABLE and CHKUSER_WRONGRCPT_LIMIT_VARIABLE,
 * makes chkuser rejecting everything else
 */
#define CHKUSER_WRONGRCPT_LIMIT_VARIABLE "CHKUSER_WRONGRCPTLIMIT"

/*
 * Uncomment to define the variable containing the percent to check for.
 * Remember to define externally (i.e. in tcp.smtp) the environment variable containing
 * the limit percent.
 * If the variable is not defined, or it is <= 0, quota checking is not performed.
 */
#define CHKUSER_MBXQUOTA_VARIABLE "CHKUSER_MBXQUOTA"

/*
 * Delay to wait for each not existing recipient
 * value is expressed in milliseconds
 */
#define CHKUSER_ERROR_DELAY 1000

/*
 * Uncomment to consider rcpt errors on address format and MX as intrusive
 *
 */
#define CHKUSER_RCPT_DELAY_ANYERROR

/*
 * Uncomment to consider sender errors on address format and MX as intrusive
 *
 */
#define CHKUSER_SENDER_DELAY_ANYERROR


/***************************************************
 *
 *      new/modified defines in/from 2.0.6
 *
 **************************************************/

/*
 * Before version 5.3.25, vpopmail used the function vget_real_domain()
 * to get the real name of a domain (useful if rcpt domain is aliasing
 * another domain).
 * From version 5.3.25, this call is not available and has been
 * substituted by other calls.
 *
 *        must be enabled if vpopmail version< 5.3.5
 *        must be disabled  if vpopmail version => 5.3.5 *
 */
/* #define CHKUSER_ENABLE_VGET_REAL_DOMAIN */

/***************************************************
 *
 *      new/modified defines in/from 2.0.7
 *
 **************************************************/

/*
 * Uncomment next define to accept recipients for
 * aliases that have a -default extension
 */
#define CHKUSER_ENABLE_ALIAS_DEFAULT

/*
 * This define has been eliminated and its usage will generate an error.
 * Turning it ON or OFF has no effect, as we consider the existence
 * of #define VALIAS inside ~vpopmail/include/vpopmail_config.h
 */
/* #define CHKUSER_ENABLE_VALIAS */

/*
 * Uncomment this to enable user extension on names (i.e. TMDA)
 * (for mailing lists this is done without checking this define)
 * This define substitutes #define CHKUSER_ENABLE_EXTENSIONS
 */
/* #define CHKUSER_ENABLE_USERS_EXTENSIONS */

/*
 * Enables checking for EZMLM lists
 * this define substitutes #define CHKUSER_ENABLE_LISTS
 *
 */
#define CHKUSER_ENABLE_EZMLM_LISTS

/*
 * Help identifying remote authorized IPs giving them a descriptive name
 * Can be put in tcp.smtp, and will be displayed inside chkuser log
 */
#define CHKUSER_IDENTIFY_REMOTE_VARIABLE "CHKUSER_IDENTIFY"

/*
 * The following #define set the character used for users extensions
 * be careful: this is a  single char '-' definition, not a "string"
 * this define substitutes #define CHKUSER_EXTENSION_DASH
 * MUST be defined if CHKUSER_ENABLE_USERS_EXTENSIONS is defined
 */
#define CHKUSER_USERS_DASH '-'

/*
 * Enables checking for mailman lists
 *
 */
/* #define CHKUSER_ENABLE_MAILMAN_LISTS */

/*
 * Identifies the pattern string to be searched within mailman aliases
 *
 */
#define CHKUSER_MAILMAN_STRING "mailman"

/*
 * The following #define set the character used for mailman lists extensions
 * be careful: this is a  single char '-' definition, not a "string"
 */
#define CHKUSER_MAILMAN_DASH '-'


/*
 * Enables final clean-up routine of chkuser
 * This routine cleans open DB connections used for checking users and valiases
 */
#define CHKUSER_DB_CLEANUP

/***************************************************
 *
 *      new/modified defines in/from 2.0.8
 *
 **************************************************/

/*
 * The following defines are NO MORE used. NULL SENDER rejecting breaks RFC
 * compatibility, and makes harder to handle e-mail receipts.
 * Please comment or delete them from your chkuser_settings.h.
 */
/* #define CHKUSER_ACCEPT_NULL_SENDER */
/* #define CHKUSER_ENABLE_NULL_SENDER_WITH_TCPREMOTEHOST */

/*
 * Uncomment to enable checking of user and domain format for rcpt addresses
 *      user    =       any UTF8 character in the world EXCEPT CHKUSER_INVALID_UTF8_CHARS
 *                      provided that SMTPUTF8 was advertised by the remote client in MAIL FROM
 *                      or only alphanum chars with CHKUSER_ALLOWED_CHARS additions will be allowed
 *      domain  =       any UTF8 character in the world EXCEPT CHKUSER_INVALID_UTF8_CHARS with not consecutive "-.", not leading or ending "-."
 *                      provided that SMTPUTF8 was advertised by the remote client in MAIL FROM
 *                      or only alphanum chars with CHKUSER_ALLOWED_CHARS additions will be allowed
 */
#define CHKUSER_RCPT_FORMAT

/*
 * Uncomment to enable checking of domain MX for rcpt addresses
 * It works on any rcpt address domain that is not inside rcpthosts
 */
#define CHKUSER_RCPT_MX

/*
 * Uncomment to enable checking of user and domain format for sender address
 *      user    =       any UTF8 character in the world EXCEPT (),%:;<>@[\]
 *      domain  =       any UTF8 character in the world EXCEPT (),%:;<>@[\] with not consecutive "-.", not leading or ending "-."
 */
#define CHKUSER_SENDER_FORMAT

/*
 * Uncomment to enable checking of domain MX for sender address
 * it works on the first rcpt address, despite of any domain setting on chkuser
 */
#define CHKUSER_SENDER_MX

/*
 * Delay to add, for each not existing recipient, to the initial CHKUSER_ERROR_DELAY value
 * value is expressed in milliseconds
 */
#define CHKUSER_ERROR_DELAY_INCREASE 300

/***************************************************
 *
 *      new/modified defines in/from 2.0.9
 *
 **************************************************/

/*
 * A new class of defines is introduced
 *	CHKUSER_EXTRA_xxxxx
 *
 *	These defines will be used for features/behaviours that may work despite of other CHKUSER enable/disable settings
 *
 */

/*
 * If you want to accept only authenticated/authorized users you MUST enable this define and set the related variable.
 *
 * if this define is uncommented and the variable is set (to whatever value) then RELAYCLIENT must be set
 *      otherwise any message will be rejected giving "not authorized" error.
 *
 */
/* #define CHKUSER_EXTRA_MUSTAUTH_VARIABLE "CHKUSER_MUSTAUTH" */


/*
 * This is to check DB availability
 * It avoids bouncing messages with wrong codes if MySQL/LDAP/PostGRES/etc are down or not reachable
 *
 * If you are using MySQL in normal installation use #define CHKUSER_VAUTH_OPEN_CALL vauth_open_update
 * If you are using MySQL with separate servers for read and write use #define CHKUSER_VAUTH_OPEN_CALL vauth_open
 * If you are using other DB, check the most appropriate function for your DB within dedicated vpopmail module
 *
 * This define substitutes CHKUSER_ENABLE_VAUTH_OPEN
 */

/* #define CHKUSER_VAUTH_OPEN_CALL vauth_open   */
#define CHKUSER_VAUTH_OPEN_CALL vauth_open_update

/*
 * Variable to be set in order to disable chkuser
 * You may set it to any value you like. If it exists chkuser will be disabled.
 * 	Setting it to RELAYCLIENT helps disabling chkuser when sender is a known/authenticated mail client 
 * 	This is useful because Outlook/Eudora and other clients are not able to handle a KO when multiple recipients
 *		are present in the message. They should always relay to a SMTP service accepting all.
 *
 *	Recipients will be logged anyway if CHKUSER_LOG_VALID_RCPT is defined.
 *
 * Important changes from 2.0.9
 *	CHKUSER_ALWAYS_ON and CHKUSER_STARTING_VARIABLE cannot be defined together and in such a case a fatal error is displayed
 *	(in the previous versions CHKUSER_ALWAYS_ON would automatically disable CHKUSER_STARTING_VARIABLE definition)
 *
 *	CHKUSER_DISABLE_VARIABLE is always evaluated after CHKUSER_ALWAYS_ON is set or CHKUSER_STARTING_VARIABLE is evaluated, so
 *		CHKUSER_ALWAYS_ON or CHKUSER_STARTING_VARIABLE can set the general behaviour, while CHKUSER_DISABLE_VARIABLE
 *		should be invoked to handle exceptions.
 *
 */
#define CHKUSER_DISABLE_VARIABLE "RELAYCLIENT"


/*
 * Error strings (SMTP error answers)
 * If you don't like these definitions you can change them here
 *
 */
#define CHKUSER_NORCPT_STRING "550 5.1.1 sorry, no mailbox here by that name (chkuser)\r\n"
#define CHKUSER_RESOURCE_STRING "451 4.3.0 system temporary unavailable, try again later (chkuser)\r\n"
#define CHKUSER_MBXFULL_STRING "552 5.2.2 sorry, recipient mailbox is full (chkuser)\r\n"
#define CHKUSER_MAXRCPT_STRING "550 5.5.3 sorry, reached maximum number of recipients allowed in one session (chkuser)\r\n"
#define CHKUSER_MAXWRONGRCPT_STRING "550 5.5.3 sorry, you are violating our security policies (chkuser)\r\n"
#define CHKUSER_DOMAINMISSING_STRING "550 5.1.2 sorry, you must specify a domain (chkuser)\r\n"
#define CHKUSER_RCPTFORMAT_STRING "553 5.1.3 sorry, mailbox syntax not allowed (chkuser)\r\n"
#define CHKUSER_RCPTMX_STRING "550 5.1.2 sorry, can't find a valid MX for rcpt domain (chkuser)\r\n"
#define CHKUSER_SENDERFORMAT_STRING "553 5.1.7 sorry, mailbox syntax not allowed (chkuser)\r\n"
#define CHKUSER_SENDERMX_STRING "550 5.1.8 sorry, can't find a valid MX for sender domain (chkuser)\r\n"
#define CHKUSER_INTRUSIONTHRESHOLD_STRING "550 5.7.1 sorry, you are violating our security policies (chkuser)\r\n"
#define CHKUSER_NORELAY_STRING "553 5.7.1 sorry, that domain isn't in my list of allowed rcpthosts (chkuser)\r\n"

#define CHKUSER_RCPTMX_TMP_STRING "451 4.4.0 DNS temporary failure (chkuser)\r\n"
#define CHKUSER_SENDERMX_TMP_STRING "451 4.4.0 DNS temporary failure (chkuser)\r\n"

#define CHKUSER_MUSTAUTH_STRING "530 5.7.0 Authentication required (chkuser)\r\n"

/*
 * No more used defines
 *	Following defines are eliminated since 2.0.9
 *	They will make compilation errors and must be deleted/commented
 *
 * 			#define CHKUSER_ENABLE_VAUTH_OPEN -> Substituted by CHKUSER_VAUTH_OPEN_CALL
 */

/*
 * This define tells chkuser which variable must be set to accept a <#@[]> sender
 * This kind of sender is usually generated from qmail when there is a doublebounce
 * and all the job is done within the same system.
 * You may need to accept double bounces from outside when you are migrating servers and
 * doublebounces are forwarded between systems
 */
#define CHKUSER_ENABLE_DOUBLEBOUNCE_VARIABLE "CHKUSER_DOUBLEBOUNCE"

/*
 * Denied characters among the UTF8 set of charactes in sender name, rcpt name and domain name
 * CHKUSER_INVALID_UTF8_CHARS is evaluated only if the remote server advertises the SMTPUTF8 verb
 * in the MAIL FROM.
 */
#define CHKUSER_INVALID_UTF8_CHARS "(),:;<>@[]"

/*
 * CHKUSER_ALLOWED_CHARS is evaluated only when the remote server does NOT advertise the SMTPUTF8 verb in the
 * SMTP conversation. In this case only ASCII characters are allowed in sender name, rcpt name and domain name
 * plus the CHKUSER_ALLOWED_CHARS set of characters.
 *
 * As of November 2024, '#' and '+' are ALWAYS accepted regardless of the definition of CHKUSER_ALLOW_SENDER_SRS,
 * which is no longer used.
 * In addition, CHKUSER_ALLOWED_CHARS replaces the CHKUSER_ALLOW_SENDER_CHAR_1----12 variables,
 * which have been dropped.
 *
 * CHKUSER_ALLOWED_CHARS is used for additional characters both for sender and recipient names
 *
 * #+_-.= should be always allowed (# and + are needed for SRS)
 */
#define CHKUSER_ALLOWED_CHARS "$%?*^~&/\\£#+_-.="
