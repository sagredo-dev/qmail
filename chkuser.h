
/*
 *
 * 'chkuser.h' v.2.0.9
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

#define CHKUSER
#define CHKUSER_VERSION		"2.0.9"
#define CHKUSER_VERSION_RL	2
#define CHKUSER_VERSION_MJ	0
#define CHKUSER_VERSION_MN	9

#define CHKUSER_OK_NOCHECKALL		11
#define CHKUSER_OK_NOCHECKDOMAIN	10
#define CHKUSER_OK			1
#define CHKUSER_RELAYING		0
#define CHKUSER_KO			-1
#define CHKUSER_NORCPTHOSTS		-10
#define CHKUSER_ERR_MUSTAUTH		-15
#define CHKUSER_ERR_AUTH_RESOURCE	-20
#define CHKUSER_ERR_MBXFULL		-30
#define CHKUSER_ERR_MAXRCPT		-40
#define CHKUSER_ERR_MAXWRONGRCPT	-50
#define CHKUSER_ERR_DOMAIN_MISSING	-60
#define CHKUSER_ERR_RCPT_FORMAT		-70
#define CHKUSER_ERR_RCPT_MX		-75
#define CHKUSER_ERR_RCPT_MX_TMP		-76
#define CHKUSER_ERR_SENDER_FORMAT	-80
#define CHKUSER_ERR_SENDER_MX		-85
#define CHKUSER_ERR_SENDER_MX_TMP	-86
#define CHKUSER_ERR_INTRUSION_THRESHOLD	-90


void chkuser_cleanup (int exit_value);
int chkuser_realrcpt (stralloc *sender, stralloc *rcpt);
int chkuser_sender (stralloc *sender);

#ifdef TLS_H
#undef _exit
#define _exit(value) { if (ssl) ssl_free(ssl); chkuser_cleanup(value); }
#else
#define _exit(value) chkuser_cleanup(value);
#endif
