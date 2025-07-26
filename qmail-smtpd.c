#include "sig.h"
#include "readwrite.h"
#include "stralloc.h"
#include "substdio.h"
#include "alloc.h"
#include "auto_qmail.h"
#include "control.h"
#include "received.h"
#include "constmap.h"
#include "error.h"
#include "ipme.h"
#include "ip.h"
#include "qmail.h"
#include "str.h"
#include "strerr.h"
#include "qregex.h"
#include "cdb.h"
#include "fmt.h"
#include "scan.h"
#include "byte.h"
#include "case.h"
#include "env.h"
#include "now.h"
#include "exit.h"
#include "rcpthosts.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "commands.h"
#include "dns.h"
#include "wait.h"
#include "qmail-spp.h"
#include "base64.h"
#include "fd.h"
#include "open.h"
#include "policy.h"
#include <string.h>

extern int spp_rcpt_accepted();

/* chkuser.h will check if TLS_H is defined, so this has to come before chkuser.h */
#ifdef TLS
#include <sys/stat.h>
#include "tls.h"
#include "ssl_timeoutio.h"
void tls_init();
int tls_verify();
void tls_nogateway();
int ssl_rfd = -1, ssl_wfd = -1; /* SSL_get_Xfd() are broken */
int forcetls = 1;
stralloc proto = {0};
#endif

/* start chkuser code */
#include "chkuser.h"
/* end chkuser code */
#include "spf.h"
void spfreceived();
void spfauthenticated();
/* rbl: start */
#include "strsalloc.h"
/* rbl: end */

#define AUTHSLEEP 5

#define MAXHOPS 100

#define BMCHECK_BMF 0
#define BMCHECK_BMFNR 1
#define BMCHECK_BMT 2
#define BMCHECK_BMTNR 3
#define BMCHECK_BHELO 4
#define BMCHECK_BHELONR 5

int spp_val;

unsigned int databytes = 0;
char *greetdelays;
unsigned int greetdelay = 0;
unsigned int drop_pre_greet = 0;
int timeout = 1200;
int maxrcpt = -1;
unsigned int spfbehavior = 0;

/* rejectrelaytest: start */
unsigned int rejectrelaytest = 0;
/* rejecrelayttest: end */
/* rejectnullsenders: start */
unsigned int rejnsmf = 0;
/* rejectnullsenders: end */

static const char *protocol = "SMTP";

/* spf ipv6 fix */
char *remoteip4;
/* end spf ipv6 fix */

ssize_t safewrite(fd,buf,len) int fd; char *buf; int len;
{
  int r;
#ifdef TLS
  if (ssl && fd == ssl_wfd)
    r = ssl_timeoutwrite(timeout, ssl_rfd, ssl_wfd, ssl, buf, len);
  else
#endif
  r = timeoutwrite(timeout,fd,buf,len);
  if (r <= 0) _exit(1);
  return r;
}

char ssoutbuf[512];
char sslogbuf[512];
char sserrbuf[512];
substdio ssout = SUBSTDIO_FDBUF(safewrite,1,ssoutbuf,sizeof ssoutbuf);
substdio sslog = SUBSTDIO_FDBUF(safewrite,2,sslogbuf,sizeof sslogbuf);
substdio sserr = SUBSTDIO_FDBUF(safewrite,2,sserrbuf,sizeof sserrbuf);

int addrinrcpthosts = 0;
int envelopepos = 0; // 1: ehlo/helo, 2: mailfrom, 3: rcptto: 4: data
void qsmtpdlog(const char *head, const char *result, const char *reason, const char *detail, const char *statuscode);
void qlogenvelope(char *result, char *reason, char *detail, char *statuscode) { qsmtpdlog("qlogenvelope",result,reason,detail,statuscode); }
void qlogreceived(char *result, char *reason, char *detail, char *statuscode) { qsmtpdlog("qlogreceived",result,reason,detail,statuscode); }

void logit(const char* message);
void logit2(const char* message, const char* reason);
void flush() { substdio_flush(&ssout); }
void out(s) char *s; { substdio_puts(&ssout,s); }

void die_read(char *reason) { logit2("read failed", reason); flush(); _exit(1); }
void die_alarm() { qlogenvelope("rejected","alarmtimeout","","451"); out("451 timeout (#4.4.2)\r\n"); flush(); _exit(1); }
void die_nomem() { qlogenvelope("rejected","out_of_memory","","421"); out("421 out of memory (#4.3.0)\r\n"); flush(); _exit(1); }
void die_control() { qlogenvelope("rejected","cannot_read_controls","","421"); out("421 unable to read controls (#4.3.0)\r\n"); flush(); _exit(1); }
void die_ipme() { qlogenvelope("rejected","unknown_ip_me","","553"); out("421 unable to figure out my IP addresses (#4.3.0)\r\n"); flush(); _exit(1); }
/* rbl: start */
/*
void die_dnsbl(arg)
char *arg;
{
  out("421 your ip is currently blacklisted, try to auth first ("); out(arg); out(")\r\n");
  logit2("message rejected (qmail-dnsbl)", arg);
  flush();
  _exit(1);
}
*/
/* rbl: end */
void err_maxrcpt()
{
  out("452 max rcpt limit exceeded (#5.7.1)\r\n");
  qlogenvelope("rejected","max_rcpt_exceeded","","452");
  flush();
}
void straynewline() { qlogenvelope("rejected","bad_newlines","","451"); out("451 See http://pobox.com/~djb/docs/smtplf.html.\r\n"); flush(); _exit(1); }
void die_pre_greet() { qlogenvelope("rejected","pregreet","","554"); out("554 SMTP protocol violation\r\n"); flush(); _exit(1); }

void err_size() { qlogreceived("rejected","databytes_limit_exceeded","","552"); out("552 sorry, that message size exceeds my databytes limit (#5.3.4)\r\n"); }
#ifndef TLS
void err_nogateway() { qlogenvelope("rejected","not_in_rcpthosts","","553"); out("553 sorry, that domain isn't in my list of allowed rcpthosts (#5.7.1)\r\n"); }
#else
void err_nogateway()
{
  qlogenvelope("rejected","not_in_rcpthosts","","553"); out("553 sorry, that domain isn't in my list of allowed rcpthosts");
  tls_nogateway();
  out(" (#5.7.1)\r\n");
}
#endif
void err_unimpl(arg) char *arg; { out("502 unimplemented (#5.5.1)\r\n"); }
void err_unrecog() { out("500 unrecognised (#5.5.2)\r\n"); }
void err_syntax() { out("555 syntax error (#5.5.4)\r\n"); }
void err_wantmail() { out("503 MAIL first (#5.5.1)\r\n"); }
void err_wantrcpt() { out("503 RCPT first (#5.5.1)\r\n"); }
void err_noop(arg) char *arg; { out("250 ok\r\n"); }
void err_vrfy(arg) char *arg; { out("252 send some mail, i'll try my best\r\n"); }
void err_qqt() { qlogenvelope("rejected","qqtfailure","","451"); out("451 qqt failure (#4.3.0)\r\n"); }

int err_child() { out("454 oops, problem with child and I can't auth (#4.3.0)\r\n"); return -1; }
int err_fork() { out("454 oops, child won't start and I can't auth (#4.3.0)\r\n"); return -1; }
int err_pipe() { out("454 oops, unable to open pipe and I can't auth (#4.3.0)\r\n"); return -1; }
int err_write() { out("454 oops, unable to write pipe and I can't auth (#4.3.0)\r\n"); return -1; }
void err_authd() { out("503 you're already authenticated (#5.5.0)\r\n"); }
void err_authmail() { out("503 no auth during mail transaction (#5.5.0)\r\n"); }
int err_noauth() { out("504 auth type unimplemented (#5.5.1)\r\n"); return -1; }
int err_authabrt() { out("501 auth exchange canceled (#5.0.0)\r\n"); return -1; }
int err_input() { out("501 malformed auth input (#5.5.4)\r\n"); return -1; }
void err_authfail() { qlogenvelope("rejected","authfailed","","535"); out("535 authentication failed (#5.7.1)\r\n"); }
void err_authinvalid() { qlogenvelope("rejected","authinvalid","","504"); out("504 auth type invalid (#5.5.1)\r\n"); }
void err_submission() { qlogenvelope("rejected","authrequired","","530"); out("530 Authorization required (#5.7.1) \r\n"); }
void err_vrt() { qlogenvelope("rejected","validrcptto","","553"); out("553 sorry, this recipient is not in my validrcptto list (#5.7.1)\r\n"); }
void die_brtlimit() { qlogenvelope("rejected","brtlimit","","421"); out("421 too many invalid addresses, goodbye (#4.3.0)\r\n"); flush(); _exit(1); }
void err_rcpt() { qlogenvelope("rejected","nomailbox","","550"); out("550 sorry, no mailbox here by that name (#5.1.1)\r\n"); }
/* rcptcheck: start */
void die_fork() { qlogenvelope("rejected","rcptcheck","cannotfork","421"); out("421 unable to fork (#4.3.0)\r\n"); flush(); _exit(1); }
void die_rcpt() { qlogenvelope("rejected","rcptcheck","cannotverify","421"); out("421 unable to verify recipient (#4.3.0)\r\n"); flush(); _exit(1); }
void die_rcpt2() { qlogenvelope("rejected","rcptcheck","cannotexecute","421"); out("421 unable to execute recipient check (#4.3.0)\r\n"); flush(); _exit(1); }
/* rcptcheck: end */
/* qregex: start */
/*
void err_bmf() { out("553 sorry, your envelope sender is in my badmailfrom list (#5.7.1)\r\n"); }
*/
void err_bmf() { out("553 sorry, your envelope sender has been denied (#5.7.1)\r\n"); }
void err_bmt() { out("553 sorry, your envelope recipient has been denied (#5.7.1)\r\n"); }
void err_bhelo() { out("553 sorry, your HELO host name has been denied (#5.7.1)\r\n"); }
/* qregex: end */
/* rejectnullsenders: start */
void die_nullsender() { qlogenvelope("rejected","nullsenderdenied","","421"); out("421 null senders temporarily denied (#4.3.0)\r\n"); flush(); _exit(1); }
/* rejectnullsenders: end */
/* rejectrelaytest: start */
void err_relay() { qlogenvelope("rejected","dontrelay","","553"); out("553 we don't relay (#5.7.1)\r\n"); }
/* rejectrelaytest: end */
/* authtlsvariables: start */
void err_authmismatch() { qlogenvelope("rejected","authnotmailfrom","","503"); out("503 from and auth not the same (#5.5.1)\r\n"); }
/* authtlsvariables: end */

stralloc greeting = {0};
stralloc spflocal = {0};
stralloc spfguess = {0};
stralloc spfexp = {0};

void smtp_greet(code) char *code;
{
  substdio_puts(&ssout,code);
  substdio_put(&ssout,greeting.s,greeting.len);
}
void smtp_help(arg) char *arg;
{
  out("214 netqmail home page: http://qmail.org/netqmail\r\n");
}
void smtp_quit(arg) char *arg;
{
  smtp_greet("221 "); out("\r\n"); flush(); _exit(0);
}

/* char *protocol; */
char *remoteip;
char *remotehost;
char *remoteinfo;
char *local;
char *localport;
char *submission;
char *relayclient;
char *dnsblskip;
char *auth;
/* authtlsvariables: start */
int flagtls = 0;
int forceauthmailfrom = 0;
int disabletls = 0;
/* authtlsvariables: end */

char unique[FMT_ULONG + FMT_ULONG + 3];
static stralloc authin = {0};   /* input from SMTP client */
static stralloc user = {0};     /* authorization user-id */
static stralloc pass = {0};     /* plain passwd or digest */
static stralloc resp = {0};     /* b64 response */
static stralloc chal = {0};     /* plain challenge */
static stralloc slop = {0};     /* b64 challenge */

char **childargs;
char ssauthbuf[512];
substdio ssauth = SUBSTDIO_FDBUF(safewrite,3,ssauthbuf,sizeof(ssauthbuf));

stralloc helohost = {0};
char *fakehelo; /* pointer into helohost, or 0 */

void dohelo(arg) char *arg; {
  if (!stralloc_copys(&helohost,arg)) die_nomem(); 
  if (!stralloc_0(&helohost)) die_nomem(); 
  fakehelo = case_diffs(remotehost,helohost.s) ? helohost.s : 0;
}

int smtpauth = 0;
int liphostok = 0;
stralloc liphost = {0};
int bmfok = 0;
stralloc bmf = {0};

/* rbl: start */
int flagrbldns = 0;
int flagrbldelay = 0;
int flagrblfailclosed = 0;
int flagmustnotbounce = 0;
static stralloc rbldnslist = {0};
static stralloc rblhost = {0};
int rblhosterror = 0;
int rbllistok = 0;
int rblok = 0;
char *ip_env;
static stralloc ip_reverse;
int rbldecision = 0; /* 0 undecided, 1 accept, 2 reject (451), 3 bounce (553) */
static stralloc rbltext = {0}; /* defined if rbldecision is 2 or 3 */
static stralloc rblmessage = {0};
static stralloc rblserver = {0};

void err_rblreject() {
  if (env_get("RBLSMTPD")) {
    qlogenvelope("rejected","rblreject","rblsmtpd","553");
  }
  else {
    if (rblserver.len) qlogenvelope("rejected","rblreject",rblserver.s,"553");
    else qlogenvelope("rejected","rblreject","","553");
  }
  substdio_put(&ssout,rblmessage.s,rblmessage.len);
  flush();
}

void die_rbldelay() {
  if (env_get("RBLSMTPD")) {
    qlogenvelope("rejected","rbldelay","rblsmtpd","451");
  }
  else {
    if (rblserver.len) qlogenvelope("rejected","rbldelay",rblserver.s,"451");
    else qlogenvelope("rejected","rbldelay","","451");
  }
  substdio_put(&ssout,rblmessage.s,rblmessage.len); flush();
  _exit(1);
}
/* rbl: end */

/* qregex: start */
/*
 struct constmap mapbmf;
*/
int bmfnrok = 0;
stralloc bmfnr = {0};

int bmtok = 0;
stralloc bmt = {0};

int bmtnrok = 0;
stralloc bmtnr = {0};

int bhelook = 0;
stralloc bhelo = {0};

int bhelonrok = 0;
stralloc bhelonr = {0};

int logregex = 0;
stralloc matchedregex = {0};

int disable_badmailfrom = 0;
/* qregex: end */

/* validrcptto.cdb: start */
int vrtok = 0;
stralloc vrt = {0};
struct constmap mapvrt;

int vrtfd = -1;
int vrtcount = 0;
int vrtlog_do = 0;

stralloc title = {0};
char pid_buf[FMT_ULONG];
/* validrcptto.cdb: end */

/* realbadrcpt: start */
int brtlimit = 0;
static char strnumpid[FMT_ULONG];
static char strnumqp[FMT_ULONG];
/* realbadrcpt: end */

/* rcptcheck: start */
static char *rcptcheck[2] = { 0, 0 };
char rcptcheck_err[1024];
int rcptcheckrelayclient = 0;
/* rcptcheck: end */

void setup()
{
  char *x;
  unsigned long u;
 
  if (control_init() == -1) die_control();
  if (control_rldef(&greeting,"control/smtpgreeting",1,(char *) 0) != 1)
    die_control();
  liphostok = control_rldef(&liphost,"control/localiphost",1,(char *) 0);
  if (liphostok == -1) die_control();
  if (control_readint(&timeout,"control/timeoutsmtpd") == -1) die_control();
  if (timeout <= 0) timeout = 1;
  if (control_readint(&maxrcpt,"control/maxrcpt") == -1) die_control();

  if (rcpthosts_init() == -1) die_control();
  if (spp_init() == -1) die_control();

  bmfok = control_readfile(&bmf,"control/badmailfrom",0);
  if (bmfok == -1) die_control();
/* qregex: start */
/*
  if (bmfok)
    if (!constmap_init(&mapbmf,bmf.s,bmf.len,0)) die_nomem();
*/
  strnumpid[fmt_uint(strnumpid,(unsigned int) getpid())] = 0;

  bmfnrok = control_readfile(&bmfnr,"control/badmailfromnorelay",0);
  if (bmfnrok == -1) die_control();

  bmtok = control_readfile(&bmt,"control/badrcptto",0);
  if (bmtok == -1) die_control();

  bmtnrok = control_readfile(&bmtnr,"control/badrcpttonorelay",0);
  if (bmtnrok == -1) die_control();

  bhelook = control_readfile(&bhelo, "control/badhelo",0);
  if (bhelook == -1) die_control();

  bhelonrok = control_readfile(&bhelonr, "control/badhelonorelay",0);
  if (bhelonrok == -1) die_control();

  if (env_get("LOGREGEX")) logregex = 1;

  if (env_get("DISABLE_BADMAILFROM")) disable_badmailfrom = 1;

/* qregex: end */

/* validrcptto.cdb: start */
  x = env_get("VALIDRCPTTO");
  if (x) { vrtok = control_readfile(&vrt,x,0); }
  else vrtok = control_readfile(&vrt,"control/validrcptto",0);
  if (vrtok == -1) die_control();
  if (vrtok)
  if (!constmap_init(&mapvrt,vrt.s,vrt.len,0)) die_nomem();

  x = env_get("MOREVALIDRCPTTO_CDB");
  if (x) { vrtfd = open_read(x); }
  else vrtfd = open_read("control/morevalidrcptto.cdb");
  if (-1 == vrtfd) if (errno != error_noent) die_control();

  x = env_get("VALIDRCPTTO_LOG");
  if(x) { scan_ulong(x,&u); vrtlog_do = (int) u; }
/* validrcptto.cdb: end */

/* realbadrcpt: start */
  if (control_readint(&brtlimit,"control/brtlimit") == -1) die_control();
  x = env_get("BRTLIMIT");
  if (x) { scan_ulong(x,&u); brtlimit = u; };
  /* Disable limits check, defaults to 0 */
/*  if (brtlimit <= 1) brtlimit = 2; */
/* realbadrcpt: end */

/* rcptcheck: start */
  rcptcheck[0] = env_get("RCPTCHECK");

  x = env_get("RCPTCHECKRELAYCLIENT");
  if (x) { scan_ulong(x,&u); rcptcheckrelayclient = u; };
/* rcptcheck: end */

/* rejectrelaytest: start */
  if (control_readint(&rejectrelaytest,"control/rejectrelaytest") == -1) die_control();
/* rejectrelaytest: end */

/* rejectnullsenders: start */
  x = env_get("REJECTNULLSENDERS");
  if (x) { scan_ulong(x,&u); rejnsmf = u; }
  else if (control_readint(&rejnsmf,"control/rejectnullsenders") == -1) die_control();
/* rejectnullsenders: end */
 
  if (control_readint(&databytes,"control/databytes") == -1) die_control();
  x = env_get("DATABYTES");
  if (x) { scan_ulong(x,&u); databytes = u; }
  if (!(databytes + 1)) --databytes;

  greetdelays = env_get("SMTPD_GREETDELAY");
  if (greetdelays) { scan_ulong(greetdelays, &u); greetdelay = u; }
  x = env_get("DROP_PRE_GREET");
  if (x) { scan_ulong(x, &u); drop_pre_greet = u; }

  protocol = "SMTP";

  if (control_readint(&spfbehavior,"control/spfbehavior") == -1)
    die_control();
  x = env_get("SPFBEHAVIOR");
  if (x) { scan_ulong(x,&u); spfbehavior = u; }

  if (control_readline(&spflocal,"control/spfrules") == -1) die_control();
  if (spflocal.len && !stralloc_0(&spflocal)) die_nomem();
  if (control_readline(&spfguess,"control/spfguess") == -1) die_control();
  if (spfguess.len && !stralloc_0(&spfguess)) die_nomem();
  if (control_rldef(&spfexp,"control/spfexp",0,SPF_DEFEXP) == -1)
    die_control();
  if (!stralloc_0(&spfexp)) die_nomem();

  /* spf ipv6 fix */
  if (!(remoteip4 = env_get("TCPREMOTEIP")))
      remoteip4 = "unknown";
  /* end spf ipv6 fix */
  remoteip = env_get("TCPREMOTEIP");
  if (!remoteip) remoteip = "unknown";
  localport = env_get("TCPLOCALPORT");
  if (!localport) localport = "0";
  local = env_get("TCPLOCALHOST");
  if (!local) local = env_get("TCPLOCALIP");
  if (!local) local = "unknown";
  remotehost = env_get("TCPREMOTEHOST");
  if (!remotehost) remotehost = "unknown";
  remoteinfo = env_get("TCPREMOTEINFO");
  relayclient = env_get("RELAYCLIENT");
  dnsblskip = env_get("DNSBLSKIP");
/* rbl: start */
  x = env_get("DNSBLLIST");
  if (x) {
    rbllistok = control_readfile(&rbldnslist,x,0);
    if (rbllistok == -1) die_control();
    if (rbllistok) rblok = 1;
  }
  else {
    rbllistok = control_readfile(&rbldnslist,"control/dnsbllist",0);
    if (rbllistok == -1) die_control();
    if (rbllistok) rblok = 1;
  }

  /* from rblsmtpd.c, if RBLSMTPD is defined and empty then accept mail, if defined and string begins with '-' then
     block mail using error code 553 + string without hyphen, else (if defined, not null and not beginning with '-')
     reject mail using error code 451 + string  */
  x = env_get("RBLSMTPD");
  if (x) {
    if (!*x)
      rbldecision = 1;
    else if (*x == '-') {
      if (!stralloc_copys(&rbltext,x + 1)) die_nomem();
      rbldecision = 3;
    }
    else {
      if (!stralloc_copys(&rbltext,x)) die_nomem();
      rbldecision = 2;
    }
    rblok = 1;
  }
  
  if (control_readint(&flagrblfailclosed,"control/dnsblfailclosed") == -1) die_control();
  x = env_get("DNSBLFAILCLOSED");
  if (x) { scan_ulong(x,&u); flagrblfailclosed = u; }
/* rbl: end */
  auth = env_get("SMTPAUTH");
  if (auth) {
    smtpauth = 1;
    case_lowers(auth);
    if (!case_diffs(auth,"-") || !case_diffs(auth,"0")) smtpauth = 0;
    if (!case_diffs(auth,"!")) smtpauth = 11;
    if (case_starts(auth,"cram")) smtpauth = 2;
    if (case_starts(auth,"+cram")) smtpauth = 3;
    if (case_starts(auth,"!cram")) smtpauth = 12;
    if (case_starts(auth,"!+cram")) smtpauth = 13;
  }
/* authtlsvariables: start */
  x = env_get("FORCEAUTHMAILFROM"); if (x) if (!str_diff(x,"1")) { forceauthmailfrom = 1; }
  #ifdef TLS
  x = env_get("DISABLETLS"); if (x) if (!str_diff(x,"1")) { disabletls = 1; }
  #endif
/* authtlsvariables: end */
  #ifdef TLS
  x = env_get("FORCETLS"); if (x) if (!str_diff(x, "0")) forcetls = 0;
  if (env_get("SMTPS")) { smtps = 1; tls_init(); }
  else
  #endif
  dohelo(remotehost);
}

stralloc addr = {0}; /* will be 0-terminated, if addrparse returns 1 */

int addrparse(arg)
char *arg;
{
  int i;
  char ch;
  char terminator;
  struct ip_address ip;
  int flagesc;
  int flagquoted;
 
  terminator = '>';
  i = str_chr(arg,'<');
  if (arg[i])
    arg += i + 1;
  else { /* partner should go read rfc 821 */
    terminator = ' ';
    arg += str_chr(arg,':');
    if (*arg == ':') ++arg;
    if (*arg == '\0') return 0;
    while (*arg == ' ') ++arg;
  }

  /* strip source route */
  if (*arg == '@') while (*arg) if (*arg++ == ':') break;

  if (!stralloc_copys(&addr,"")) die_nomem();
  flagesc = 0;
  flagquoted = 0;
  for (i = 0; (ch = arg[i]); ++i) { /* copy arg to addr, stripping quotes */
    if (flagesc) {
      if (!stralloc_append(&addr,&ch)) die_nomem();
      flagesc = 0;
    }
    else {
      if (!flagquoted && (ch == terminator)) break;
      switch(ch) {
        case '\\': flagesc = 1; break;
        case '"': flagquoted = !flagquoted; break;
        default: if (!stralloc_append(&addr,&ch)) die_nomem();
      }
    }
  }
  /* could check for termination failure here, but why bother? */
  if (!stralloc_append(&addr,"")) die_nomem();

  if (liphostok) {
    i = byte_rchr(addr.s,addr.len,'@');
    if (i < addr.len) /* if not, partner should go read rfc 821 */
      if (addr.s[i + 1] == '[')
        if (!addr.s[i + 1 + ip_scanbracket(addr.s + i + 1,&ip)])
          if (ipme_is(&ip)) {
            addr.len = i + 1;
            if (!stralloc_cat(&addr,&liphost)) die_nomem();
            if (!stralloc_0(&addr)) die_nomem();
          }
  }

  if (addr.len > 900) return 0;
  return 1;
}

/* qregex: start */
/*
int bmfcheck()
{
  int j;
  if (!bmfok) return 0;
  if (constmap(&mapbmf,addr.s,addr.len - 1)) return 1;
  j = byte_rchr(addr.s,addr.len,'@');
  if (j < addr.len)
    if (constmap(&mapbmf,addr.s + j,addr.len - j - 1)) return 1;
  return 0;
}
*/
int bmcheck(which) int which;
{
  int i = 0;
  int j = 0;
  int x = 0;
  int negate = 0;
  static stralloc bmb = {0};
  static stralloc curregex = {0};

  if (which == BMCHECK_BMF) {
    if (!stralloc_copy(&bmb,&bmf)) die_nomem();
  } else if (which == BMCHECK_BMFNR) {
    if (!stralloc_copy(&bmb,&bmfnr)) die_nomem();
  } else if (which == BMCHECK_BMT) {
    if (!stralloc_copy(&bmb,&bmt)) die_nomem();
  } else if (which == BMCHECK_BMTNR) {
    if (!stralloc_copy(&bmb,&bmtnr)) die_nomem();
  } else if (which == BMCHECK_BHELO) {
    if (!stralloc_copy(&bmb,&bhelo)) die_nomem();
  } else if (which == BMCHECK_BHELONR) {
    if (!stralloc_copy(&bmb,&bhelonr)) die_nomem();
  } else {
    die_control();
  }

  while (j < bmb.len) {
    i = j;
    while ((bmb.s[i] != '\0') && (i < bmb.len)) i++;
    if (bmb.s[j] == '!') {
      negate = 1;
      j++;
    }
    if (!stralloc_copyb(&curregex,bmb.s + j,(i - j))) die_nomem();
    if (!stralloc_0(&curregex)) die_nomem();
    if (which == BMCHECK_BHELO) {
      x = matchregex(helohost.s, curregex.s);
    } else {
      x = matchregex(addr.s, curregex.s);
    }
    if ((negate) && (x == 0)) {
      if (!stralloc_copyb(&matchedregex,bmb.s + j - 1,(i - j + 1))) die_nomem();
      if (!stralloc_0(&matchedregex)) die_nomem();
      return 1;
    }
    if (!(negate) && (x > 0)) {
      if (!stralloc_copyb(&matchedregex,bmb.s + j,(i - j))) die_nomem();
      if (!stralloc_0(&matchedregex)) die_nomem();
      return 1;
    }
    j = i + 1;
    negate = 0;
  }
  return 0;
}
/* qregex: end */

/* validrcptto.cdb: start */
void vrtlog(l,a,b)
char *l;
const char *a;
const char *b;
{
/*  if (l <= vrtlog_do)
    strerr_warn6(title.s,"validrcptto [",remoteip,"] ",a,b,0);*/
}

int vrtcheck()
{
  static char *rcptto = "RCPT TO: ";
  static char *trying = "trying: ";
  static char *found  = "found: ";
  static char *reject = "reject: ";
  char *f = 0;
  int j,k,r;
  uint32 dlen;
  stralloc laddr = {0};

  stralloc luser = {0};
  stralloc adom = {0};
  stralloc utry = {0};
  stralloc stnoaddr = {0};
  stralloc stnodom = {0};

  int atfound, okaddr, okdom, noaddr, nodom;

  /* if both validrcptto and morevalidrcptto.cdb are missing, consider valid the recipient */
  if (!((vrtok) || (vrtfd != -1))) return 1;

  okaddr = 0; okdom = 0; noaddr = 0; nodom = 0; atfound = 0;

  /* lowercase whatever we were sent */
  if (!stralloc_copy(&laddr,&addr)) die_nomem() ;
  case_lowerb(laddr.s,laddr.len);

  /* split user/domain parts, create negated stralloc */
  j = byte_rchr(laddr.s,laddr.len,'@');
  if (j < laddr.len) {
    atfound = 1;
    if (!stralloc_copyb(&luser,laddr.s,j)) die_nomem();
    if (!stralloc_copyb(&adom,laddr.s+j,laddr.len-j-1)) die_nomem();

    if (!stralloc_copys(&stnodom,"-")) die_nomem();
    if (!stralloc_cat(&stnodom,&adom)) die_nomem();
    if (!stralloc_0(&stnodom)) die_nomem();

    if (!stralloc_copys(&stnoaddr,"-")) die_nomem();
    if (!stralloc_cat(&stnoaddr,&luser)) die_nomem();
    if (!stralloc_cat(&stnoaddr,&adom)) die_nomem();
    if (!stralloc_0(&stnoaddr)) die_nomem();
  }
  /* validrcptto */
  if (vrtok) {
    vrtlog(rcptto,laddr.s,0);
    if (constmap(&mapvrt,laddr.s,laddr.len - 1)) { okaddr = 1; vrtlog(found,laddr.s,0); }
    if (atfound) {
      if (constmap(&mapvrt,stnoaddr.s,stnoaddr.len-1)) { noaddr= 1; vrtlog(reject,stnoaddr.s,0); }
      if (constmap(&mapvrt,laddr.s+j,laddr.len-j-1)) { okdom = 1; vrtlog(found,laddr.s+j,0); }
      if (constmap(&mapvrt,stnodom.s,stnodom.len-1)) { nodom = 1; vrtlog(reject,stnodom.s,0); }
    }
  }
  
  /* morevalidrcptto.cdb */
  if ((vrtfd != -1)) {
    vrtlog(rcptto,laddr.s,0);

    if (cdb_seek(vrtfd,laddr.s,laddr.len-1,&dlen) > 0) { okaddr = 1; vrtlog(found,laddr.s,0); }
    if (atfound) {
      if (cdb_seek(vrtfd,stnoaddr.s,stnoaddr.len-1,&dlen) > 0) { noaddr = 1; vrtlog(reject,stnoaddr.s,0); }
      if (cdb_seek(vrtfd,laddr.s+j,laddr.len-j-1,&dlen) > 0) { okdom = 1; vrtlog(found,laddr.s+j,0); }
      if (cdb_seek(vrtfd,stnodom.s,stnodom.len-1,&dlen) > 0) { nodom = 1; vrtlog(reject,stnodom.s,0); }
    }
  }

  if (okaddr) return 1;
  else if (noaddr) return -1;
  else if (okdom) return 1;
  else if (nodom) return -1;
  else return 0;
}
/* validrcptto.cdb: end */

/* rbl: start */
void rbl(char *base)
{
  int i,j;
  int whitelisted = 0;
  int altmustbounce = 0;
  char *altreply = 0;
  int ignore = 0;
  strsalloc ssa = {0};

  if (!str_len(base)) return;
  if (!stralloc_copys(&rbltext,"")) die_nomem();
  if (!stralloc_copys(&rblhost,"")) die_nomem();
  if (!stralloc_copys(&rblserver,"")) die_nomem();

  if (!stralloc_copy(&rblhost,&ip_reverse)) die_nomem();
  i = str_chr(base, ':');
  if (base[i]) {
    if (base[i+1] == '-') { /* if reply begins with '-', message must bounce (check rblsmtpd man page) */
      altreply = base+i+2;
      altmustbounce = 1;
    }
    else altreply = base+i+1;
  }

  if (base[0] == '+') { /* entries beginning with '+' are for whitelistedlists */
    whitelisted = 1;
    if (!stralloc_catb(&rblhost,base+1,i-1)) die_nomem();
    if (!stralloc_catb(&rblserver,base+1,i-1)) die_nomem();
  }
  else if (base[0] == '-') { /* force bounce (553 error message), instead of default reject (451) */
    altmustbounce = 1;
    if (!stralloc_catb(&rblhost,base+1,i-1)) die_nomem();
    if (!stralloc_catb(&rblserver,base+1,i-1)) die_nomem();
  }
  else if (base[0] == '=') { /* ignore and just log */
    ignore = 1;
    if (!stralloc_catb(&rblhost,base+1,i-1)) die_nomem();
    if (!stralloc_catb(&rblserver,base+1,i-1)) die_nomem();
  }
  else {
    if (!stralloc_catb(&rblhost,base,i)) die_nomem();
    if (!stralloc_catb(&rblserver,base,i)) die_nomem();
  }
  if (!stralloc_0(&rblhost)) die_nomem();
  if (!stralloc_0(&rblserver)) die_nomem();

  rblhosterror = 0; /* set in case of dns errors */

  if (altreply) { /* if text response is defined in control file, query A records */
    if (dns_ip(&rbltext,&rblhost) == -1) {
      flagmustnotbounce = 1;
      rblhosterror = 1;
      if (flagrblfailclosed) {
        if (!stralloc_copys(&rbltext,"temporary RBL lookup error")) die_nomem();
        if (whitelisted) rbldecision = 1; else if (ignore) rbldecision = -1; else rbldecision = 2;
      }
      return;
    }
    if (rbltext.len) {
      if(!stralloc_copys(&rbltext, "")) die_nomem();
      while(*altreply) {
        i = str_chr(altreply, '%');
        if(!stralloc_catb(&rbltext, altreply, i)) die_nomem();
        if(altreply[i] &&
           altreply[i+1]=='I' &&
           altreply[i+2]=='P' &&
           altreply[i+3]=='%') {
          if(!stralloc_catb(&rbltext, ip_env, str_len(ip_env))) die_nomem();
          altreply+=i+4;
        } else if(altreply[i]) {
          if(!stralloc_cats(&rbltext, "%")) die_nomem();
          altreply+=i+1;
        } else {
          altreply+=i;
        }
      }
    }
  } else { /* normal rbl query looks for TXT record */
    if (dns_txt(&ssa,&rblhost) == -1) { /* DNS_SOFT = -1, DNS_HARD = -2, DNS_MEM = -3 */
      flagmustnotbounce = 1;
      rblhosterror = 1;
      if (flagrblfailclosed) {
        if (!stralloc_copys(&rbltext,"temporary RBL lookup error")) die_nomem();
        if (whitelisted) rbldecision = 1; else if (ignore) rbldecision = -1; else rbldecision = 2;
      }
      return;
    }
    else {
      /* in case of multiple records, take only the first */
      if (ssa.len > 0)
        if (!stralloc_cat(&rbltext,&ssa.sa[0])) die_nomem();
      /* in case of multiple records, append results to rbltext */
      /*for (j = 0;j < ssa.len;++j) if (!stralloc_cat(&rbltext,&ssa.sa[j])) die_nomem();*/
    }
  }
  if (rbltext.len) {
    if (whitelisted) {
      rbldecision = 1;
    }
    else {
      if (ignore) {
        rbldecision = -1;
      } else {
	 if (altmustbounce)
           rbldecision = 3;
         else
           rbldecision = 2;
      }
    }
  }
  else rbldecision = 0;
}

int rblcheck()
{
  char *ch;
  unsigned int i;
  unsigned int j;
  stralloc sar = {0};

  if (rbldecision) return rbldecision; /* rbldecision already set in case of RBLSMTPD or if rblcheck was executed previously */
  if (!rbllistok) return 0;

  ip_env = env_get("TCPREMOTEIP");
  if (!ip_env) ip_env = "";
  if (!stralloc_copys(&ip_reverse,"")) die_nomem();

  i = str_len(ip_env);
  while (i) {
    for (j = i;j > 0;--j) if (ip_env[j - 1] == '.') break;
    if (!stralloc_catb(&ip_reverse,ip_env + j,i - j)) die_nomem();
    if (!stralloc_cats(&ip_reverse,".")) die_nomem();
    if (!j) break;
    i = j - 1;
  }
  
  ch = rbldnslist.s;
  while (ch < (rbldnslist.s + rbldnslist.len)) {
    rbl(ch);
    /* debug log */
    if (!stralloc_copys(&sar,title.s)) die_nomem();
    if (!stralloc_cats(&sar,"rbl: ip=")) die_nomem();
    if (!stralloc_cats(&sar,ip_env)) die_nomem();
    if (!stralloc_cats(&sar," query=")) die_nomem();
    if (!stralloc_cats(&sar,rblhost.s)) die_nomem();
    if (rblhosterror) {
      if (!stralloc_cats(&sar," result=dnserr")) die_nomem();
    }
    else {
      if (!stralloc_cats(&sar," result=")) die_nomem();
      switch (rbldecision) {
        case -1: if (!stralloc_cats(&sar,"ignore")) die_nomem(); break;
        case 0: if (!stralloc_cats(&sar,"pass")) die_nomem(); break;
        case 1: if (!stralloc_cats(&sar,"accept")) die_nomem(); break;
        case 2: if (!stralloc_cats(&sar,"delay")) die_nomem(); break;
        case 3: if (!stralloc_cats(&sar,"reject")) die_nomem(); break;
      }
    }
    if (!stralloc_cats(&sar," message='")) die_nomem();
    if (!stralloc_catb(&sar,rbltext.s,rbltext.len)) die_nomem();
    if (!stralloc_cats(&sar,"'")) die_nomem();
    if (!stralloc_0(&sar)) die_nomem();
    strerr_warn1(sar.s,0);
    /* end debug log */
    if (rbldecision) break;
    while (*ch++);
  }
  return rbldecision;
}
/* rbl: end */

int addrallowed()
{
  int r;
  r = rcpthosts(addr.s,str_len(addr.s));
  if (r == -1) die_control();
#ifdef TLS
  if (r == 0) if (tls_verify()) r = -2;
#endif
  return r;
}

/* rejectrelaytest: start */
int addrrelay()
{
  if (!rejectrelaytest) { return 0; }
  else
  {
    int j;
    j = addr.len;
    while(--j >= 0)
      if (addr.s[j] == '@') break;
    if (j < 0) j = addr.len;
    while(--j >= 0) {
      if (addr.s[j] == '@') return 1;
      if (addr.s[j] == '%') return 1;
      if (addr.s[j] == '!') return 1;
    }
    return 0;
  }
}
/* rejectrelaytest: end */

int seenauth = 0;
int seenmail = 0;
int rcptcount = 0;

/* qregex: start */
/*
int flagbarf;
*/
int flagbarfbmf; /* defined if seenmail */
int flagbarfbmt;
int flagbarfbhelo;
/* qregex: end */

int allowed;
int flagsize;
int flagbarfspf;
stralloc spfbarfmsg = {0};
stralloc mailfrom = {0};
stralloc rcptto = {0};
stralloc fuser = {0};
stralloc mfparms = {0};
stralloc log_buf = {0};
int smtputf8 = 0; // if MAIL FROM has SMTPUTF8 param

/* realbadrcpt: start */
int flagvrt; /* defined if valid rcpt */
int brtcount = 0; /* for brtlimit count */
/* realbadrcpt: end */

/* rcptcheck: start */
int addrvalid()
{
  int pid;
  int wstat;
  int pierr[2] ;
  substdio ss;
  char ssbuf[sizeof(rcptcheck_err)];
  int len = 0 ;
  char ch;

  if (!rcptcheck[0]) return 1;
  if (pipe(pierr) == -1) die_rcpt2();

  switch(pid = fork()) {
    case -1:
      close(pierr[0]);
      close(pierr[1]);
      die_fork();
    case 0:
      if (!env_put2("SENDER",mailfrom.s)) die_nomem();
      if (!env_put2("RECIPIENT",addr.s)) die_nomem();
      if (!env_put2("HELO",helohost.s)) die_nomem();
      if (!env_put2("USE_FD4","1")) die_nomem();
      close(1);
      dup2(2,1);
      close(pierr[0]);
      if (fd_move(4,pierr[1]) == -1) die_rcpt2();
      execv(*rcptcheck,rcptcheck);
      _exit(120);
  }

  close(pierr[1]);
  if (wait_pid(&wstat,pid) == -1) die_rcpt2();
  if (wait_crashed(wstat)) die_rcpt2();

  substdio_fdbuf(&ss,read,pierr[0],ssbuf,sizeof(ssbuf));
  while ( substdio_bget(&ss,&ch,1) && len < (sizeof(ssbuf)-3) )
    rcptcheck_err[len++] = ch;
  close(pierr[0]);

  while (len&&((rcptcheck_err[len-1]=='\n')||(rcptcheck_err[len-1]=='\r')))
    len -- ;
  if (len) {
    rcptcheck_err[len] = '\0';
    strerr_warn3(title.s,"RCPTCHECK error: ",rcptcheck_err,0);
    rcptcheck_err[len++] = '\r';
    rcptcheck_err[len++] = '\n';
  }
  rcptcheck_err[len] = '\0';

  switch(wait_exitcode(wstat)) {
    case 100:
      return 0;
    case 111:
      die_rcpt();
    case 112:
      return 2; // ignore
    case 113:
      return 3; // overlimit
    case 120:
      die_rcpt2();
  }
  return 1;
}
/* rcptcheck: end */

int checkrcptcount() {
  if (env_get("DISABLE_MAXRCPT")) return 0;
  if (maxrcpt == -1) {return 0;}
  else if (rcptcount > maxrcpt) {return 1;}
  else {return 0;}
}

/* logging patch */

void safeloglen(const char* string, const int len) {
    if (string && len) {
        if (!stralloc_catb(&log_buf, string, len-1)) die_nomem();
    } else {
        if (!stralloc_catb(&log_buf, "(null)", 6)) die_nomem();
    }
}

void safelog(const char* string) {
    if (string) {
        if (!stralloc_cats(&log_buf, string)) die_nomem();
    } else {
        if (!stralloc_catb(&log_buf, "(null)", 6)) die_nomem();
    }
}

void logit(const char* message) {
    logit2(message, (const char*)0);
}

void logit2(const char* message, const char* reason)
{
  if (!stralloc_copys(&log_buf, "qmail-smtpd: ")) die_nomem();
  safelog(message);
  if (reason) {
      if (!stralloc_cats(&log_buf, " (")) die_nomem();
      if (!stralloc_cats(&log_buf, reason)) die_nomem();
      if (!stralloc_cats(&log_buf, ")")) die_nomem();
  }
  if (!stralloc_catb(&log_buf, ": ", 2)) die_nomem();
  safeloglen(mailfrom.s, mailfrom.len);
  if (!stralloc_catb(&log_buf, " from ", 6)) die_nomem();
  safelog(remoteip);
  if (!stralloc_catb(&log_buf, " to ", 4)) die_nomem();
  safeloglen(addr.s, addr.len);
  if (!stralloc_catb(&log_buf, " helo ", 6)) die_nomem();
  safeloglen(helohost.s, helohost.len);
  if (!stralloc_catb(&log_buf, "\n", 1)) die_nomem();
  substdio_putflush(&sserr, log_buf);
}

/* end logging patch */

int mailfrom_size(arg) char *arg;
{
  long r;
  unsigned long sizebytes = 0;

  scan_ulong(arg,&r);
  sizebytes = r;
  if (databytes) if (sizebytes > databytes) return 1;
  return 0;
}

void mailfrom_auth(arg,len)
char *arg;
int len;
{
  if (!stralloc_copys(&fuser,"")) die_nomem();
  if (case_starts(arg,"<>")) { if (!stralloc_cats(&fuser,"unknown")) die_nomem(); }
  else
    while (len) {
      if (*arg == '+') {
        if (case_starts(arg,"+3D")) { arg=arg+2; len=len-2; if (!stralloc_cats(&fuser,"=")) die_nomem(); }
        if (case_starts(arg,"+2B")) { arg=arg+2; len=len-2; if (!stralloc_cats(&fuser,"+")) die_nomem(); }
      }
      else
        if (!stralloc_catb(&fuser,arg,1)) die_nomem();
      arg++; len--;
    }
  if(!stralloc_0(&fuser)) die_nomem();
  if (!remoteinfo) {
    remoteinfo = fuser.s;
    if (!env_unset("TCPREMOTEINFO")) die_read("TCPREMOTEINFO unset");
    if (!env_put2("TCPREMOTEINFO",remoteinfo)) die_nomem();
  }
}

void mailfrom_parms(arg) char *arg;
{
  int i;
  int len;

    len = str_len(arg);
    if (!stralloc_copys(&mfparms,"")) die_nomem();
    i = byte_chr(arg,len,'>');
    if (i > 4 && i < len) {
      while (len) {
        arg++; len--;
        if (*arg == ' ' || *arg == '\0' ) {
           if (case_starts(mfparms.s,"SMTPUTF8")) smtputf8 = 1;
           if (case_starts(mfparms.s,"SIZE=")) if (mailfrom_size(mfparms.s+5)) { flagsize = 1; return; }
           if (case_starts(mfparms.s,"AUTH=")) mailfrom_auth(mfparms.s+5,mfparms.len-5);
           if (!stralloc_copys(&mfparms,"")) die_nomem();
        }
        else
           if (!stralloc_catb(&mfparms,arg,1)) die_nomem();
      }
    }
}

void smtp_helo(arg) char *arg;
{
  envelopepos = 1;
  if(!(spp_val = spp_helo(arg))) return;
  smtp_greet("250 "); out("\r\n");
  seenmail = 0; dohelo(arg);
  flagbarfbhelo = 0;
  if (spp_val == 1) {
    if (bhelook) flagbarfbhelo = bmcheck(BMCHECK_BHELO);
    if ((!flagbarfbhelo) && (bhelonrok) && (!relayclient)) flagbarfbhelo = bmcheck(BMCHECK_BHELONR);
  }
}
/* ESMTP extensions are published here */
void smtp_ehlo(arg) char *arg;
{
  char size[FMT_ULONG];
#ifdef TLS
  struct stat st;
#endif
  size[fmt_ulong(size,(unsigned int) databytes)] = 0;
  envelopepos = 1;
  if(!(spp_val = spp_helo(arg))) return;
  smtp_greet("250-");
  #ifdef TLS
  if (!disabletls && !ssl && (stat("control/servercert.pem",&st) == 0))
  out("\r\n250-STARTTLS");
  #endif
  out("\r\n250-PIPELINING\r\n250-SMTPUTF8\r\n250-8BITMIME\r\n");
#ifdef TLS
  if (!forcetls || ssl) {
#endif
  if (smtpauth == 1 || smtpauth == 11) out("250-AUTH LOGIN PLAIN\r\n");
  if (smtpauth == 3 || smtpauth == 13) out("250-AUTH LOGIN PLAIN CRAM-MD5\r\n");
  if (smtpauth == 2 || smtpauth == 12) out("250-AUTH CRAM-MD5\r\n");
#ifdef TLS
  }
#endif
  out("250 SIZE "); out(size); out("\r\n");
  seenmail = 0; dohelo(arg);
  flagbarfbhelo = 0;
  if (spp_val == 1) {
    if (bhelook) flagbarfbhelo = bmcheck(BMCHECK_BHELO);
    if ((!flagbarfbhelo) && (bhelonrok) && (!relayclient)) flagbarfbhelo = bmcheck(BMCHECK_BHELONR);
  }
}

void smtp_rset(arg) char *arg;
{
  spp_rset();
  seenmail = 0; /* seenauth = 0; RFC 5321: retain authentication */
  mailfrom.len = 0; rcptto.len = 0;
  /* prevents the maxrcpto error if control/maxrcpt limit has been exceeded in the same email, but not in multiple messages sequentially */
  rcptcount = 0;
  envelopepos = 1;
  /* end rcptcount adjustment */
  out("250 flushed\r\n");
}

void smtp_mail(arg) char *arg;
{
  int r;

  envelopepos = 2;
  if (smtpauth)
    if (smtpauth > 10 && !seenauth) { err_submission(); return; }
  if (!addrparse(arg)) { err_syntax(); return; }
/* authtlsvariables: start */
    /* if it is authenticated but MAIL FROM and AUTH USER are different */
    if (smtpauth && seenauth && forceauthmailfrom) {
      if (strcmp(addr.s,user.s)) { err_authmismatch(); return; }
    }
/* authtlsvariables: end */
/* rejectnullsenders: start */
  if ((rejnsmf) && (addr.len <= 1)) { die_nullsender(); return; }
/* rejectnullsenders: end */
  flagsize = 0;
  mailfrom_parms(arg);
  if (flagsize) {
    logit("exceeded datasize limit");
    err_size();
    return;
  }
  if (!(spp_val = spp_mail())) return;

/* start chkuser code */
  if (spp_val == 1) {
    switch (chkuser_sender (&addr)) {
      case CHKUSER_OK:
        break;
      case CHKUSER_ERR_MUSTAUTH:
        qlogenvelope("rejected","chkusersender","mustauth","530");
        return;
        break;
      case CHKUSER_ERR_SENDER_FORMAT:
        qlogenvelope("rejected","chkusersender","senderformat","553");
        return;
        break;
      case CHKUSER_ERR_SENDER_MX:
        qlogenvelope("rejected","chkusersender","sendermxinvalid","550");
        return;
        break;
      case CHKUSER_ERR_SENDER_MX_TMP:
        qlogenvelope("rejected","chkusersender","sendermxdnstmpfail","451");
        return;
        break;
      default:
        qlogenvelope("rejected","chkusersender","invalid","550");
        return;
        break;
    }
  }
/* end chkuser code */

/* qregex: start */
  flagbarfbmf = 0;
  if (spp_val == 1) {
  /*
    flagbarf = bmfcheck();
  */
    /* bmcheck is skipped for empty envelope senders */
    if ((bmfok) && (addr.len != 1)) flagbarfbmf = bmcheck(BMCHECK_BMF);
    if ((!flagbarfbmf) && (bmfnrok) && (addr.len != 1) && (!relayclient)) {
      flagbarfbmf = bmcheck(BMCHECK_BMFNR);
    }
  }
/* qregex: end */

  if (!stralloc_copys(&rcptto,"")) die_nomem();
  if (!stralloc_copys(&mailfrom,addr.s)) die_nomem();
  if (!stralloc_0(&mailfrom)) die_nomem();

  flagbarfspf = 0;
  if (spfbehavior && !relayclient)
   {
    switch(r = spfcheck(remoteip4)) {
    case SPF_OK: env_put2("SPFRESULT","pass"); break;
    case SPF_NONE: env_put2("SPFRESULT","none"); break;
    case SPF_UNKNOWN: env_put2("SPFRESULT","unknown"); break;
    case SPF_NEUTRAL: env_put2("SPFRESULT","neutral"); break;
    case SPF_SOFTFAIL: env_put2("SPFRESULT","softfail"); break;
    case SPF_FAIL: env_put2("SPFRESULT","fail"); break;
    case SPF_ERROR: env_put2("SPFRESULT","error"); break;
    }
    spfauthenticated();
    switch (r) {
    case SPF_NOMEM:
      die_nomem();
    case SPF_ERROR:
      if (spfbehavior < 2) break;
      qlogenvelope("rejected","spf","lookupfailure","451");
      out("451 SPF lookup failure (#4.3.0)\r\n");
      return;
    case SPF_NONE:
    case SPF_UNKNOWN:
      if (spfbehavior < 6) break;
    case SPF_NEUTRAL:
      if (spfbehavior < 5) break;
    case SPF_SOFTFAIL:
      if (spfbehavior < 4) break;
    case SPF_FAIL:
      if (spfbehavior < 3) break;
      if (!spfexplanation(&spfbarfmsg)) die_nomem();
      if (!stralloc_0(&spfbarfmsg)) die_nomem();
      flagbarfspf = 1;
    }
   }
  else env_unset("SPFRESULT");

  if (spp_val != 1) flagbarfspf = 0;

  seenmail = 1;
  out("250 ok\r\n");
}

void err_spf() {
  int i,j;

  for(i = 0; i < spfbarfmsg.len; i = j + 1) {
    j = byte_chr(spfbarfmsg.s + i, spfbarfmsg.len - i, '\n') + i;
    if (j < spfbarfmsg.len) {
      out("550-");
      spfbarfmsg.s[j] = 0;
      out(spfbarfmsg.s);
      spfbarfmsg.s[j] = '\n';
      out("\r\n");
    } else {
      out("550 ");
      out(spfbarfmsg.s);
      out(" (#5.7.1)\r\n");
    }
  }
}

int flagdnsbl = 0;
stralloc dnsblhost = {0};

void smtp_rcpt(arg) char *arg; {
  int flagrcptmatch = 0; /* 0 undefined, 1 validrcptto, 2 chkuser, 3 chkuserrelay, 4 rcptcheck */
/* added by empf patch */
  int ret = 0;
/* end of empf patch  */
  envelopepos = 3;
  if (!seenmail) { err_wantmail(); return; }
  if (!addrparse(arg)) { err_syntax(); return; }
/* rejectrelaytest: start */
  if (addrrelay()) { err_relay(); return; }
/* rejectrelaytest: end */
  if (addr.len) addrinrcpthosts = addrallowed();
  else addrinrcpthosts = 0;
/* qregex: start */
  /*
  if (flagbarf) { err_bmf(); return; }
  */
  if (flagbarfbhelo) {
    if (logregex) {
      strerr_warn5(title.s,"badhelo: <",helohost.s,"> matches pattern: ",matchedregex.s,0);
    } else {
      strerr_warn5(title.s,"badhelo: <",helohost.s,"> at ",remoteip,0);
    }
    qlogenvelope("rejected","qregexbhelo",matchedregex.s,"553");
    err_bhelo();
    return;
  }
  if (!disable_badmailfrom) {
   if (flagbarfbmf) {
     if (logregex) {
       strerr_warn5(title.s,"badmailfrom: <",mailfrom.s,"> matches pattern: ",matchedregex.s,0);
     } else {
       strerr_warn5(title.s,"badmailfrom: <",mailfrom.s,"> at ",remoteip,0);
     }
     qlogenvelope("rejected","qregexbmf",matchedregex.s,"553");
     err_bmf();
     return;
   }
  }
/* qregex: end */

  if (!relayclient) allowed = addrallowed();
  else allowed = 1;
  if (!(spp_val = spp_rcpt(allowed))) return;
fprintf(stderr,"spp_val2: %d\n",spp_val);
  if (flagbarfspf) { qlogenvelope("rejected","spf",env_get("SPFRESULT"),"550"); err_spf(); return; }

/* dnsbl: start */
/*
  if (!(relayclient || dnsblskip || flagdnsbl))
    if (dnsblcheck()) die_dnsbl(dnsblhost.s);
*/
/* dnsbl: end */
/* Original code substituted by chkuser code */
/*  if (relayclient) {
    --addr.len;
    if (!stralloc_cats(&addr,relayclient)) die_nomem();
    if (!stralloc_0(&addr)) die_nomem();
  }
  else
    if (!addrallowed()) { err_nogateway(); return; }
*/

/* qregex: start */
  if (spp_val == 1) {
    if (brtlimit && (brtcount >= brtlimit)) {
      strerr_warn3(title.s,"badrcptto: excessive rcptto violations hanging up on ",remoteip,0);
      die_brtlimit();
    }

    flagbarfbmt = 0;
    if (bmtok) flagbarfbmt = bmcheck(BMCHECK_BMT);
    if ((!flagbarfbmt) && (bmtnrok) && (!relayclient)) {
      flagbarfbmt = bmcheck(BMCHECK_BMTNR);
    }
    if (flagbarfbmt) {
      if (logregex) {
        strerr_warn5(title.s,"badrcptto: <",addr.s,"> matches pattern: ",matchedregex.s,0);
      } else {
        strerr_warn5(title.s,"badrcptto: <",addr.s,"> at ",remoteip,0);
      }
      qlogenvelope("rejected","qregexbmt",matchedregex.s,"553");
      ++brtcount;
      err_bmt();
      return;
    }
  }
/* qregex: end */

/* realbadrcpt: start */
  if ((spp_val == 1) && !relayclient) {	/* if relayclient is defined, skip valid recipient checking */
    /* validrcptto */
    flagvrt = 0;
    int vrtres = 0;
    if ((vrtok) || (vrtfd != -1)) {  /* run check only if validrcptto or morevalidrcptto.cdb exist */
      vrtres = vrtcheck();
      if (vrtres > 0) {
        flagvrt = 1;
	    flagrcptmatch = 1;
        strerr_warn5(title.s,"validrcptto: accepted address <",addr.s,"> at ",remoteip,0);
      }
      else if (vrtres < 0) {
        strerr_warn5(title.s,"validrcptto: drop address <",addr.s,"> at ",remoteip,0);
        ++brtcount;
        err_vrt();
        /*err_rcpt();*/
        return;
      }
    }
  } // if (!relayclient)

    if ((spp_val == 1) &&  !flagvrt) {
      switch (chkuser_realrcpt (&mailfrom, &addr)) {
         case CHKUSER_OK:
		flagrcptmatch = 2;
                break;
         case CHKUSER_RELAYING:
                --addr.len;
                if (!stralloc_cats(&addr,relayclient)) die_nomem();
                if (!stralloc_0(&addr)) die_nomem();
		flagrcptmatch = 3;
                break;
         case CHKUSER_NORCPTHOSTS:
                qlogenvelope("rejected","chkuser","notinrcpthosts","553");
                ++brtcount;
                return;
                break;
         case CHKUSER_KO:
                qlogenvelope("rejected","chkuser","nomailbox","550");
            	++brtcount;
                return;
                break;
         case CHKUSER_ERR_AUTH_RESOURCE:
                qlogenvelope("rejected","chkuser","noauthresource","451");
                return;
                break;
         case CHKUSER_ERR_MUSTAUTH:
                qlogenvelope("rejected","chkuser","mustauth","530");
                return;
                break;
         case CHKUSER_ERR_MBXFULL:
                qlogenvelope("rejected","chkuser","mailboxfull","552");
                return;
                break;
         case CHKUSER_ERR_MAXRCPT:
                qlogenvelope("rejected","chkuser","maxrcpt","550");
                return;
                break;
         case CHKUSER_ERR_MAXWRONGRCPT:
                qlogenvelope("rejected","chkuser","maxwrongrcpt","550");
                return;
                break;
         case CHKUSER_ERR_INTRUSION_THRESHOLD:
                qlogenvelope("rejected","chkuser","instrusionthreshold","550");
                ++brtcount;
                return;
                break;
         case CHKUSER_ERR_DOMAIN_MISSING:
                qlogenvelope("rejected","chkuser","domainmissing","550");
            	++brtcount;
                return;
                break;
         case CHKUSER_ERR_RCPT_FORMAT:
                qlogenvelope("rejected","chkuser","rcptformat","553");
                ++brtcount;
                return;
                break;
         case CHKUSER_ERR_RCPT_MX:
                qlogenvelope("rejected","chkuser","rcptmxinvalid","550");
            	++brtcount;
                return;
                break;
         case CHKUSER_ERR_RCPT_MX_TMP:
                qlogenvelope("rejected","chkuser","rcptmxdnstmpfail","451");
                return;
                break;
         default:
                qlogenvelope("rejected","chkuser","invalid","550");
                return;
                break;
      }
    }

  /* rcptcheck */
  if ( (rcptcheck[0]) && (!relayclient || rcptcheckrelayclient) ) { // if RCPTCHECK is not defined, addrvalid returns 1 (rcpt ok),check before calling
    strerr_warn5(title.s,"rcptcheck: checking <",addr.s,"> at ",remoteip,0);
    if (flagrcptmatch) {
      if (!env_put2("RCPTFOUND","1")) die_nomem();
    }
    else {
      if (!env_unset("RCPTFOUND")) die_nomem();
    }
    if (addrinrcpthosts) {
      if (!env_put2("RCPTHOSTS","1")) die_nomem();
    }
    else {
      if (!env_unset("RCPTHOSTS")) die_nomem();
    }

    int rcres = 0;
    rcres = addrvalid();

    char smtperrcode[4];
    char *smtperrstrptr;
    long smtperrcodenum = 0;
    int closesession = 0;

    if ((rcptcheck_err[0]) && (sizeof(rcptcheck_err) > 3)) {
      strncpy(smtperrcode,rcptcheck_err,3);
      smtperrcode[3] = '\0';
      smtperrcodenum = strtoul(smtperrcode, &smtperrstrptr, 10);
      if ((smtperrcodenum >= 400) && (smtperrcodenum <=599)) {
        if (smtperrcodenum == 421) closesession = 1;
      }
      else {
        str_copy(rcptcheck_err,"451 temporary problem (#4.4.2)\r\n");
        // strcpy() copies the string pointed to by src, including the terminating null byte ('\0')
        //rcptcheck_err[len] = '\0' ;
      }
      qlogenvelope("rejected","rcptcheck","custom",smtperrcode);
    }
    else {
      switch (rcres) {
        case 0:
          strerr_warn5(title.s,"rcptcheck: drop address <",addr.s,"> at ",remoteip,0);
          qlogenvelope("rejected","rcptcheck","nomailbox","550");
          str_copy(rcptcheck_err,"550 sorry, no mailbox here by that name. (#5.1.1)\r\n");
          //rcptcheck_err[len] = '\0';
          break;
        case 1:
          strerr_warn5(title.s,"rcptcheck: accepted address <",addr.s,"> at ",remoteip,0);
          flagrcptmatch = 4;
          break;
        case 2:
          strerr_warn5(title.s,"rcptcheck: ignore address <",addr.s,"> at ",remoteip,0);
          break;
        case 3:
          strerr_warn5(title.s,"rcptcheck: overlimit sender <",addr.s,"> at ",remoteip,0);
          qlogenvelope("rejected","rcptcheck","overlimit","421");
          str_copy(rcptcheck_err,"421 you have exceeded your messaging limits (#4.3.0)\r\n");
          //rcptcheck_err[len] = '\0';
          closesession = 1;
          break;
      }
    }

    if ( (rcres == 0) || (rcres == 3) ) {
      out(rcptcheck_err); flush();
      if (closesession) {
        _exit(1);
      }
      return;
    }
  } // if rcptcheck[0]
/* realbadrcpt: end */

/* rbl: start */
  if ((rblok) && !(relayclient || seenauth || dnsblskip || flagrbldns)) {
    flagrbldns = 1;
    switch(rblcheck()) {
      case -1: env_put2("RBLRESULT","ignore"); break;
      case 0: env_put2("RBLRESULT","pass"); break;
      case 1: env_put2("RBLRESULT","accept"); break;
      case 2: env_put2("RBLRESULT","delay"); break;
      case 3: env_put2("RBLRESULT","reject"); break;
    }
  }
  else env_unset("RBLRESULT");
  if (rbldecision >= 2) {
    if (!stralloc_ready(&rblmessage,0)) die_nomem();
    if (flagmustnotbounce || (rbldecision == 2)) {
      if (!stralloc_copys(&rblmessage,"451 ")) die_nomem();
    }
    else
      if (!stralloc_copys(&rblmessage,"553 ")) die_nomem();
        if (rbltext.len > 500) rbltext.len = 500;
    if (!stralloc_cat(&rblmessage,&rbltext)) die_nomem();
    int i;
    for (i = 0;i < rblmessage.len;++i)
      if ((rblmessage.s[i] < 32) || (rblmessage.s[i] > 126))
              rblmessage.s[i] = '?';
        if (!stralloc_cats(&rblmessage,"\r\n")) die_nomem();
    if (flagmustnotbounce || (rbldecision == 2)) die_rbldelay();
    else err_rblreject();
    return;
  }
/* rbl: end */

  if (!spp_rcpt_accepted()) return;

/* start empf code */
  ret = policy_check();

  if (ret == 1) {
    if (!stralloc_cats(&rcptto,"T")) die_nomem();
    if (!stralloc_cats(&rcptto,addr.s)) die_nomem();
    if (!stralloc_0(&rcptto)) die_nomem();
    rcptcount++;
    if (checkrcptcount() == 1) { err_maxrcpt(); return; }
    if (flagrcptmatch == 1) { qlogenvelope("accepted","rcptto","validrcptto","250"); }
    else if (flagrcptmatch == 2) { qlogenvelope("accepted","rcptto","chkuser","250"); }
    else if (flagrcptmatch == 3) { qlogenvelope("accepted","rcptto","chkuserrelay","250"); }
    else if (flagrcptmatch == 4) { qlogenvelope("accepted","rcptto","rcptcheck","250"); }
    else {
      if (relayclient) { qlogenvelope("accepted","relayclient","","250"); }
      else if (spp_val != 1) { qlogenvelope("accepted","spp","","250"); }
      else { qlogenvelope("accepted","rcpthosts","","250"); }
    }
    out("250 ok\r\n");
  }

  else if (ret == 0) {
    qlogenvelope("rejected","empf","","550");
    out("550 cannot message ");
    out(addr.s);
    out(" (#5.0.0 denied by policy)\r\n");
  }

  else {
    qlogenvelope("rejected","empf","","454");
    out("454 cannot message ");
    out(addr.s);
    out(" (#4.3.0 broken policy)\r\n");
 }
/* end of empf code */

/*
 * code substituted by empf code
  if (!stralloc_cats(&rcptto,"T")) die_nomem();
  if (!stralloc_cats(&rcptto,addr.s)) die_nomem();
  if (!stralloc_0(&rcptto)) die_nomem();
  rcptcount++;
  if (checkrcptcount() == 1) { err_maxrcpt(); return; }
  out("250 ok\r\n");
 */
}

ssize_t saferead(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  flush();
#ifdef TLS
  if (ssl && fd == ssl_rfd)
    r = ssl_timeoutread(timeout, ssl_rfd, ssl_wfd, ssl, buf, len);
  else
#endif
  r = timeoutread(timeout,fd,buf,len);
  if (r == -1) if (errno == error_timeout) die_alarm();
  if (r <= 0) die_read("connection closed by the client before the quit cmd");
  return r;
}

char ssinbuf[1024];
substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof ssinbuf);
#ifdef TLS
void flush_io() { ssin.p = 0; flush(); }
#endif

struct qmail qqt;
unsigned int bytestooverflow = 0;

void put(ch)
char *ch;
{
  if (bytestooverflow)
    if (!--bytestooverflow)
      qmail_fail(&qqt);
  qmail_put(&qqt,ch,1);
}

void blast(hops)
int *hops;
{
  char ch;
  int state;
  int flaginheader;
  int pos; /* number of bytes since most recent \n, if fih */
  int flagmaybex; /* 1 if this line might match RECEIVED, if fih */
  int flagmaybey; /* 1 if this line might match \r\n, if fih */
  int flagmaybez; /* 1 if this line might match DELIVERED, if fih */

  state = 1;
  *hops = 0;
  flaginheader = 1;
  pos = 0; flagmaybex = flagmaybey = flagmaybez = 1;
  for (;;) {
    substdio_get(&ssin,&ch,1);
    if (flaginheader) {
      if (pos < 9) {
        if (ch != "delivered"[pos]) if (ch != "DELIVERED"[pos]) flagmaybez = 0;
        if (flagmaybez) if (pos == 8) ++*hops;
        if (pos < 8)
          if (ch != "received"[pos]) if (ch != "RECEIVED"[pos]) flagmaybex = 0;
        if (flagmaybex) if (pos == 7) ++*hops;
        if (pos < 2) if (ch != "\r\n"[pos]) flagmaybey = 0;
        if (flagmaybey) if (pos == 1) flaginheader = 0;
	++pos;
      }
      if (ch == '\n') { pos = 0; flagmaybex = flagmaybey = flagmaybez = 1; }
    }
    /* Allow bare LF if env variable ALLOW_BARELF is defined */
    if (env_get("ALLOW_BARELF")) {
      switch(state) {
        case 0:
          if (ch == '\n') { state = 1; break; }
          if (ch == '\r') { state = 4; continue; }
          break;
        case 1: /* \r\n */
          if (ch == '.') { state = 2; continue; }
          if (ch == '\r') { state = 4; continue; }
          if (ch != '\n') state = 0;
          break;
        case 2: /* \r\n + . */
          if (ch == '\n') return;       /* this is what sendmail-8.8.4 does -djg */
          if (ch == '\r') { state = 3; continue; }
          state = 0;
          break;
        case 3: /* \r\n + .\r */
          if (ch == '\n') return;
          put(".");
          put("\r");
          if (ch == '\r') { state = 4; continue; }
          state = 0;
          break;
        case 4: /* + \r */
          if (ch == '\n') { state = 1; break; }
          if (ch != '\r') { put("\r"); state = 0; }
      }
    }
    else {
      switch(state) {
        case 0:
          if (ch == '\n') straynewline();
          if (ch == '\r') { state = 4; continue; }
          break;
        case 1: /* \r\n */
          if (ch == '\n') straynewline();
          if (ch == '.') { state = 2; continue; }
          if (ch == '\r') { state = 4; continue; }
          state = 0;
          break;
        case 2: /* \r\n + . */
          if (ch == '\n') straynewline();
          if (ch == '\r') { state = 3; continue; }
          state = 0;
          break;
        case 3: /* \r\n + .\r */
          if (ch == '\n') return;
          put(".");
          put("\r");
          if (ch == '\r') { state = 4; continue; }
          state = 0;
          break;
        case 4: /* + \r */
          if (ch == '\n') { state = 1; break; }
          if (ch != '\r') { put("\r"); state = 0; }
      }
    }
    put(&ch);
  }
}

void spfreceived()
{
  stralloc sa = {0};
  stralloc rcvd_spf = {0};

  if (!spfbehavior || relayclient) return;

  if (!stralloc_copys(&rcvd_spf, "Received-SPF: ")) die_nomem();
  if (!spfinfo(&sa,0)) die_nomem();
  if (!stralloc_cat(&rcvd_spf, &sa)) die_nomem();
  if (!stralloc_append(&rcvd_spf, "\n")) die_nomem();
  if (bytestooverflow) {
    bytestooverflow -= rcvd_spf.len;
    if (bytestooverflow <= 0) qmail_fail(&qqt);
  }
  qmail_put(&qqt,rcvd_spf.s,rcvd_spf.len);
}

void spfauthenticated()
{
  const char* e;
  stralloc sa = {0};
  stralloc auth_spf = {0};

  if (!spfbehavior || relayclient) return;

  e = env_get("QMAILAUTHENTICATED");
  if(e && *e) {
     if (!stralloc_copys(&auth_spf, e)) die_nomem();
     if (!stralloc_cats(&auth_spf, ";\n\tspf=")) die_nomem();
  } else {
     if (!stralloc_copys(&auth_spf, "spf=")) die_nomem();
  }
  if (!spfinfo(&sa,1)) die_nomem();
  if (!stralloc_cat(&auth_spf, &sa)) die_nomem();
  if (!stralloc_0(&auth_spf)) die_nomem();
  if (!env_put2("QMAILAUTHENTICATED",auth_spf.s)) die_nomem();
}


/* rbl: start */
/*
int dnsblcheck()
{
  char *ch;
  static stralloc dnsblbyte = {0};
  static stralloc dnsblrev = {0};
  static ipalloc dnsblip = {0};
  static stralloc dnsbllist = {0};

  ch = remoteip;
  if(control_readfile(&dnsbllist,"control/dnsbllist",0) != 1) return 0;

  if (!stralloc_copys(&dnsblrev,"")) return 0;
  for (;;) {
    if (!stralloc_copys(&dnsblbyte,"")) return 0;
    while (ch[0] && (ch[0] != '.')) {
      if (!stralloc_append(&dnsblbyte,ch)) return 0;
      ch++;
    }
    if (!stralloc_append(&dnsblbyte,".")) return 0;
    if (!stralloc_cat(&dnsblbyte,&dnsblrev)) return 0;
    if (!stralloc_copy(&dnsblrev,&dnsblbyte)) return 0;

    if (!ch[0]) break;
    ch++;
  }

  flagdnsbl = 1;
  ch = dnsbllist.s;
  while (ch < (dnsbllist.s + dnsbllist.len)) {
    if (!stralloc_copy(&dnsblhost,&dnsblrev)) return 0;
    if (!stralloc_cats(&dnsblhost,ch)) return 0;
    if (!stralloc_0(&dnsblhost)) return 0;

    if (!dns_ip(&dnsblip,&dnsblhost)) return 1;
    while (*ch++);
  }

  return 0;
}
*/
/* rbl:end */

char accept_buf[FMT_ULONG];
void acceptmessage(qp) unsigned long qp;
{
  datetime_sec when;
  when = now();
  out("250 ok ");
  accept_buf[fmt_ulong(accept_buf,(unsigned long) when)] = 0;
  out(accept_buf);
  out(" qp ");
  accept_buf[fmt_ulong(accept_buf,qp)] = 0;
  out(accept_buf);
  out("\r\n");
}

void smtp_data(arg) char *arg; {
  int hops;
  unsigned long qp;
  char *qqx;

  if (!seenmail) { err_wantmail(); return; }
  if (!rcptto.len) { err_wantrcpt(); return; }
  envelopepos = 4;
  if (!spp_data()) return;
  seenmail = 0;
  if (databytes) bytestooverflow = databytes + 1;
  if (qmail_open(&qqt) == -1) { err_qqt(); return; }
  qp = qmail_qp(&qqt);
  strnumqp[fmt_ulong(strnumqp,qp)] = 0; /* qp for qlog */
  out("354 go ahead\r\n");

  if (smtputf8) {
    stralloc utf8proto = {0};
    if ('E' == *protocol) protocol++;
    if (!stralloc_copys(&utf8proto, "UTF8")) die_nomem();
    if (!stralloc_cats(&utf8proto, protocol)) die_nomem();
    utf8proto.s[utf8proto.len] = '\0';
    protocol = utf8proto.s;
  }

  received(&qqt,protocol,local,remoteip,remotehost,remoteinfo,fakehelo);
  spfreceived();
  qmail_put(&qqt,sppheaders.s,sppheaders.len); /* set in qmail-spp.c */
  spp_rset();
  blast(&hops);
  hops = (hops >= MAXHOPS);
  if (hops) qmail_fail(&qqt);
  qmail_from(&qqt,mailfrom.s);
  qmail_put(&qqt,rcptto.s,rcptto.len);
 
  qqx = qmail_close(&qqt);
  if (!*qqx) { acceptmessage(qp); qlogreceived("accepted","queueaccept","","250"); return; }
  if (hops) {
    out("554 too many hops, this message is looping (#5.4.6)\r\n");
    qlogreceived("rejected","message_loop","","554");
    return;
  }
  if (databytes) if (!bytestooverflow) {
    err_size();
    logit("message too big");
    return;
  }
  if (*qqx == 'D') {
    out("554 ");
    qlogreceived("rejected","queuereject",qqx + 1,"554");
  } else {
    out("451 ");
    qlogreceived("rejected","queue_delay",qqx + 1,"451");
  }
  out(qqx + 1);
  out("\r\n");
}


int authgetl(void) {
  int i;

  if (!stralloc_copys(&authin,"")) die_nomem();
  for (;;) {
    if (!stralloc_readyplus(&authin,1)) die_nomem(); /* XXX */
    i = substdio_get(&ssin,authin.s + authin.len,1);
    if (i != 1) die_read("error in authgetl function");
    if (authin.s[authin.len] == '\n') break;
    ++authin.len;
  }

  if (authin.len > 0) if (authin.s[authin.len - 1] == '\r') --authin.len;
  authin.s[authin.len] = 0;
  if (*authin.s == '*' && *(authin.s + 1) == 0) { return err_authabrt(); }
  if (authin.len == 0) { return err_input(); }
  return authin.len;
}

int authenticate(void)
{
  int child;
  int wstat;
  int pi[2];

  if (!stralloc_0(&user)) die_nomem();
  if (!stralloc_0(&pass)) die_nomem();
  if (!stralloc_0(&chal)) die_nomem();

  if (pipe(pi) == -1) return err_pipe();
  switch(child = fork()) {
    case -1:
      return err_fork();
    case 0:
      close(pi[1]);
      if(fd_copy(3,pi[0]) == -1) return err_pipe();
      sig_pipedefault();
        execvp(*childargs, childargs);
      _exit(1);
  }
  close(pi[0]);

  substdio_fdbuf(&ssauth,write,pi[1],ssauthbuf,sizeof ssauthbuf);
  if (substdio_put(&ssauth,user.s,user.len) == -1) return err_write();
  if (substdio_put(&ssauth,pass.s,pass.len) == -1) return err_write();
  if (smtpauth == 2 || smtpauth == 3 || smtpauth == 12 || smtpauth == 13)
    if (substdio_put(&ssauth,chal.s,chal.len) == -1) return err_write();
  if (substdio_flush(&ssauth) == -1) return err_write();

  close(pi[1]);
  if (!stralloc_copys(&chal,"")) die_nomem();
  if (!stralloc_copys(&slop,"")) die_nomem();
  byte_zero(ssauthbuf,sizeof ssauthbuf);
  if (wait_pid(&wstat,child) == -1) return err_child();
  if (wait_crashed(wstat)) return err_child();
  if (wait_exitcode(wstat)) { sleep(AUTHSLEEP); return 1; } /* no */
  return 0; /* yes */
}

int auth_login(arg) char *arg;
{
  int r;

  if (*arg) {
    if ((r = b64decode(arg,str_len(arg),&user)) == 1) return err_input();
  }
  else {
    out("334 VXNlcm5hbWU6\r\n"); flush();       /* Username: */
    if (authgetl() < 0) return -1;
    if ((r = b64decode(authin.s,authin.len,&user)) == 1) return err_input();
  }
  if (r == -1) die_nomem();

  out("334 UGFzc3dvcmQ6\r\n"); flush();         /* Password: */

  if (authgetl() < 0) return -1;
  if ((r = b64decode(authin.s,authin.len,&pass)) == 1) return err_input();
  if (r == -1) die_nomem();

  if (!user.len || !pass.len) return err_input();
  return authenticate();
}

int auth_plain(arg) char *arg;
{
  int r, id = 0;

  if (*arg) {
    if ((r = b64decode(arg,str_len(arg),&resp)) == 1) return err_input();
  }
  else {
    out("334 \r\n"); flush();
    if (authgetl() < 0) return -1;
    if ((r = b64decode(authin.s,authin.len,&resp)) == 1) return err_input();
  }
  if (r == -1 || !stralloc_0(&resp)) die_nomem();
  while (resp.s[id]) id++;                       /* "authorize-id\0userid\0passwd\0" */

  if (resp.len > id + 1)
    if (!stralloc_copys(&user,resp.s + id + 1)) die_nomem();
  if (resp.len > id + user.len + 2)
    if (!stralloc_copys(&pass,resp.s + id + user.len + 2)) die_nomem();

  if (!user.len || !pass.len) return err_input();
  return authenticate();
}

int auth_cram()
{
  int i, r;
  char *s;

  s = unique;                                           /* generate challenge */
  s += fmt_uint(s,getpid());
  *s++ = '.';
  s += fmt_ulong(s,(unsigned long) now());
  *s++ = '@';
  *s++ = 0;
  if (!stralloc_copys(&chal,"<")) die_nomem();
  if (!stralloc_cats(&chal,unique)) die_nomem();
  if (!stralloc_cats(&chal,local)) die_nomem();
  if (!stralloc_cats(&chal,">")) die_nomem();
  if (b64encode(&chal,&slop) < 0) die_nomem();
  if (!stralloc_0(&slop)) die_nomem();

  out("334 ");                                          /* "334 base64_challenge \r\n" */
  out(slop.s);
  out("\r\n");
  flush();

  if (authgetl() < 0) return -1;                        /* got response */
  if ((r = b64decode(authin.s,authin.len,&resp)) == 1) return err_input();
  if (r == -1 || !stralloc_0(&resp)) die_nomem();

  i = str_rchr(resp.s,' ');
  s = resp.s + i;
  while (*s == ' ') ++s;
  resp.s[i] = 0;
  if (!stralloc_copys(&user,resp.s)) die_nomem();       /* userid */
  if (!stralloc_copys(&pass,s)) die_nomem();            /* digest */

  if (!user.len || !pass.len) return err_input();
  return authenticate();
}

struct authcmd {
  char *text;
  int (*fun)();
} authcmds[] = {
  { "login",auth_login }
, { "plain",auth_plain }
, { "cram-md5",auth_cram }
, { 0,err_noauth }
};

void smtp_auth(arg)
char *arg;
{
  int i;
  char *cmd = arg;
  if (!smtpauth || !*childargs) { out("503 auth not available (#5.3.3)\r\n"); logit("reject (auth not available)"); return; }
  if (seenauth) { err_authd(); return; }
  if (seenmail) { err_authmail(); return; }
#ifdef TLS
  if (forcetls && !ssl) { out("538 auth not available without TLS (#5.3.3)\r\n"); logit("reject (auth not available without TLS)"); return; }
#endif

  if (!stralloc_copys(&user,"")) die_nomem();
  if (!stralloc_copys(&pass,"")) die_nomem();
  if (!stralloc_copys(&resp,"")) die_nomem();
  if (!stralloc_copys(&chal,"")) die_nomem();

  i = str_chr(cmd,' ');
  arg = cmd + i;
  while (*arg == ' ') ++arg;
  cmd[i] = 0;

  for (i = 0;authcmds[i].text;++i)
    if (case_equals(authcmds[i].text,cmd)) break;

  /* invalid auth command patch */
  if (!authcmds[i].text) {
    err_authinvalid();
    return;
  }
  /* end invalid auth command patch */

  if (!env_unset("SMTPAUTHMETHOD")) die_read("SMTPAUTHMETHOD not set");
  if (!env_put2("SMTPAUTHMETHOD", authcmds[i].text)) die_nomem();

  switch (authcmds[i].fun(arg)) {
    case 0:
      if (!spp_auth(authcmds[i].text, user.s)) return;
      seenauth = 1;
#ifdef TLS
      if (ssl) {
        if (!stralloc_copys(&proto, "ESMTPSA (")
            || !stralloc_cats(&proto, SSL_get_cipher(ssl))
            || !stralloc_cats(&proto, " encrypted, authenticated)")) 
          die_nomem();
        if (!stralloc_0(&proto)) die_nomem();
        protocol = proto.s;
      } else {
        protocol = "ESMTPA";
      }
#else
      protocol = "ESMTPA";
#endif
      relayclient = "";
      remoteinfo = user.s;
      if (!env_unset("TCPREMOTEINFO")) die_read("TCPREMOTEINFO not set");
      if (!env_put2("TCPREMOTEINFO",remoteinfo)) die_nomem();
      if (!env_put2("RELAYCLIENT",relayclient)) die_nomem();

      if (!env_unset("SMTPAUTHUSER")) die_read("SMTPAUTHUSER not set");
      if (!env_put2("SMTPAUTHUSER",user.s)) die_nomem();
      if (!env_unset("SMTP_AUTH_USER")) die_read("SMTP_AUTH_USER not set");
      if (!env_put2("SMTP_AUTH_USER",user.s)) die_nomem();

      strerr_warn6(title.s,"auth: auth-success type=",authcmds[i].text," user=<",user.s,">",0);
      out("235 ok, go ahead (#2.0.0)\r\n");
      break;
    case 1:
      strerr_warn6(title.s,"auth: auth-failed type=",authcmds[i].text," user=<",user.s,">",0);
      err_authfail(user.s,authcmds[i].text);
  }
}

#ifdef TLS
int ssl_verified = 0;
const char *ssl_verify_err = 0;

void smtp_tls(char *arg)
{
  if (ssl || disabletls) err_unimpl();
  else if (*arg) {out("501 Syntax error (no parameters allowed) (#5.5.4)\r\n"); logit("reject (Syntax error, no parameters allowed)");}
  else tls_init();
}

/* don't want to fail handshake if cert isn't verifiable */
int verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx) { return 1; }

void tls_nogateway()
{
  /* there may be cases when relayclient is set */
  if (!ssl || relayclient) return;
  out("; no valid cert for gatewaying");
  if (ssl_verify_err) { out(": "); out(ssl_verify_err); }
}
void tls_out(const char *s1, const char *s2)
{
  out("454 TLS "); out(s1);
  if (s2) { out(": "); out(s2); }
  out(" (#4.3.0)\r\n"); flush();
}
void tls_err(const char *s) { tls_out(s, ssl_error()); if (smtps) die_read("tls error"); }

# define CLIENTCA "control/clientca.pem"
# define CLIENTCRL "control/clientcrl.pem"
# define SERVERCERT "control/servercert.pem"

int tls_verify()
{
  stralloc clients = {0};
  struct constmap mapclients;

  if (!ssl || relayclient || ssl_verified) return 0;
  ssl_verified = 1; /* don't do this twice */

  /* request client cert to see if it can be verified by one of our CAs
   * and the associated email address matches an entry in tlsclients */
  switch (control_readfile(&clients, "control/tlsclients", 0))
  {
  case 1:
    if (constmap_init(&mapclients, clients.s, clients.len, 0)) {
      /* if CLIENTCA contains all the standard root certificates, a
       * 0.9.6b client might fail with SSL_R_EXCESSIVE_MESSAGE_SIZE;
       * it is probably due to 0.9.6b supporting only 8k key exchange
       * data while the 0.9.6c release increases that limit to 100k */
      STACK_OF(X509_NAME) *sk = SSL_load_client_CA_file(CLIENTCA);
      if (sk) {
        SSL_set_client_CA_list(ssl, sk);
        SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_cb);
        break;
      }
      constmap_free(&mapclients);
    }
  case 0: alloc_free(clients.s); return 0;
  case -1: die_control();
  }

  if (ssl_timeoutrehandshake(timeout, ssl_rfd, ssl_wfd, ssl) <= 0) {
    const char *err = ssl_error_str();
    tls_out("rehandshake failed", err); die_read("rehandshake failed");
  }

  do { /* one iteration */
    X509 *peercert;
    X509_NAME *subj;
    stralloc email = {0};

    int n = SSL_get_verify_result(ssl);
    if (n != X509_V_OK)
      { ssl_verify_err = X509_verify_cert_error_string(n); break; }
    peercert = SSL_get_peer_certificate(ssl);
    if (!peercert) break;

    subj = X509_get_subject_name(peercert);
    n = X509_NAME_get_index_by_NID(subj, NID_pkcs9_emailAddress, -1);
    if (n >= 0) {
      const ASN1_STRING *s = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subj, n));
      if (s) { email.len = s->length; email.s = s->data; }
    }

    if (email.len <= 0)
      ssl_verify_err = "contains no email address";
    else if (!constmap(&mapclients, email.s, email.len))
      ssl_verify_err = "email address not in my list of tlsclients";
    else {
      /* add the cert email to the proto if it helped allow relaying */
      --proto.len;
      if (!stralloc_cats(&proto, "\n  (cert ") /* continuation line */
        || !stralloc_catb(&proto, email.s, email.len)
        || !stralloc_cats(&proto, ")")
        || !stralloc_0(&proto)) die_nomem();
      relayclient = "";
      /* also inform qmail-queue */
      if (!env_put("RELAYCLIENT=")) die_nomem();
      protocol = proto.s;
    }

    X509_free(peercert);
  } while (0);
  constmap_free(&mapclients); alloc_free(clients.s);

  /* we are not going to need this anymore: free the memory */
  SSL_set_client_CA_list(ssl, NULL);
  SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

  return relayclient ? 1 : 0;
}

void tls_init()
{
  SSL *myssl;
  SSL_CTX *ctx;
  const char *ciphers;
  stralloc saciphers = {0};
  X509_STORE *store;
  X509_LOOKUP *lookup;
  int session_id_context = 1; /* anything will do */

  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

  /* a new SSL context with the bare minimum of options */
  ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) { tls_err("unable to initialize ctx"); return; }

  /* renegotiation should include certificate request */
  SSL_CTX_set_options(ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

  /* Disables all renegotiation in TLSv1.2 and earlier (TLS Renegotiation vulnerability) */
#ifdef SSL_OP_NO_RENEGOTIATION
  SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
#endif

  /* never bother the application with retries if the transport is blocking */
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

  /* relevant in renegotiation */
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
  if (!SSL_CTX_set_session_id_context(ctx, (void *)&session_id_context,
                                        sizeof(session_id_context)))
    { SSL_CTX_free(ctx); tls_err("failed to set session_id_context"); return; }

  if (!SSL_CTX_use_certificate_chain_file(ctx, SERVERCERT))
    { SSL_CTX_free(ctx); tls_err("missing certificate"); return; }
  SSL_CTX_load_verify_locations(ctx, CLIENTCA, NULL);

  /* crl checking */
  store = SSL_CTX_get_cert_store(ctx);
  if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) &&
      (X509_load_crl_file(lookup, CLIENTCRL, X509_FILETYPE_PEM) == 1))
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
                                X509_V_FLAG_CRL_CHECK_ALL);

  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

  SSL_CTX_set_dh_auto(ctx, 1);

  /* a new SSL object, with the rest added to it directly to avoid copying */
  myssl = SSL_new(ctx);
  SSL_CTX_free(ctx);
  if (!myssl) { tls_err("unable to initialize ssl"); return; }

  /* this will also check whether public and private keys match */
  if (!SSL_use_PrivateKey_file(myssl, SERVERCERT, SSL_FILETYPE_PEM))
    { SSL_free(myssl); tls_err("no valid RSA private key"); return; }

  ciphers = env_get("TLSCIPHERS");
  if (!ciphers) {
    if (control_readfile(&saciphers, "control/tlsserverciphers", 0) == -1)
      { SSL_free(myssl); die_control(); }
    if (saciphers.len) { /* convert all '\0's except the last one to ':' */
      int i;
      for (i = 0; i < saciphers.len - 1; ++i)
        if (!saciphers.s[i]) saciphers.s[i] = ':';
      ciphers = saciphers.s;
    }
  }
  if (!ciphers || !*ciphers) ciphers = "DEFAULT";
  /* TLSv1.2 and lower*/
  SSL_set_cipher_list(myssl, ciphers);
  /* TLSv1.3 and above*/
  SSL_set_ciphersuites(myssl, ciphers);
  alloc_free(saciphers.s);

  SSL_set_rfd(myssl, ssl_rfd = substdio_fileno(&ssin));
  SSL_set_wfd(myssl, ssl_wfd = substdio_fileno(&ssout));

  if (!smtps) { flagtls = 1; out("220 ready for tls\r\n"); flush(); }

  if (ssl_timeoutaccept(timeout, ssl_rfd, ssl_wfd, myssl) <= 0) {
    /* neither cleartext nor any other response here is part of a standard */
    const char *err = ssl_error_str();
    tls_out("connection failed", err); ssl_free(myssl); die_read("tls connection failed");
  }
  ssl = myssl;

  /* populate the protocol string, used in Received */
  if (!stralloc_copys(&proto, "ESMTPS (")
    || !stralloc_cats(&proto, SSL_get_cipher(ssl))
    || !stralloc_cats(&proto, " encrypted)")) die_nomem();
  if (!stralloc_0(&proto)) die_nomem();
  protocol = proto.s;

  /* have to discard the pre-STARTTLS HELO/EHLO argument, if any */
  dohelo(remotehost);
}

# undef SERVERCERT
# undef CLIENTCA

#endif

struct commands smtpcommands[] = {
  { "rcpt", smtp_rcpt, 0 }
, { "mail", smtp_mail, 0 }
, { "data", smtp_data, flush }
, { "auth", smtp_auth, flush }
, { "quit", smtp_quit, flush }
, { "helo", smtp_helo, flush }
, { "ehlo", smtp_ehlo, flush }
, { "rset", smtp_rset, 0 }
, { "help", smtp_help, flush }
#ifdef TLS
, { "starttls", smtp_tls, flush_io }
#endif
, { "noop", err_noop, flush }
, { "vrfy", err_vrfy, flush }
, { 0, err_unrecog, flush }
} ;

/* qsmtpdlog: start */
void outqlog(const char *s, unsigned int n) {
  while (n > 0) {
    if (smtputf8) substdio_put(&sslog,s,1);
    else substdio_put(&sslog,((*s > 32) && (*s <= 126)) ? s : "_",1);
    --n;
    ++s;
  }
}

void outsqlog(const char *s) { outqlog(s,str_len(s)); }

void qsmtpdlog(const char *head, const char *result, const char *reason, const char *detail, const char *statuscode) {
  char *x;
  char *ch;
  int i, r;
  stralloc lst = {0};
  int isenvelope = 0;
  
  stralloc_copys(&lst,head);
  if (stralloc_starts(&lst,"qlogenvelope")) isenvelope = 1;
  substdio_puts(&sslog, head);
  substdio_puts(&sslog, ":");

  substdio_puts(&sslog, " result="); if (result) outsqlog(result);
  substdio_puts(&sslog, " code="); if (detail) outsqlog(statuscode);
  substdio_puts(&sslog, " reason="); if (reason) outsqlog(reason);
  substdio_puts(&sslog, " detail="); if (detail) outsqlog(detail);
  substdio_puts(&sslog, " helo="); if (helohost.len) outsqlog(helohost.s);
  substdio_puts(&sslog, " mailfrom=");
  if (mailfrom.len) outsqlog(mailfrom.s);
  else if ( (envelopepos==2) && (addr.len) ) outsqlog(addr.s); // qlog called in smtp_mail() doesn't have mailfrom.s defined yet

  substdio_puts(&sslog, " rcptto=");
  if ((rcptto.len) && (!isenvelope)) {
    ch = rcptto.s;
    outsqlog(ch+1);
    while (*ch++);
    while (ch < (rcptto.s + rcptto.len)) {
      outsqlog(",");
      outsqlog(ch+1);
      while (*ch++);
    }
  }
  else if ( (envelopepos==3) && (addr.len) ) outsqlog(addr.s); // qlog was probably called at the beginning of smtp_rcpt and addr.s contains the recipient

  substdio_puts(&sslog, " relay="); if (relayclient) outsqlog("yes"); else outsqlog("no");

  // only log rcpthosts value in smtp_rcpt(), that is for a single recipient, this field is meaningless for multiple recipients
  substdio_puts(&sslog, " rcpthosts="); if (isenvelope && addr.len && (envelopepos==3)) { if (addrinrcpthosts) outsqlog("yes"); else outsqlog("no"); }

  substdio_puts(&sslog, " size=");
  if (bytestooverflow) {
    char *p,text[20];
    if ((databytes - bytestooverflow) >= 0)
      sprintf(text,"%d",databytes - bytestooverflow);
    else
      sprintf(text,"");
    p = text;
    outsqlog(p);
  }

  substdio_puts(&sslog, " authuser="); if (user.len) outsqlog(user.s);
  substdio_puts(&sslog, " authtype="); x = env_get("SMTPAUTHMETHOD"); if (x) outsqlog(x);
  substdio_puts(&sslog, " encrypted="); if (smtps) outsqlog("ssl"); else if (flagtls) outsqlog("tls");

  substdio_puts(&sslog, " sslverified=");
#ifdef TLS
  if (ssl_verified) outsqlog("yes"); else outsqlog("no");
#endif
/*
  substdio_puts(&sslog, " sslproto=");
#ifdef TLS
  if (proto.len) outsqlog(proto.s);
#endif
*/
  substdio_puts(&sslog, " localip="); x = env_get("TCPLOCALIP"); if (x) outsqlog(x);
  substdio_puts(&sslog, " localport="); x = env_get("TCPLOCALPORT"); if (x) outsqlog(x);
  substdio_puts(&sslog, " remoteip="); x = env_get("TCPREMOTEIP"); if (x) outsqlog(x);
  substdio_puts(&sslog, " remoteport="); x = env_get("TCPREMOTEPORT"); if (x) outsqlog(x);
  substdio_puts(&sslog, " remotehost="); x = env_get("TCPREMOTEHOST"); if (x) outsqlog(x);
  substdio_puts(&sslog, " qp="); if (strnumqp) outsqlog(strnumqp);
  substdio_puts(&sslog, " pid="); if (strnumpid) outsqlog(strnumpid);
  substdio_putsflush(&sslog, "\n");
}
/* qsmtpdlog: end */

int main(argc,argv)
int argc;
char **argv;
{
  int n, m;
  childargs = argv + 1;
  sig_pipeignore();
  if (chdir(auto_qmail) == -1) die_control();

  pid_buf[fmt_ulong(pid_buf,getpid())]=0;
  if (!stralloc_copys(&title,"qmail-smtpd[")) die_nomem();
  if (!stralloc_cats(&title,pid_buf)) die_nomem();
  if (!stralloc_cats(&title,"]: ")) die_nomem();
  if (!stralloc_0(&title)) die_nomem();

  setup();
  if (ipme_init() != 1) die_ipme();
  if (!relayclient && greetdelay) {
    if (drop_pre_greet) {
      strerr_warn4(title.s, "GREETDELAY: ", greetdelays, "s", 0);
      n = timeoutread(greetdelay ? greetdelay : 1, 0, ssinbuf, sizeof(ssinbuf));
      if(n == -1) {
        if (errno != error_timeout) {
          strerr_die4sys(1, title.s, "GREETDELAY from ", remoteip, ": ");
        }
      } else if (n == 0) {
        strerr_die4x(1, title.s, "GREETDELAY from ", remoteip, ": client disconnected");
      } else {
        strerr_warn4(title.s, "GREETDELAY from ", remoteip, ": client sent data before greeting", 0);
        die_pre_greet();
      }
    }
    else {
      strerr_warn4(title.s, "GREETDELAY: ", greetdelays, "s", 0);
      sleep(greetdelay);
      m = 0;
      for (;;) {
        n = timeoutread(0, 0, ssinbuf, sizeof(ssinbuf));
        if (n <= 0)
          break;
        if (n > 0 && m == 0) {
          strerr_warn4(title.s, "GREETDELAY from ", remoteip, ": client sent data before greeting. ignoring", 0);
          m = 1;
        }
      }
    }
  }

  if (spp_connect()) {
    smtp_greet("220 ");
    out(" ESMTP\r\n");
  }
  if (commands(&ssin,&smtpcommands) == 0) die_read("commands error");
  die_nomem();
}
