#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <idn2.h>
#include "sig.h"
#include "stralloc.h"
#include "substdio.h"
#include "subfd.h"
#include "scan.h"
#include "case.h"
#include "error.h"
#include "auto_qmail.h"
#include "control.h"
#include "dns.h"
#include "alloc.h"
#include "quote.h"
#include "ip.h"
#include "ipalloc.h"
#include "ipme.h"
#include "gen_alloc.h"
#include "gen_allocdefs.h"
#include "str.h"
#include "now.h"
#include "exit.h"
#include "constmap.h"
#include "tcpto.h"
#include "readwrite.h"
#include "timeoutconn.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "base64.h"
#include "hmac_md5.h"
#include "eai.h"

#define HUGESMTPTEXT 5000

#define PORT_SMTP 25 /* silly rabbit, /etc/services is for users */
unsigned long port = PORT_SMTP;

GEN_ALLOC_typedef(saa,stralloc,sa,len,a)
GEN_ALLOC_readyplus(saa,stralloc,sa,len,a,i,n,x,10,saa_readyplus)
static stralloc sauninit = {0};

stralloc helohost = {0};
stralloc outgoingip = {0};
stralloc routes = {0};
struct constmap maproutes;
stralloc host = {0};
stralloc asciihost = {0};
stralloc firstpart = {0};
int utf8message = 0;
stralloc sender = {0};

stralloc authsenders = {0};
struct constmap mapauthsenders;
stralloc user = {0};
stralloc pass = {0};
stralloc auth = {0};
stralloc plain = {0};
stralloc chal  = {0};
stralloc slop  = {0};
char *authsender;

saa reciplist = {0};

struct ip_address partner;
struct ip_address outip;

#ifdef TLS
# include <sys/stat.h>
# include "tls.h"
# include "ssl_timeoutio.h"
# include <openssl/x509v3.h>
# define EHLO 1

int tls_init();
const char *ssl_err_str = 0;
#endif 

void out(s) char *s; { if (substdio_puts(subfdoutsmall,s) == -1) _exit(0); }
void zero() { if (substdio_put(subfdoutsmall,"\0",1) == -1) _exit(0); }
void zerodie() { zero(); substdio_flush(subfdoutsmall); _exit(0); }
void outsafe(sa) stralloc *sa; { int i; char ch;
for (i = 0;i < sa->len;++i) {
ch = sa->s[i]; if (ch < 33) ch = '?'; if (ch > 126) ch = '?';
if (substdio_put(subfdoutsmall,&ch,1) == -1) _exit(0); } }

void temp_noip() { out("Zinvalid ipaddr in control/outgoingip (#4.3.0)\n"); zerodie(); }
void temp_nomem() { out("ZOut of memory. (#4.3.0)\n"); zerodie(); }
void temp_oserr() { out("Z\
System resources temporarily unavailable. (#4.3.0)\n"); zerodie(); }
void temp_noconn() { out("Z\
Sorry, I wasn't able to establish an SMTP connection. (#4.4.1)\n"); zerodie(); }
void temp_read() { out("ZUnable to read message. (#4.3.0)\n"); zerodie(); }
void temp_dnscanon() { out("Z\
CNAME lookup failed temporarily. (#4.4.3)\n"); zerodie(); }
void temp_dns() { out("Z\
Sorry, I couldn't find any host by that name. (#4.1.2)\n"); zerodie(); }
void temp_chdir() { out("Z\
Unable to switch to home directory. (#4.3.0)\n"); zerodie(); }
void temp_control() { out("Z\
Unable to read control files. (#4.3.0)\n"); zerodie(); }
void perm_partialline() { out("D\
SMTP cannot transfer messages with partial final lines. (#5.6.2)\n"); zerodie(); }
void perm_usage() { out("D\
I (qmail-remote) was invoked improperly. (#5.3.5)\n"); zerodie(); }
void perm_dns() { out("D\
Sorry, I couldn't find any host named ");
outsafe(&host);
out(". (#5.1.2)\n"); zerodie(); }
void perm_nomx() { out("D\
Sorry, I couldn't find a mail exchanger or IP address. (#5.4.4)\n");
zerodie(); }
void perm_ambigmx() { out("D\
Sorry. Although I'm listed as a best-preference MX or A for that host,\n\
it isn't in my control/locals file, so I don't treat it as local. (#5.4.6)\n");
zerodie(); }

void err_authprot() {
  out("Kno supported AUTH method found, continuing without authentication.\n");
  zero();
  substdio_flush(subfdoutsmall);
}

void outhost()
{
  char x[IPFMT];
  if (substdio_put(subfdoutsmall,x,ip_fmt(x,&partner)) == -1) _exit(0);
}

int flagcritical = 0;

void dropped() {
  out("ZConnected to ");
  outhost();
  out(" but connection died. ");
  if (flagcritical) out("Possible duplicate! ");
#ifdef TLS
  if (ssl_err_str) { out((char *)ssl_err_str); out(" "); }
#endif
  out("(#4.4.2)\n");
  zerodie();
}

int timeoutconnect = 60;
int smtpfd;
int timeout = 1200;

ssize_t saferead(fd,buf,len) int fd; char *buf; int len;
{
  int r;
#ifdef TLS
  if (ssl) {
    r = ssl_timeoutread(timeout, smtpfd, smtpfd, ssl, buf, len);
    if (r < 0) ssl_err_str = ssl_error_str();
  } else
#endif
  r = timeoutread(timeout,smtpfd,buf,len);
  if (r <= 0) dropped();
  return r;
}
ssize_t safewrite(fd,buf,len) int fd; char *buf; int len;
{
  int r;
#ifdef TLS
  if (ssl) {
    r = ssl_timeoutwrite(timeout, smtpfd, smtpfd, ssl, buf, len);
    if (r < 0) ssl_err_str = ssl_error_str();
  } else
#endif 
  r = timeoutwrite(timeout,smtpfd,buf,len);
  if (r <= 0) dropped();
  return r;
}

char inbuf[1024];
substdio ssin = SUBSTDIO_FDBUF(read,0,inbuf,sizeof inbuf);
char smtptobuf[1024];
substdio smtpto = SUBSTDIO_FDBUF(safewrite,-1,smtptobuf,sizeof smtptobuf);
char smtpfrombuf[128];
substdio smtpfrom = SUBSTDIO_FDBUF(saferead,-1,smtpfrombuf,sizeof smtpfrombuf);

stralloc smtptext = {0};

void get(ch)
char *ch;
{
  substdio_get(&smtpfrom,ch,1);
  if (*ch != '\r')
    if (smtptext.len < HUGESMTPTEXT)
     if (!stralloc_append(&smtptext,ch)) temp_nomem();
}

unsigned long smtpcode()
{
  unsigned char ch;
  unsigned long code;

  if (!stralloc_copys(&smtptext,"")) temp_nomem();

  get(&ch); code = ch - '0';
  get(&ch); code = code * 10 + (ch - '0');
  get(&ch); code = code * 10 + (ch - '0');
  for (;;) {
    get(&ch);
    if (ch != '-') break;
    while (ch != '\n') get(&ch);
    get(&ch);
    get(&ch);
    get(&ch);
  }
  while (ch != '\n') get(&ch);

  return code;
}

#ifdef EHLO
saa ehlokw = {0}; /* list of EHLO keywords and parameters */
int maxehlokwlen = 0;

unsigned long ehlo()
{
  stralloc *sa;
  char *s, *e, *p;
  unsigned long code;

  if (ehlokw.len > maxehlokwlen) maxehlokwlen = ehlokw.len;
  ehlokw.len = 0;

# ifdef MXPS
  if (type == 's') return 0;
# endif

  substdio_puts(&smtpto, "EHLO ");
  substdio_put(&smtpto, helohost.s, helohost.len);
  substdio_puts(&smtpto, "\r\n");
  substdio_flush(&smtpto);

  code = smtpcode();
  if (code != 250) return code;

  s = smtptext.s;
  while (*s++ != '\n') ; /* skip the first line: contains the domain */

  e = smtptext.s + smtptext.len - 6; /* 250-?\n */
  while (s <= e)
  {
    int wasspace = 0;

    if (!saa_readyplus(&ehlokw, 1)) temp_nomem();
    sa = ehlokw.sa + ehlokw.len++;
    if (ehlokw.len > maxehlokwlen) *sa = sauninit; else sa->len = 0;

     /* smtptext is known to end in a '\n' */
     for (p = (s += 4); ; ++p)
       if (*p == '\n' || *p == ' ' || *p == '\t') {
         if (!wasspace)
           if (!stralloc_catb(sa, s, p - s) || !stralloc_0(sa)) temp_nomem();
         if (*p == '\n') break;
         wasspace = 1;
       } else if (wasspace == 1) {
         wasspace = 0;
         s = p;
       }
    s = ++p;

    /* keyword should consist of alpha-num and '-'
     * broken AUTH might use '=' instead of space */
    for (p = sa->s; *p; ++p) if (*p == '=') { *p = 0; break; }
  }

  return 250;
}
#endif

void outsmtptext()
{
  int i; 
  if (smtptext.s) if (smtptext.len) {
    out("Remote host said: ");
    for (i = 0;i < smtptext.len;++i)
      if (!smtptext.s[i]) smtptext.s[i] = '?';
    if (substdio_put(subfdoutsmall,smtptext.s,smtptext.len) == -1) _exit(0);
    smtptext.len = 0;
  }
}

void quit(prepend,append)
char *prepend;
char *append;
{
#ifdef TLS
  /* shouldn't talk to the client unless in an appropriate state */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  OSSL_HANDSHAKE_STATE state = ssl ? SSL_get_state(ssl) : TLS_ST_BEFORE;
  if (state & TLS_ST_OK || (!smtps && state & TLS_ST_BEFORE))
#else
  int state = ssl ? ssl->state : SSL_ST_BEFORE;
  if (state & SSL_ST_OK || (!smtps && state & SSL_ST_BEFORE))
#endif
#endif
  substdio_putsflush(&smtpto,"QUIT\r\n");
  /* waiting for remote side is just too ridiculous */
  out(prepend);
  outhost();
  out(append);
  out(".\n");
  outsmtptext();

#if defined(TLS) && defined(DEBUG)
  if (ssl) {
    X509 *peercert;

    out("STARTTLS proto="); out(SSL_get_version(ssl));
    out("; cipher="); out(SSL_get_cipher(ssl));

    /* we want certificate details */
    if (peercert = SSL_get_peer_certificate(ssl)) {
      char *str;

      str = X509_NAME_oneline(X509_get_subject_name(peercert), NULL, 0);
      out("; subject="); out(str); OPENSSL_free(str);

      str = X509_NAME_oneline(X509_get_issuer_name(peercert), NULL, 0);
      out("; issuer="); out(str); OPENSSL_free(str);

      X509_free(peercert);
    }
    out(";\n");
  }
#endif

  zerodie();
}

void blast()
{
  int r;
  int i;
  int o;
  char ch;
  char in[4096];
  char out[4096*2+1];
  int sol;
  int cr;

  substdio_put(&smtpto,firstpart.s,firstpart.len);

  for (sol = 1, cr = 0;;) {
    r = substdio_get(&ssin,in,sizeof in);
    if (r == 0) break;
    if (r == -1) temp_read();
    for (i = o = 0; i < r; ) {
      if (sol && in[i] == '.') {
	out[o++] = '.';
	out[o++] = in[i++];
      }
      sol = 0;
      while (i < r) {
	if (in[i] == '\n') {
	  sol = 1;
	  cr = 0;
	  ++i;
	  out[o++] = '\r';
	  out[o++] = '\n';
	  break;
	}
	if (cr) {
	  sol = 1;
	  cr = 0;
	  out[o++] = '\r';
	  out[o++] = '\n';
	  break;
	}
	if (in[i] == '\r') {
	  ++i;
	  cr = 1;
	  continue;
	}
	out[o++] = in[i++];
      }
    }
    substdio_put(&smtpto,out,o);
  }

  if (cr) substdio_put(&smtpto,"\r\n",2);
  else if (!sol) perm_partialline();
  flagcritical = 1;
  substdio_put(&smtpto,".\r\n",3);
  substdio_flush(&smtpto);
}

#ifdef TLS
char *partner_fqdn = 0;

# define TLS_QUIT quit(ssl ? "; connected to " : "; connecting to ", "")
void tls_quit(const char *s1, const char *s2)
{
  /*
     touch control/notlshosts/<fqdn> if control/notlshosts_auto contains any
     number greater than 0 in order to skip the TLS connection for remote
     servers with an obsolete TLS version.
     Thanks Alexandre Fonceca
   */
  unsigned long i = 0;
  if (control_readint(&i,"control/notlshosts_auto") && i) {
    struct passwd *info = getpwuid(getuid()); // get qmail dir
    FILE *fp;
    char acfcommand[1200];
    sprintf(acfcommand, "/bin/touch %s/control/notlshosts/'%s'", info->pw_dir, partner_fqdn);
    fp = popen(acfcommand, "r");
    if (fp == NULL) {
      out("Failed to run touch command ");
      exit(1);
    }
    pclose(fp);
  }
  /* end skip TLS patch */
  out((char *)s1); if (s2) { out(": "); out((char *)s2); } TLS_QUIT;
}
# define tls_quit_error(s) tls_quit(s, ssl_error())

int match_partner(const char *s, int len)
{
  if (!case_diffb(partner_fqdn, len, s) && !partner_fqdn[len]) return 1;
  /* we also match if the name is *.domainname */
  if (*s == '*') {
    const char *domain = partner_fqdn + str_chr(partner_fqdn, '.');
    if (!case_diffb(domain, --len, ++s) && !domain[len]) return 1;
  }
  return 0;
}

/* don't want to fail handshake if certificate can't be verified */
int verify_cb(int preverify_ok, X509_STORE_CTX *ctx) { return 1; }

int tls_init()
{
  int i;
  SSL *myssl;
  SSL_CTX *ctx;
  stralloc saciphers = {0};
  const char *ciphers, *servercert = 0;

  if (partner_fqdn) {
    struct stat st;
    stralloc tmp = {0};
    if (!stralloc_copys(&tmp, "control/tlshosts/")
      || !stralloc_catb(&tmp, partner_fqdn, str_len(partner_fqdn))
      || !stralloc_catb(&tmp, ".pem", 5)) temp_nomem();
    if (stat(tmp.s, &st) == 0) 
      servercert = tmp.s;
    else {
      if (!stralloc_copys(&tmp, "control/notlshosts/")
        || !stralloc_catb(&tmp, partner_fqdn, str_len(partner_fqdn)+1))
        temp_nomem();
      if ((stat("control/tlshosts/exhaustivelist", &st) == 0) ||
	  (stat(tmp.s, &st) == 0)) {
         alloc_free(tmp.s);
         return 0;
      }
      alloc_free(tmp.s);
    }
  }
 
  if (!smtps) {
    stralloc *sa = ehlokw.sa;
    unsigned int len = ehlokw.len;
    /* look for STARTTLS among EHLO keywords */
    for ( ; len && case_diffs(sa->s, "STARTTLS"); ++sa, --len) ;
    if (!len) {
      if (!servercert) return 0;
      out("ZNo TLS achieved while "); out((char *)servercert);
      out(" exists"); smtptext.len = 0; TLS_QUIT;
    }
  }

  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
  ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    if (!smtps && !servercert) return 0;
    smtptext.len = 0;
    tls_quit_error("ZTLS error initializing ctx");
  }

  if (servercert) {
    if (!SSL_CTX_load_verify_locations(ctx, servercert, NULL)) {
      SSL_CTX_free(ctx);
      smtptext.len = 0;
      out("ZTLS unable to load "); tls_quit_error(servercert);
    }
    /* set the callback here; SSL_set_verify didn't work before 0.9.6c */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);
  }

  /* let the other side complain if it needs a cert and we don't have one */
# define CLIENTCERT "control/clientcert.pem"
  if (SSL_CTX_use_certificate_chain_file(ctx, CLIENTCERT))
    SSL_CTX_use_PrivateKey_file(ctx, CLIENTCERT, SSL_FILETYPE_PEM);
# undef CLIENTCERT

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  SSL_CTX_set_post_handshake_auth(ctx, 1);
#endif

  myssl = SSL_new(ctx);
  SSL_CTX_free(ctx);
  if (!myssl) {
    if (!smtps && !servercert) return 0;
    smtptext.len = 0;
    tls_quit_error("ZTLS error initializing ssl");
  }

  if (!smtps) substdio_putsflush(&smtpto, "STARTTLS\r\n");

  /* while the server is preparing a responce, do something else */
  if (control_readfile(&saciphers, "control/tlsclientciphers", 0) == -1)
    { SSL_free(myssl); temp_control(); }
  if (saciphers.len) {
    for (i = 0; i < saciphers.len - 1; ++i)
      if (!saciphers.s[i]) saciphers.s[i] = ':';
    ciphers = saciphers.s;
  }
  else ciphers = "DEFAULT";
  /* TLSv1.2 and lower*/
  SSL_set_cipher_list(myssl, ciphers);
  /* TLSv1.3 and above*/
  SSL_set_ciphersuites(myssl, ciphers);
  alloc_free(saciphers.s);

  SSL_set_fd(myssl, smtpfd);

  /* read the response to STARTTLS */
  if (!smtps) {
    if (smtpcode() != 220) {
      SSL_free(myssl);
      if (!servercert) return 0;
      out("ZSTARTTLS rejected while ");
      out((char *)servercert); out(" exists"); TLS_QUIT;
    }
    smtptext.len = 0;
  }

  ssl = myssl;
  if (ssl_timeoutconn(timeout, smtpfd, smtpfd, ssl) <= 0)
    tls_quit("ZTLS connect failed", ssl_error_str());

  if (servercert) {
    X509 *peercert;
    STACK_OF(GENERAL_NAME) *gens;
    int found_gen_dns = 0;
    int matched_gen_dns = 0;

    int r = SSL_get_verify_result(ssl);
    if (r != X509_V_OK) {
      out("ZTLS unable to verify server with ");
      tls_quit(servercert, X509_verify_cert_error_string(r));
    }
    alloc_free(servercert);

    peercert = SSL_get_peer_certificate(ssl);
    if (!peercert) {
      out("ZTLS unable to verify server ");
      tls_quit(partner_fqdn, "no certificate provided");
    }

    /* RFC 2595 section 2.4: find a matching name
     * first find a match among alternative names */
    gens = X509_get_ext_d2i(peercert, NID_subject_alt_name, 0, 0);
    if (gens) {
      for (i = 0, r = sk_GENERAL_NAME_num(gens); i < r; ++i)
      {
        const GENERAL_NAME *gn = sk_GENERAL_NAME_value(gens, i);
        if (gn->type == GEN_DNS){
          found_gen_dns = 1;
          if (match_partner(gn->d.ia5->data, gn->d.ia5->length)){
            matched_gen_dns = 1;
            break;
          }
        }
      }
      sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    }

    /* no SubjectAltName of type DNS found, look up commonName */
    if (!found_gen_dns) {
      stralloc peer = {0};
      X509_NAME *subj = X509_get_subject_name(peercert);
      i = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
      if (i >= 0) {
        const ASN1_STRING *s = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subj, i));
        if (s) { peer.len = s->length; peer.s = s->data; }
      }
      if (peer.len <= 0) {
        out("ZTLS unable to verify server ");
        tls_quit(partner_fqdn, "certificate contains no valid commonName");
      }
      if (!match_partner(peer.s, peer.len)) {
        out("ZTLS unable to verify server "); out(partner_fqdn);
        out(": received certificate for "); outsafe(&peer); TLS_QUIT;
      }
    } else if (!matched_gen_dns) {
      out("ZTLS unable to verify server ");
      tls_quit(partner_fqdn, "certificate contains no matching dNSNnames");
    }

    X509_free(peercert);
  }

  return 1;
}
#endif

stralloc recip = {0};

void mailfrom()
{
  substdio_puts(&smtpto,"MAIL FROM:<");
  substdio_put(&smtpto,sender.s,sender.len);
  substdio_puts(&smtpto,">");
  if (utf8message) substdio_puts(&smtpto," SMTPUTF8");
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
}

stralloc xuser = {0};

int xtext(sa,s,len)
stralloc *sa;
char *s;
int len;
{
  int i;

  if(!stralloc_copys(sa,"")) temp_nomem();
  
  for (i = 0; i < len; i++) {
    if (s[i] == '=') {
      if (!stralloc_cats(sa,"+3D")) temp_nomem();
    } else if (s[i] == '+') {  
        if (!stralloc_cats(sa,"+2B")) temp_nomem(); 
    } else if ((int) s[i] < 33 || (int) s[i] > 126) {
        if (!stralloc_cats(sa,"+3F")) temp_nomem(); /* ok. not correct */
    } else if (!stralloc_catb(sa,s+i,1)) {
        temp_nomem();
    }
  }

  return sa->len;
}

void mailfrom_xtext()
{
  if (!xtext(&xuser,user.s,user.len)) temp_nomem();
  substdio_puts(&smtpto,"MAIL FROM:<");
  substdio_put(&smtpto,sender.s,sender.len);
  substdio_puts(&smtpto,"> AUTH=");
  substdio_put(&smtpto,xuser.s,xuser.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
}

int mailfrom_plain()
{
  substdio_puts(&smtpto,"AUTH PLAIN\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 334) { quit("ZConnected to "," but authentication was rejected (AUTH PLAIN)."); return -1; }
  if (!stralloc_cat(&plain,&user)) temp_nomem(); /* <authorization-id> */
  if (!stralloc_0(&plain)) temp_nomem();
  if (!stralloc_cat(&plain,&user)) temp_nomem(); /* <authentication-id> */
  if (!stralloc_0(&plain)) temp_nomem();
  if (!stralloc_cat(&plain,&pass)) temp_nomem(); /* password */
  if (b64encode(&plain,&auth)) quit("ZConnected to "," but unable to base64encode (plain).");
  substdio_put(&smtpto,auth.s,auth.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() == 235) { mailfrom_xtext(); return 0; }
  else if (smtpcode() == 432) { quit("ZConnected to "," but password expired."); return 1; }
  else { quit("ZConnected to "," but authentication was rejected (plain)."); return 1; }

  return 0;
}

int mailfrom_login()
{
  substdio_puts(&smtpto,"AUTH LOGIN\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 334) { quit("ZConnected to "," but authentication was rejected (AUTH LOGIN)."); return -1; }

  if (!stralloc_copys(&auth,"")) temp_nomem();
  if (b64encode(&user,&auth)) quit("ZConnected to "," but unable to base64encode user.");
  substdio_put(&smtpto,auth.s,auth.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 334) quit("ZConnected to "," but authentication was rejected (username).");

  if (!stralloc_copys(&auth,"")) temp_nomem();
  if (b64encode(&pass,&auth)) quit("ZConnected to "," but unable to base64encode pass.");
  substdio_put(&smtpto,auth.s,auth.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() == 235) { mailfrom_xtext(); return 0; }
  else if (smtpcode() == 432) { quit("ZConnected to "," but password expired."); return 1; }
  else { quit("ZConnected to "," but authentication was rejected (password)."); return 1; }
}

int mailfrom_cram()
{
  int j;
  unsigned char h;
  unsigned char digest[16];
  unsigned char digascii[33];
  static char hextab[]="0123456789abcdef";

  substdio_puts(&smtpto,"AUTH CRAM-MD5\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() != 334) { quit("ZConnected to "," but authentication was rejected (AUTH CRAM-MD5)."); return -1; }

  if (str_chr(smtptext.s+4,' ')) { 			/* Challenge */
    if(!stralloc_copys(&slop,"")) temp_nomem();
    if (!stralloc_copyb(&slop,smtptext.s+4,smtptext.len-5)) temp_nomem();
    if (b64decode(slop.s,slop.len,&chal)) quit("ZConnected to "," but unable to base64decode challenge.");
  }
   
  hmac_md5(chal.s,chal.len,pass.s,pass.len,digest);

  for (j = 0;j < 16;j++)				/* HEX => ASCII */
  {
    digascii[2*j] = hextab[digest[j] >> 4];  
    digascii[2*j+1] = hextab[digest[j] & 0xf]; 
  }
  digascii[32]=0;

  slop.len = 0;
  if (!stralloc_copys(&slop,"")) temp_nomem();
  if (!stralloc_cat(&slop,&user)) temp_nomem();		 /* user-id */
  if (!stralloc_cats(&slop," ")) temp_nomem();
  if (!stralloc_catb(&slop,digascii,32)) temp_nomem();   /* digest */ 

  if (!stralloc_copys(&auth,"")) temp_nomem();
  if (b64encode(&slop,&auth)) quit("ZConnected to "," but unable to base64encode username+digest.");
  substdio_put(&smtpto,auth.s,auth.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  if (smtpcode() == 235) { mailfrom_xtext(); return 0; }
  else if (smtpcode() == 432) { quit("ZConnected to "," but password expired."); return 1; }
  else { quit("ZConnected to "," but authentication was rejected (username+digest)."); return 1; }
}

void smtp_auth()
{
  int i, j; 

  for (i = 0; i + 8 < smtptext.len; i += str_chr(smtptext.s+i,'\n')+1)
    if (!str_diffn(smtptext.s+i+4,"AUTH",4)) {  
      if ((j = str_chr(smtptext.s+i+8,'C')) > 0)
        if (case_starts(smtptext.s+i+8+j,"CRAM"))
          if (mailfrom_cram() >= 0) return;

      if ((j = str_chr(smtptext.s+i+8,'P')) > 0)
        if (case_starts(smtptext.s+i+8+j,"PLAIN")) 
          if (mailfrom_plain() >= 0) return;

      if ((j = str_chr(smtptext.s+i+8,'L')) > 0)
        if (case_starts(smtptext.s+i+8+j,"LOGIN")) 
          if (mailfrom_login() >= 0) return;

      err_authprot();
      mailfrom();
    }
}

void smtp()
{
  unsigned long code;
  int flagbother;
  int i;
 
  #ifndef PORT_SMTP
    /* the qmtpc patch uses smtp_port and undefines PORT_SMTP */
  # define port smtp_port
  #endif

  #ifdef TLS
  # ifdef MXPS
    if (type == 'S') smtps = 1;
    else if (type != 's')
  # endif
      if (port == 465) smtps = 1;
    if (!smtps)
  #endif

  code = smtpcode();
  if (code >= 500 && code < 600) quit("DConnected to "," but greeting failed");
  if (code >= 400 && code < 500) return; /* try next MX, see RFC-2821 */
  if (code != 220) quit("ZConnected to "," but greeting failed");

#ifdef EHLO
# ifdef TLS
  if (!smtps)
# endif
  code = ehlo();

# ifdef TLS
  if (tls_init()) {
    if (smtps) {
        code = smtpcode();
        if (code >= 500 && code < 600) quit("DTLS Connected to "," but greeting failed");
        if (code >= 400 && code < 500) return; /* try next MX, see RFC-2821 */
        if (code != 220) quit("ZTLS Connected to "," but greeting failed");
    }
  /* RFC2487 says we should issue EHLO (even if we might not need
     * extensions); at the same time, it does not prohibit a server
     * to reject the EHLO and make us fallback to HELO */
    code = ehlo();
  }
# endif

  if (code == 250) {
    /* add EHLO response checks here */

    /* and if EHLO failed, use HELO */
  } else {
#endif

/*  if (smtpcode() != 250) { */
    substdio_puts(&smtpto,"HELO ");
    substdio_put(&smtpto,helohost.s,helohost.len);
    substdio_puts(&smtpto,"\r\n");
    substdio_flush(&smtpto);
    code = smtpcode();
    if (code >= 500) quit("DConnected to "," but my name was rejected");
    if (code != 250) quit("ZConnected to "," but my name was rejected");
/*  } */

#ifdef EHLO
  }
#endif

  checkutf8message();
  if (utf8message && !get_capa("SMTPUTF8")) quit("DConnected to "," but server does not support unicode in email addresses");

  if (user.len && pass.len)
    smtp_auth();
  else
    mailfrom();

  code = smtpcode();
  if (code >= 500) quit("DConnected to "," but sender was rejected");
  if (code >= 400) quit("ZConnected to "," but sender was rejected");

  flagbother = 0;
  for (i = 0;i < reciplist.len;++i) {
    substdio_puts(&smtpto,"RCPT TO:<");
    substdio_put(&smtpto,reciplist.sa[i].s,reciplist.sa[i].len);
    substdio_puts(&smtpto,">\r\n");
    substdio_flush(&smtpto);
    code = smtpcode();
    if (code >= 500) {
      /* added by Endersys R&D Team */
      out("h<From:"); outsafe(&sender); out(" To:"); outsafe(&reciplist.sa[i]); out("> ");  outhost(); out(" does not like recipient.\n");
      outsmtptext(); zero();
    }
    else if (code >= 400) {
      /* added by Endersys R&D Team */
      out("s<From:"); outsafe(&sender); out(" To:"); outsafe(&reciplist.sa[i]);  out("> ");  outhost(); out(" does not like recipient.\n");
      outsmtptext(); zero();
    }
    else {
       /*
       * James Raftery <james@now.ie>
       * Log _real_ envelope recipient, post canonicalisation.
       * and modified by Endersys R&D Team
       */

      out("r<From:"); outsafe(&sender); out(" To:"); outsafe(&reciplist.sa[i]); out("> "); zero();
      flagbother = 1;
    }
  }
  if (!flagbother) quit("DGiving up on ","");
 
  substdio_putsflush(&smtpto,"DATA\r\n");
  code = smtpcode();
  if (code >= 500) quit("D"," failed on DATA command");
  if (code >= 400) quit("Z"," failed on DATA command");
 
  blast();
  code = smtpcode();
  flagcritical = 0;
  if (code >= 500) quit("D"," failed after I sent the message");
  if (code >= 400) quit("Z"," failed after I sent the message");
  quit("K"," accepted message");
}

stralloc canonhost = {0};
stralloc canonbox = {0};

void addrmangle(saout,s,flagalias,flagcname)
stralloc *saout; /* host has to be canonical, box has to be quoted */
char *s;
int *flagalias;
int flagcname;
{
  int j;
 
  *flagalias = flagcname;
 
  j = str_rchr(s,'@');
  if (!s[j]) {
    if (!stralloc_copys(saout,s)) temp_nomem();
    return;
  }
  if (!stralloc_copys(&canonbox,s)) temp_nomem();
  canonbox.len = j;
  if (!quote(saout,&canonbox)) temp_nomem();
  if (!stralloc_cats(saout,"@")) temp_nomem();
 
  if (!stralloc_copys(&canonhost,s + j + 1)) temp_nomem();
  if (flagcname) *flagalias = 0;

  if (!stralloc_cat(saout,&canonhost)) temp_nomem();
}

void getcontrols()
{
  int r;
  if (control_init() == -1) temp_control();
  if (control_readint(&timeout,"control/timeoutremote") == -1) temp_control();
  if (control_readint(&timeoutconnect,"control/timeoutconnect") == -1)
    temp_control();
  if (control_rldef(&helohost,"control/helohost",1,(char *) 0) != 1)
    temp_control();
  switch(control_readfile(&routes,"control/smtproutes",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&maproutes,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&maproutes,routes.s,routes.len,1)) temp_nomem(); break;
  }
  
  switch(control_readfile(&authsenders,"control/authsenders",0)) {
    case -1:
       temp_control();
    case 0:
      if (!constmap_init(&mapauthsenders,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&mapauthsenders,authsenders.s,authsenders.len,1)) temp_nomem(); break;
  }
 r = control_readline(&outgoingip,"control/outgoingip");
 if (-1 == r) { if (errno == error_nomem) temp_nomem(); temp_control(); }
 if (0 == r && !stralloc_copys(&outgoingip, "0.0.0.0")) temp_nomem();
 if (str_equal(outgoingip.s, "0.0.0.0"))
   { outip.d[0]=outip.d[1]=outip.d[2]=outip.d[3]=(unsigned long) 0; }
 else if (!ip_scan(outgoingip.s, &outip)) temp_noip();
}

int main(argc,argv)
int argc;
char **argv;
{
  static ipalloc ip = {0};
  int i, j;
  unsigned long random;
  char **recips;
  unsigned long prefme;
  int flagallaliases;
  int flagalias;
  char *relayhost;
   
  sig_pipeignore();
  if (argc < 4) perm_usage();
  if (chdir(auto_qmail) == -1) temp_chdir();
  getcontrols();
 
  if (!stralloc_copys(&host,argv[1])) temp_nomem();

  authsender = 0;
  relayhost = 0;

  addrmangle(&sender,argv[2],&flagalias,0);

  for (i = 0;i <= sender.len;++i)
    if ((i == 0) || (i == sender.len) || (sender.s[i] == '.') || (sender.s[i] == '@'))
      if ((authsender = constmap(&mapauthsenders,sender.s + i,sender.len - i)))
        break;

  if (authsender && !*authsender) authsender = 0;

  if (authsender) {
    i = str_chr(authsender,'|');
    if (authsender[i]) {
      j = str_chr(authsender + i + 1,'|');
      if (authsender[j]) {
        authsender[i] = 0;
        authsender[i + j + 1] = 0;
        if (!stralloc_copys(&user,"")) temp_nomem();
        if (!stralloc_copys(&user,authsender + i + 1)) temp_nomem();
        if (!stralloc_copys(&pass,"")) temp_nomem();
        if (!stralloc_copys(&pass,authsender + i + j + 2)) temp_nomem();
      }
    }
    i = str_chr(authsender,':');
    if (authsender[i]) {
      scan_ulong(authsender + i + 1,&port);
      authsender[i] = 0;
    }

    if (!stralloc_copys(&relayhost,authsender)) temp_nomem();
    if (!stralloc_copys(&host,authsender)) temp_nomem();

  }
  else {					/* default smtproutes -- authenticated */
    for (i = 0;i <= host.len;++i)
      if ((i == 0) || (i == host.len) || (host.s[i] == '.'))
        if ((relayhost = constmap(&maproutes,host.s + i,host.len - i)))
          break;

    if (relayhost && !*relayhost) relayhost = 0;

    if (relayhost) {
      i = str_chr(relayhost,'|');
      if (relayhost[i]) {
        j = str_chr(relayhost + i + 1,'|');
        if (relayhost[j]) {
          relayhost[i] = 0;
          relayhost[i + j + 1] = 0;
          if (!stralloc_copys(&user,"")) temp_nomem();
          if (!stralloc_copys(&user,relayhost + i + 1)) temp_nomem();
          if (!stralloc_copys(&pass,"")) temp_nomem();
          if (!stralloc_copys(&pass,relayhost + i + j + 2)) temp_nomem();
        }
      }
      i = str_chr(relayhost,':');
      if (relayhost[i]) {
        scan_ulong(relayhost + i + 1,&port);
        relayhost[i] = 0;
      }
      if (!stralloc_copys(&host,relayhost)) temp_nomem();
    } else {
        char * ascii = 0;
        host.s[host.len] = '\0';
        switch (idn2_lookup_u8(host.s, (uint8_t**)&ascii, IDN2_NFC_INPUT)) {
          case IDN2_OK: break;
          case IDN2_MALLOC: temp_nomem();
          default: perm_dns();
        }
        if (!stralloc_copys(&asciihost, ascii)) temp_nomem();
    }
  }

  if (!saa_readyplus(&reciplist,0)) temp_nomem();
  if (ipme_init() != 1) temp_oserr();
 
  flagallaliases = 1;
  recips = argv + 3;
  while (*recips) {
    if (!saa_readyplus(&reciplist,1)) temp_nomem();
    reciplist.sa[reciplist.len] = sauninit;
    addrmangle(reciplist.sa + reciplist.len,*recips,&flagalias,!relayhost);
    if (!flagalias) flagallaliases = 0;
    ++reciplist.len;
    ++recips;
  }

 
  random = now() + (getpid() << 16);
  switch (relayhost ? dns_ip(&ip,&host) : dns_mxip(&ip,&asciihost,random)) {
    case DNS_MEM: temp_nomem();
    case DNS_SOFT: temp_dns();
    case DNS_HARD: perm_dns();
    case 1:
      if (ip.len <= 0) temp_dns();
  }
 
  if (ip.len <= 0) perm_nomx();
 
  prefme = 100000;
  for (i = 0;i < ip.len;++i)
    if (ipme_is(&ip.ix[i].ip))
      if (ip.ix[i].pref < prefme)
        prefme = ip.ix[i].pref;
 
  if (relayhost) prefme = 300000;
  if (flagallaliases) prefme = 500000;
 
  for (i = 0;i < ip.len;++i)
    if (ip.ix[i].pref < prefme)
      break;
 
  if (i >= ip.len)
    perm_ambigmx();
 
  for (i = 0;i < ip.len;++i) if (ip.ix[i].pref < prefme) {
    if (tcpto(&ip.ix[i].ip)) continue;
 
    smtpfd = socket(AF_INET,SOCK_STREAM,0);
    if (smtpfd == -1) temp_oserr();
 
    if (timeoutconn(smtpfd,&ip.ix[i].ip,&outip,(unsigned int) port,timeoutconnect) == 0) {
      tcpto_err(&ip.ix[i].ip,0);
      partner = ip.ix[i].ip;
#ifdef TLS
      partner_fqdn = ip.ix[i].fqdn;
#endif
      smtp(); /* only returns when the next MX is to be tried */
    }
    tcpto_err(&ip.ix[i].ip,errno == error_timeout);
    close(smtpfd);
  }
  
  temp_noconn();
}
