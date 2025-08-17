#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ndelay.h"
#include "select.h"
#include "error.h"
#include "readwrite.h"
#include "ip.h"
#include "byte.h"
#include "timeoutconn.h"
#include "control.h"
#include "constmap.h"
#include "stralloc.h"
#include "ipalloc.h"
#include "str.h"

/* if 1, bind() failing will be ignored */
#define IGNORE_BIND_ERROR 0

struct ip_address iplocal;
int bindlocal = 0 ;

int bind_by_sender(s,addr,force)
int s;
char *addr;
int force;
{
  int j;
  stralloc stext = {0} ;
  struct constmap senderip ;
  stralloc domain = {0} ;
  char *chosenip = (char *) 0 ;

  if (!force) if(bindlocal) return 0; /* already bound, no bind */

  switch ( control_readfile ( &stext , "control/senderip" , 0 ) )
  {
    case  0: return  0 ; /* no file, no bind */
    case -1: return -2 ; /* error */
    case  1:
      if ( ! constmap_init ( &senderip , stext.s , stext.len , 1 ) )
        return -3 ;
  }

  j = str_chr(addr,'@') ;
  stralloc_copys ( &domain , addr[j] ? &(addr[j+1]) : addr ) ;
  stralloc_0 ( &domain ) ;
  domain.len -- ;

  chosenip = constmap ( &senderip , domain.s , domain.len ) ;
  if ( !chosenip || !*chosenip ) return 0 ; /* no match, no bind */
  if ( ! ip_scan ( chosenip , &iplocal ) ) return -4 ; /* invalid IP */
  bindlocal = 1 ;
  return 0 ;
}

int bind_by_remoteip(s,ix,force)
int s;
struct ip_mx *ix;
int force;
{
  struct sockaddr_in salocal;
  char *ipstr, ipstring[IPFMT+1];
  int iplen;
  stralloc routes = {0};
  struct constmap bindroutes;
  char *bindroute = (char *)0;
  if (!force) if(bindlocal) return 0; /* already bound, no bind */

  /* make sure we have a control/bindroutes file */
  switch(control_readfile(&routes,"control/bindroutes",0))
  {
    case  0: return  0; /* no file, no bind to worry about */
    case -1: return -2; /* buggered up somewhere, urgh! */
    case  1: if (!constmap_init(&bindroutes,routes.s,routes.len,1)) return -3;
  }

  /* search for d.d.d.d, d.d.d., d.d., d., none */
  ipstring[0] = '.'; /* "cheating", but makes the loop check easier below! */
  ipstr = ipstring+1;
#ifdef INET6
  if (ix->af == AF_INET)
     iplen = ip_fmt(ipstr,ix->addr.ip);
  else
     iplen = ip6_fmt(ipstr,ix->addr.ip6);
#else
  iplen = ip_fmt(ipstr,ix->addr.ip); /* Well, Dan seems to trust its output! */
#endif

  bindroute = constmap(&bindroutes,ipstr,iplen);
  if (!bindroute) while (iplen--)  /* no worries - the lost char must be 0-9 */
    if (ipstring[iplen] == '.')
      if (bindroute = constmap(&bindroutes,ipstr,iplen)) break;
  if (!bindroute || !*bindroute) return 0; /* no bind required */
  if (!ip_scan(bindroute,&iplocal)) return -4; /* wasn't an ip returned */
  bindlocal = 1 ;
  return 0;
}

int timeoutconn(s,ip,outip,port,timeout)
int s;
struct ip_address *ip;
struct ip_address *outip;
unsigned int port;
int timeout;
{
  char ch;
  struct sockaddr_in sin;
  struct sockaddr_in salocal;
  char *x;
  fd_set wfds;
  struct timeval tv;

  /* bind() an outgoing ipaddr */
  byte_zero(&sin,sizeof(sin));
  byte_copy(&sin.sin_addr.s_addr,4,outip);
  sin.sin_family = AF_INET;

  if (-1 == bind(s,(struct sockaddr *) &sin,sizeof(sin))) return -1;

  byte_zero(&sin,sizeof(sin));
  byte_copy(&sin.sin_addr,4,ip);
  x = (char *) &sin.sin_port;
  x[1] = port; port >>= 8; x[0] = port;
  sin.sin_family = AF_INET;

  if (ndelay_on(s) == -1) return -1;

  /* bind s, if we've been given a local IP */
  if ( bindlocal ) {
    byte_zero ( &salocal , sizeof(salocal) ) ;
    salocal.sin_family = AF_INET ;
    byte_copy ( &salocal.sin_addr , 4 , &iplocal ) ;
    if ( bind ( s , (struct sockaddr *) &salocal , sizeof(salocal) ) )
      if ( ! IGNORE_BIND_ERROR ) return errno ;
  }

  if (connect(s,(struct sockaddr *) &sin,sizeof(sin)) == 0) {
    ndelay_off(s);
    return 0;
  }
  if ((errno != error_inprogress) && (errno != error_wouldblock)) return -1;

  FD_ZERO(&wfds);
  FD_SET(s,&wfds);
  tv.tv_sec = timeout; tv.tv_usec = 0;

  if (select(s + 1,(fd_set *) 0,&wfds,(fd_set *) 0,&tv) == -1) return -1;
  if (FD_ISSET(s,&wfds)) {
    int dummy;
    dummy = sizeof(sin);
    if (getpeername(s,(struct sockaddr *) &sin,&dummy) == -1) {
      read(s,&ch,1);
      return -1;
    }
    ndelay_off(s);
    return 0;
  }

  errno = error_timeout; /* note that connect attempt is continuing */
  return -1;
}

#ifdef INET6
int timeoutconn6(s,ip,port,timeout)
int s;
struct ip6_address *ip;
unsigned int port;
int timeout;
{
  char ch;
  struct sockaddr_in6 sin;
  char *x;
  fd_set wfds;
  struct timeval tv;

  byte_zero(&sin,sizeof(sin));
  byte_copy(&sin.sin6_addr,16,ip);
  sin.sin6_port = htons(port);;
  sin.sin6_family = AF_INET6;

  if (ndelay_on(s) == -1) return -1;

  /* XXX: could bind s */

  if (connect(s,(struct sockaddr *) &sin,sizeof(sin)) == 0) {
    ndelay_off(s);
    return 0;
  }
  if ((errno != error_inprogress) && (errno != error_wouldblock)) return -1;

  FD_ZERO(&wfds);
  FD_SET(s,&wfds);
  tv.tv_sec = timeout; tv.tv_usec = 0;

  if (select(s + 1,(fd_set *) 0,&wfds,(fd_set *) 0,&tv) == -1) return -1;
  if (FD_ISSET(s,&wfds)) {
    int dummy;
    dummy = sizeof(sin);
    if (getpeername(s,(struct sockaddr *) &sin,&dummy) == -1) {
      read(s,&ch,1);
      return -1;
    }
    ndelay_off(s);
    return 0;
  }

  errno = error_timeout; /* note that connect attempt is continuing */
  return -1;
}
#endif
