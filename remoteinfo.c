#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include "byte.h"
#include "substdio.h"
#include "ip.h"
#include "fmt.h"
#include "timeoutconn.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "remoteinfo.h"

static char line[999];
static int t;

static int mywrite(fd,buf,len) int fd; char *buf; int len;
{
  return timeoutwrite(t,fd,buf,len);
}
static int myread(fd,buf,len) int fd; char *buf; int len;
{
  return timeoutread(t,fd,buf,len);
}

union sockunion {
       struct sockaddr     sa;
       struct sockaddr_in  sa4;
#ifdef INET6
       struct sockaddr_in6 sa6;
#endif
};

char *remoteinfo_get(saremote, salocal, timeout)
union sockunion *saremote, *salocal;
int timeout;
{
  char *x;
  int s;
  union sockunion sa;
  substdio ss;
  char buf[32];
  unsigned int len, rp, lp;
  int numcolons;
  char ch;

  t = timeout;

  s = socket(saremote->sa.sa_family,SOCK_STREAM,0);
  if (s == -1) return 0;

  switch(saremote->sa.sa_family) {
  case AF_INET:
    rp = ntohs(saremote->sa4.sin_port);
    lp = ntohs(salocal->sa4.sin_port);
    byte_zero(&sa,sizeof(sa));
    sa.sa4.sin_family = AF_INET;
    byte_copy(&sa.sa4.sin_addr, 4, &salocal->sa4.sin_addr);
    sa.sa4.sin_port = 0;
    if (bind(s,(struct sockaddr *) &sa.sa,sizeof(sa.sa4)) == -1) { close(s); return 0; }
    if (timeoutconn(s,&saremote->sa4.sin_addr,113,timeout) == -1) { close(s); return 0; }
    break;
#ifdef INET6
  case AF_INET6:
    rp = ntohs(saremote->sa6.sin6_port);
    lp = ntohs(salocal->sa6.sin6_port);
    s = socket(PF_INET6, SOCK_STREAM, 0);
  if (s == -1) return 0;
    byte_zero(&sa,sizeof(sa));
    sa.sa6.sin6_family = AF_INET;
    byte_copy(&sa.sa6.sin6_addr, 16, &salocal->sa6.sin6_addr);
    sa.sa6.sin6_port = 0;
    sa.sa6.sin6_flowinfo = 0;
    if (bind(s,(struct sockaddr *) &sa.sa,sizeof(sa.sa6)) == -1) { close(s); return 0; }
    if (timeoutconn6(s,&saremote->sa6.sin6_addr,113,timeout) == -1) { close(s); return 0; }
    break;
#endif
  default:
    return 0;
  }

/*  byte_zero(&sin,sizeof(sin));
  sin.sin_family = AF_INET;
  byte_copy(&sin.sin_addr,4,ipl);
  sin.sin_port = 0;
  if (bind(s,(struct sockaddr *) &sin,sizeof(sin)) == -1) { close(s); return 0; } */
//  if (timeoutconn(s,ipr,ipl,113,timeout) == -1) { close(s); return 0; }
  fcntl(s,F_SETFL,fcntl(s,F_GETFL,0) & ~O_NDELAY);

  len = 0;
  len += fmt_ulong(line + len,rp);
  len += fmt_str(line + len," , ");
  len += fmt_ulong(line + len,lp);
  len += fmt_str(line + len,"\r\n");

  substdio_fdbuf(&ss,mywrite,s,buf,sizeof buf);
  if (substdio_putflush(&ss,line,len) == -1) { close(s); return 0; }

  substdio_fdbuf(&ss,myread,s,buf,sizeof buf);
  x = line;
  numcolons = 0;
  for (;;) {
    if (substdio_get(&ss,&ch,1) != 1) { close(s); return 0; }
    if ((ch == ' ') || (ch == '\t') || (ch == '\r')) continue;
    if (ch == '\n') break;
    if (numcolons < 3) { if (ch == ':') ++numcolons; }
    else { *x++ = ch; if (x == line + sizeof(line) - 1) break; }
  }
  *x = 0;
  close(s);
  return line;
}
