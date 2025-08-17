#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include "sig.h"
#include "stralloc.h"
#include "str.h"
#include "env.h"
#include "fmt.h"
#include "scan.h"
#include "subgetopt.h"
#include "ip.h"
#include "strsalloc.h"
#include "dns.h"
#include "byte.h"
#include "remoteinfo.h"
#include "exit.h"
#include "case.h"
#include "hassalen.h"

void die() { _exit(111); }

union sockunion {
       struct sockaddr     sa;
       struct sockaddr_in  sa4;
#ifdef INET6
       struct sockaddr_in6 sa6;
#endif
};

char temp[HOSTNAMELEN];

union sockunion salocal;
unsigned long localport;
stralloc localname = {0};

union sockunion saremote;
unsigned long remoteport;
stralloc remotename = {0};

#if defined(IN6_IS_ADDR_V4MAPPED) && defined(INET6)
void mappedtov4(union sockunion *sa)
{
       struct sockaddr_in sin;
       struct sockaddr_in6 *sin6 = &sa->sa6;

       byte_zero(&sin, sizeof(sin));
       if (sin6->sin6_family == AF_INET6 &&
         IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr) ) {
      byte_copy(&sin.sin_addr, sizeof(sin.sin_addr), sin6->sin6_addr.s6_addr+12);
               sin.sin_port = sin6->sin6_port;
               sin.sin_family = AF_INET;
#ifdef HASSALEN
               sin.sin_len = sizeof(sin);
#endif
      byte_copy(&sa->sa4, sizeof(sin), &sin);
       }

}
#else
#define mappedtov4(A)
#endif

int main(argc,argv)
int argc;
char *argv[];
{
 strsalloc ssa = {0};
 int dummy;
 char *proto;
 int opt;
 int flagremoteinfo;
 unsigned long timeout;
 struct sockaddr_in *v4;

 sig_pipeignore();

 flagremoteinfo = 1;
 timeout = 30;
 while ((opt = sgopt(argc,argv,"rRt:")) != sgoptdone)
   switch(opt)
    {
     case 'r': flagremoteinfo = 1; break;
     case 'R': flagremoteinfo = 0; break;
     case 't': scan_ulong(sgoptarg,&timeout); break;
    }

 argv += sgoptind;
 argc -= sgoptind;

 if (argc < 1) die();
 if (!env_init()) die();

 proto = env_get("PROTO");
 if (!proto || str_diff(proto,"TCP"))
  {
   if (!env_put("PROTO=TCP")) die();

   dummy = sizeof(salocal);
   if (getsockname(0,(struct sockaddr *) &salocal,&dummy) == -1) die();
   mappedtov4(&salocal);

   switch(salocal.sa.sa_family) {
   case AF_INET:
   localport = ntohs(salocal.sa4.sin_port);
   temp[fmt_ulong(temp,localport)] = 0;
   if (!env_put2("TCPLOCALPORT",temp)) die();

   temp[ip_fmt(temp, &salocal.sa4.sin_addr)] = 0;
   if (!env_put2("TCPLOCALIP",temp)) die();

//   switch(dns_ptr(&ssa,&iplocal)) {
//-   switch(dns_ptr(&localname,&iplocal)) {
//+   switch(dns_ptr(&localname,&salocal.sa4.sin_addr)) {
    switch(dns_ptr(&ssa,&salocal.sa4.sin_addr)) {
     case DNS_MEM: die();
     case DNS_SOFT:
       if (!stralloc_copys(&localname,"softdnserror")) die();
     case 0:
       if (!stralloc_copy(&localname,&ssa.sa[0])) die();
       if (!stralloc_0(&localname)) die();
       case_lowers(localname.s);
       if (!env_put2("TCPLOCALHOST",localname.s)) die();
       break;
     default:
       if (!env_unset("TCPLOCALHOST")) die();
    }
   break;
#ifdef INET6
   case AF_INET6:
      localport = ntohs(salocal.sa6.sin6_port);
      temp[fmt_ulong(temp,localport)] = 0;
      if (!env_put2("TCPLOCALPORT",temp)) die();
      temp[ip6_fmt(temp, &salocal.sa6.sin6_addr)] = 0;
      if (!env_put2("TCPLOCALIP",temp)) die();
      switch(dns_ptr6(&localname,&salocal.sa6.sin6_addr)) {
        case DNS_MEM: die();
        case DNS_SOFT:
             if (!stralloc_copys(&localname,"softdnserror")) die();
        case 0:
             if (!stralloc_0(&localname)) die();
          case_lowers(localname.s);
          if (!env_put2("TCPLOCALHOST",localname.s)) die();
          break;
        default:
             if (!env_unset("TCPLOCALHOST")) die();
      }
      break;
#endif
   default:
      die();
   }

   dummy = sizeof(saremote);
   if (getpeername(0,(struct sockaddr *) &saremote,&dummy) == -1) die();
   mappedtov4(&saremote);

   switch(saremote.sa.sa_family) {
   case AF_INET:
   remoteport = ntohs(saremote.sa4.sin_port);
   temp[fmt_ulong(temp,remoteport)] = 0;
   if (!env_put2("TCPREMOTEPORT",temp)) die();
   temp[ip_fmt(temp, &saremote.sa4.sin_addr)] = 0;
   if (!env_put2("TCPREMOTEIP",temp)) die();

//   switch(dns_ptr(&ssa,&ipremote)) {
//-   switch(dns_ptr(&remotename,&ipremote)) {
//+   switch(dns_ptr(&remotename,&saremote.sa4.sin_addr)) {
   switch(dns_ptr(&remotename,&saremote.sa4.sin_addr)) {
   case DNS_MEM: die();
   case DNS_SOFT:
     if (!stralloc_copys(&remotename,"softdnserror")) die();
   case 0:
     if (!stralloc_0(&remotename)) die();
     case_lowers(remotename.s);
     if (!env_put2("TCPREMOTEHOST",remotename.s)) die();
     break;
   default:
     if (!env_unset("TCPREMOTEHOST")) die();
   }
   break;
#ifdef INET6
   case AF_INET6:
   remoteport = ntohs(saremote.sa6.sin6_port);
         temp[fmt_ulong(temp,remoteport)] = 0;
   if (!env_put2("TCPREMOTEPORT",temp)) die();
   temp[ip6_fmt(temp, &saremote.sa6.sin6_addr)] = 0;
   if (!env_put2("TCPREMOTEIP",temp)) die();
   switch(dns_ptr6(&remotename,&saremote.sa6.sin6_addr)) {
     case DNS_MEM: die();
     case DNS_SOFT:
       if (!stralloc_copys(&remotename,"softdnserror")) die();
     case 0:
       if (!stralloc_copy(&remotename,&ssa.sa[0])) die();
       if (!stralloc_0(&remotename)) die();
       case_lowers(remotename.s);
       if (!env_put2("TCPREMOTEHOST",remotename.s)) die();
       break;
     default:
       if (!env_unset("TCPREMOTEHOST")) die();
    }
       break;
#endif
   default:
       die();
   }

   if (!env_unset("TCPREMOTEINFO")) die();

   if (flagremoteinfo)
    {
     char *rinfo;
     rinfo = remoteinfo_get(&saremote, &salocal,(int) timeout);
     if (rinfo)
       if (!env_put2("TCPREMOTEINFO",rinfo)) die();
    }
  }

 sig_pipedefault();
 execvp(*argv,argv);
 die();
}
