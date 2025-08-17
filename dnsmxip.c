#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "substdio.h"
#include "subfd.h"
#include "stralloc.h"
#include "fmt.h"
#include "dns.h"
#include "dnsdoe.h"
#include "ip.h"
#include "ipalloc.h"
#include "now.h"
#include "exit.h"

char temp[IPFMT + FMT_ULONG];

stralloc sa = {0};
ipalloc ia = {0};

int main(argc,argv)
int argc;
char **argv;
{
 int j;
 unsigned long r;

 if (!argv[1]) _exit(100);

 if (!stralloc_copys(&sa,argv[1]))
  { substdio_putsflush(subfderr,"out of memory\n"); _exit(111); }

 r = now() + getpid();
 dns_init(0);
 dnsdoe(dns_mxip(&ia,&sa,r));
 for (j = 0;j < ia.len;++j)
  {
   switch(ia.ix[j].af) {
   case AF_INET:
      substdio_put(subfdout,temp,ip_fmt(temp,&ia.ix[j].addr.ip));
      break;
#ifdef INET6
   case AF_INET6:
      substdio_put(subfdout,temp,ip6_fmt(temp,&ia.ix[j].addr.ip6));
      break;
#endif
   default:
      substdio_puts(subfdout,"Unknown address family = ");
      substdio_put(subfdout,temp,fmt_ulong(temp,ia.ix[j].af));
   }
   substdio_puts(subfdout," ");
   substdio_put(subfdout,temp,fmt_ulong(temp,(unsigned long) ia.ix[j].pref));
   substdio_putsflush(subfdout,"\n");
  }
 _exit(0);
}
