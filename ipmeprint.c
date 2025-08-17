#include <fmt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "subfd.h"
#include "substdio.h"
#include "ip.h"
#include "ipme.h"
#include "exit.h"
#include "auto_qmail.h"

char temp[IPFMT];

int main()
{
 int j,k;

 chdir(auto_qmail);
 switch(ipme_init())
  {
   case 0: substdio_putsflush(subfderr,"out of memory\n"); _exit(111);
   case -1: substdio_putsflush(subfderr,"hard error\n"); _exit(100);
  }
 for (j = 0;j < ipme.len;++j)
  {
   switch(ipme.ix[j].af) {
   case AF_INET:
      substdio_put(subfdout,temp,ip_fmt(temp,&ipme.ix[j].addr.ip));
      break;
#ifdef INET6
   case AF_INET6:
      substdio_put(subfdout,temp,ip6_fmt(temp,&ipme.ix[j].addr.ip6));
      break;
#endif
   default:
      substdio_puts(subfdout,"Unknown address family = ");
      substdio_put(subfdout,temp,fmt_ulong(temp,ipme.ix[j].af));
   }
   substdio_puts(subfdout,"/");
   substdio_put(subfdout,temp,ip_fmt(temp,&ipme_mask.ix[j].addr.ip));
   substdio_puts(subfdout," is me\n");
  }
 for (j = 0;j < notipme.len;++j)
  {
   substdio_put(subfdout,temp,ip_fmt(temp,&notipme.ix[j].addr.ip));
   substdio_puts(subfdout,"/");
   substdio_put(subfdout,temp,ip_fmt(temp,&notipme_mask.ix[j].addr.ip));
   substdio_puts(subfdout," is not me\n");
  }

 substdio_flush(subfdout);
 _exit(0);
}
