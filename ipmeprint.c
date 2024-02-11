#include <unistd.h>
#include "subfd.h"
#include "substdio.h"
#include "ip.h"
#include "ipme.h"
#include "exit.h"
#include "auto_qmail.h"

char temp[IPFMT];

void main()
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
   substdio_put(subfdout,temp,ip_fmt(temp,&ipme.ix[j].ip));
   substdio_puts(subfdout,"/");
   substdio_put(subfdout,temp,ip_fmt(temp,&ipme_mask.ix[j].ip));
   substdio_puts(subfdout," is me\n");
  }
 for (j = 0;j < notipme.len;++j)
  {
   substdio_put(subfdout,temp,ip_fmt(temp,&notipme.ix[j].ip));
   substdio_puts(subfdout,"/");
   substdio_put(subfdout,temp,ip_fmt(temp,&notipme_mask.ix[j].ip));
   substdio_puts(subfdout," is not me\n");
  }

 substdio_flush(subfdout);
 _exit(0);
}
