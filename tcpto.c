#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <unistd.h>
#include "ipalloc.h"
#include <string.h>
#include "tcpto.h"
#include "open.h"
#include "lock.h"
#include "seek.h"
#include "now.h"
#include "ip.h"
#include "ipalloc.h"
#include "byte.h"
#include "datetime.h"

struct tcpto_buf tcpto_buf[TCPTO_BUFSIZ];

static int flagwasthere;
static int fdlock;

static int getbuf()
{
 int r;
 int fd;

 fdlock = open_write("queue/lock/tcpto");
 if (fdlock == -1) return 0;
 fd = open_read("queue/lock/tcpto");
 if (fd == -1) { close(fdlock); return 0; }
 if (lock_ex(fdlock) == -1) { close(fdlock); close(fd); return 0; }
 r = read(fd,&tcpto_buf,sizeof(tcpto_buf));
 close(fd);
 if (r < 0) { close(fdlock); return 0; }
 r /= sizeof(tcpto_buf[0]);
 if (!r) close(fdlock);
 return r;
}

int tcpto(ix)
struct ip_mx *ix;
{
 int n;
 int i;
 datetime_sec when;

 flagwasthere = 0;

 n = getbuf();
 if (!n) return 0;
 close(fdlock);

 for (i = 0;i < n;++i)
  {
#ifdef INET6
   if (ix->af == tcpto_buf[i].af && (ix->af == AF_INET ? byte_equal(&ix->addr.ip, sizeof(ix->addr.ip), &tcpto_buf[i].addr.ip) : byte_equal(&ix->addr.ip6, sizeof(ix->addr.ip6), &tcpto_buf[i].addr.ip6)))
#else
   if (byte_equal(&ix->addr.ip, sizeof(ix->addr.ip), &tcpto_buf[i].addr.ip))
#endif
    {
     flagwasthere = 1;
     if (tcpto_buf[i].flag >= 2)
      {
       when = tcpto_buf[i].when;
       if (now() - when < ((60 + (getpid() & 31)) << 6))
	 return 1;
      }
     return 0;
    }
  }
 return 0;
}

void tcpto_err(ix,flagerr)
struct ip_mx *ix; int flagerr;
{
 int n;
 int i;
 datetime_sec when;
 datetime_sec firstwhen=0;
 int firstpos=-1;
 datetime_sec lastwhen;

 if (!flagerr)
   if (!flagwasthere)
     return; /* could have been added, but not worth the effort to check */

 n = getbuf();
 if (!n) return;

 for (i = 0;i < n;++i)
  {
#ifdef INET6
   if (ix->af == tcpto_buf[i].af && (ix->af == AF_INET ? byte_equal(&ix->addr.ip, sizeof(ix->addr.ip), &tcpto_buf[i].addr.ip) : byte_equal(&ix->addr.ip6, sizeof(ix->addr.ip6), &tcpto_buf[i].addr.ip6)))
#else
   if (byte_equal(&ix->addr.ip, sizeof(ix->addr.ip), &tcpto_buf[i].addr.ip))
#endif
    {
     if (!flagerr)
       tcpto_buf[i].flag = 0;
     else
      {
       lastwhen = tcpto_buf[i].when;
       when = now();

       if (tcpto_buf[i].flag && (when < 120 + lastwhen)) { close(fdlock); return; }

       if (++tcpto_buf[i].flag > 10) tcpto_buf[i].flag = 10;
       tcpto_buf[i].when = when;
      }
     if (seek_set(fdlock,sizeof(tcpto_buf[0])*i) == 0)
       if (write(fdlock,&tcpto_buf[i],sizeof(tcpto_buf[0])) < sizeof(tcpto_buf[0]))
         ; /*XXX*/
     close(fdlock);
     return;
    }
  }

 if (!flagerr) { close(fdlock); return; }

 for (i = 0;i < n;++i)
   if (tcpto_buf[i].flag == 0) break;

 if (i >= n)
  {
   firstpos = -1;
   for (i = 0;i < n;++i)
    {
     when = tcpto_buf[i].when;
     when += (tcpto_buf[i].flag << 10);
     if ((firstpos < 0) || (when < firstwhen))
      {
       firstpos = i;
       firstwhen = when;
      }
    }
   i = firstpos;
  }

 if (i >= 0)
  {
   tcpto_buf[i].af = ix->af;
#ifdef INET6
   if (ix->af == AF_INET6)
     byte_copy(&tcpto_buf[i].addr.ip6, 16, &ix->addr.ip6);
   else
#endif
     byte_copy(&tcpto_buf[i].addr.ip, 4, &ix->addr.ip);
   tcpto_buf[i].when = now();
   tcpto_buf[i].flag = 1;
   if (seek_set(fdlock,sizeof(tcpto_buf[0])*i) == 0)
     if (write(fdlock,&tcpto_buf[i],sizeof(tcpto_buf[0])) < sizeof(tcpto_buf[0]))
       ; /*XXX*/
  }

 close(fdlock);
}
