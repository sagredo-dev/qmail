/* XXX: this program knows quite a bit about tcpto's internals */

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "substdio.h"
#include "subfd.h"
#include "auto_qmail.h"
#include "fmt.h"
#include "ip.h"
#include "lock.h"
#include "error.h"
#include "exit.h"
#include "datetime.h"
#include "now.h"
#include "open.h"
#include "ipalloc.h"
#include "tcpto.h"

extern void byte_copy(char *to, unsigned int n, char *from);
void die(n) int n; { substdio_flush(subfdout); _exit(n); }

void warn(s) char *s;
{
 char *x;
 x = error_str(errno);
 substdio_puts(subfdout,s);
 substdio_puts(subfdout,": ");
 substdio_puts(subfdout,x);
 substdio_puts(subfdout,"\n");
}

void die_chdir() { warn("fatal: unable to chdir"); die(111); }
void die_open() { warn("fatal: unable to open tcpto"); die(111); }
void die_lock() { warn("fatal: unable to lock tcpto"); die(111); }
void die_read() { warn("fatal: unable to read tcpto"); die(111); }

struct tcpto_buf tcpto_buf[TCPTO_BUFSIZ];

char tmp[FMT_ULONG + IPFMT];

int main()
{
 int fdlock;
 int fd;
 int r;
 int i;
 int af;
 datetime_sec when;
 datetime_sec start;

 if (chdir(auto_qmail) == -1) die_chdir();
 if (chdir("queue/lock") == -1) die_chdir();

 fdlock = open_write("tcpto");
 if (fdlock == -1) die_open();
 fd = open_read("tcpto");
 if (fd == -1) die_open();
 if (lock_ex(fdlock) == -1) die_lock();
 r = read(fd,tcpto_buf,sizeof(tcpto_buf));
 close(fd);
 close(fdlock);

 if (r == -1) die_read();
 r /= sizeof(tcpto_buf[0]);

 start = now();

 for (i = 0;i < r;++i)
  {
   if (tcpto_buf[i].flag >= 1)
    {
     af = tcpto_buf[i].af;
     when = tcpto_buf[i].when;

#ifdef INET6
     if (af == AF_INET)
       substdio_put(subfdout,tmp,ip_fmt(tmp,&tcpto_buf[i].addr.ip));
     else
       substdio_put(subfdout,tmp,ip6_fmt(tmp,&tcpto_buf[i].addr.ip6));
#else
     substdio_put(subfdout,tmp,ip_fmt(tmp,&tcpto_buf[i].addr.ip));
#endif
     substdio_puts(subfdout," timed out ");
     substdio_put(subfdout,tmp,fmt_ulong(tmp,(unsigned long) (start - when)));
     substdio_puts(subfdout," seconds ago; # recent timeouts: ");
     substdio_put(subfdout,tmp,fmt_ulong(tmp,tcpto_buf[i].flag));
     substdio_puts(subfdout,"\n");
    }
  }

 die(0);
}
