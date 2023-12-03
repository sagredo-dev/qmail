#include "substdio.h"
#include "subfd.h"
#include "stralloc.h"
#include "str.h"
#include "scan.h"
#include "dns.h"
#include "dnsdoe.h"
#include "ip.h"
#include "strsalloc.h"
#include "exit.h"

strsalloc ssa = {0};
struct ip_address ip;

void main(argc,argv)
int argc;
char **argv;
{
 int j;

 if (!argv[1]) _exit(100);

 ip_scan(argv[1],&ip);

 dns_init(0);
 dnsdoe(dns_ptr(&ssa,&ip));
 for(j = 0;j < ssa.len;++j)
  {
   substdio_putflush(subfdout,ssa.sa[j].s,ssa.sa[j].len);
   substdio_putsflush(subfdout,"\n");
  }
 _exit(0);
}
