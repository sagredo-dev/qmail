#include <stdlib.h>
#include <unistd.h>
#include "subfd.h"
#include "substdio.h"
#include "ip.h"
#include "ipme.h"
#include "exit.h"
#include "auto_qmail.h"
#include "env.h"

void main(int argc, char *argv[])
{
  struct ip_address ip;

  if (!env_get("IPMETEST_HERE"))
    chdir(auto_qmail);

  if (argc < 2)
  {
    substdio_puts(subfdout,"invalid usage\n");
    substdio_flush(subfdout);
    exit(1);
  }
  if (!ip_scan(argv[1],&ip))
  {
    substdio_puts(subfdout,"invalid IP address\n");
    substdio_flush(subfdout);
    exit(1);
  }
  if (ipme_is(&ip))
  {
    substdio_puts(subfdout,"me\n");
  }
  else
  {
    substdio_puts(subfdout,"not me\n");
  }
  substdio_flush(subfdout);
  exit(0);
}
