#ifndef CDBMSS_H
#define CDBMSS_H

#include "cdbmake.h"
#include "substdio.h"

struct cdbmss {
  char ssbuf[1024];
  struct cdbmake cdbm;
  substdio ss;
  char packbuf[8];
  uint32 pos;
  int fd;
} ;

extern int cdbmss_start(struct cdbmss *c, int fd);
extern int cdbmss_add(struct cdbmss *c, char *key, unsigned int keylen, char *data, unsigned int datalen);
extern int cdbmss_finish(struct cdbmss *c);

#endif
