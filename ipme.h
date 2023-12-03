#ifndef IPME_H
#define IPME_H

#include "ip.h"
#include "ipalloc.h"

extern ipalloc ipme, ipme_mask, notipme, notipme_mask;

extern int ipme_init();
extern int ipme_is();

#endif
