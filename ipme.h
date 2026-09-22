#ifndef IPME_H
#define IPME_H

#include "ip.h"
#include "ipalloc.h"
#include "ipalloc_address.h"

extern ipalloc ipme, notipme;
extern ipalloc_address ipme_mask, notipme_mask;

extern int ipme_init();
extern int ipme_is(struct ip_address *);

#endif
