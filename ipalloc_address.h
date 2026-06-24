#ifndef IPALLOC_ADDRESS_H
#define IPALLOC_ADDRESS_H

#include "ip.h"
#include "gen_alloc.h"

GEN_ALLOC_typedef(ipalloc_address, struct ip_address, ia, len, a)

extern int ipalloc_address_readyplus(ipalloc_address *, unsigned int);
extern int ipalloc_address_append(ipalloc_address *, struct ip_address *);

#endif
