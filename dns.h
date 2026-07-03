#include "strsalloc.h"
#include "ipalloc.h"

#ifndef DNS_H
#define DNS_H

#define DNS_SOFT -1
#define DNS_HARD -2
#define DNS_MEM -3

void dns_init(int);
int dns_cname(stralloc *);
int dns_mxip(ipalloc *, stralloc *, unsigned long);
int dns_ip(ipalloc *, stralloc *);
int dns_ptr(strsalloc *, struct ip_address *);
int dns_txt(strsalloc *, stralloc *);

#endif
