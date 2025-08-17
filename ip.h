#ifndef IP_H
#define IP_H

struct ip_address { unsigned char d[4]; } ;
typedef struct  ip_address ip_addr;
#ifdef INET6
struct ip6_address { unsigned char d[16]; } ;
#endif

extern unsigned int ip_fmt();
#ifdef INET6
extern unsigned int ip6_fmt();
#define IPFMT 72
#else
#define IPFMT 19
#endif
extern unsigned int ip_scan();
extern unsigned int ip_scanbracket();
#ifdef INET6
extern unsigned int ip6_scan();
#endif

#define HOSTNAMELEN    1025

#endif
