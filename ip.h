#ifndef IP_H
#define IP_H

struct ip_address { unsigned char d[4]; } ;
typedef struct  ip_address ip_addr;

extern unsigned int ip_fmt(char *, struct ip_address *);
#define IPFMT 19
extern unsigned int ip_scan(char *, struct ip_address *);
extern unsigned int ip_scanbracket(char *, struct ip_address *);

#endif
