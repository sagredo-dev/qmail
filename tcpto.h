#ifndef TCPTO_H
#define TCPTO_H

#define        TCPTO_BUFSIZ    64

struct tcpto_buf {
       unsigned char af;
       unsigned char flag;
       unsigned long when;
       union {
               struct ip_address ip;
#ifdef INET6
               struct ip6_address ip6;
#endif
               unsigned char dummy[16];
       } addr;
};

extern int tcpto(struct ip_mx *ix);
extern void tcpto_err(struct ip_mx *ix, int flagerr);
extern void tcpto_clean(void);

#endif
