#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#ifndef SIOCGIFCONF /* whatever works */
#include <sys/sockio.h>
#endif
#include "hassalen.h"
#include "byte.h"
#include "ip.h"
#include "ipalloc.h"
#include "stralloc.h"
#include "ipme.h"
#include "substdio.h"
#include "readwrite.h"
#include "alloc.h"
#include "open.h"
#include "getln.h"
#include "str.h"

static int ipmeok = 0;
ipalloc ipme = {0};
ipalloc ipme_mask = {0};
ipalloc notipme = {0};
ipalloc notipme_mask = {0};

int ipme_match(struct ipalloc *ipa, struct ipalloc *ipa_mask, struct ip_address *ip);
int ipme_readipfile(ipalloc *ipa, ipalloc *ipa_mask, char *fn);

/* code dropped by ipme_is() for ipv6 */
/*
int ipme_is(ip)
struct ip_address *ip;
{
  if (ipme_init() != 1) return -1;
  return ipme_match(&ipme,&ipme_mask,ip) > ipme_match(&notipme,&notipme_mask,ip);
}

int ipme_match(ipa, ipa_mask, ip)
struct ipalloc *ipa, *ipa_mask;
struct ip_address *ip;
{
  int i,j;
  struct ip_address masked;
  int masklen, longest_masklen=-1;

  for(i=0;i < ipa->len;++i)
  {
    masklen = 0;
    for(j=0;j<4;++j)
    {
      switch(ipa_mask->ix[i].ip.d[j])
      {
        case 255:  masklen += 8; break;
        case 254:  masklen += 7; break;
        case 252:  masklen += 6; break;
        case 248:  masklen += 5; break;
        case 240:  masklen += 4; break;
        case 224:  masklen += 3; break;
        case 192:  masklen += 2; break;
        case 128:  masklen += 1; break;
        default:   masklen += 0; break;
      }
      if (ipa->ix[i].ip.d[j] != (ip->d[j] & ipa_mask->ix[i].ip.d[j]))
        break;
    }
    if ( (j == 4) && (masklen > longest_masklen) )
    {
      longest_masklen = masklen;
    }
  }
  return longest_masklen;
}
*/
/* end code dropped */

int ipme_is(ip)
struct ip_address *ip;
{
  int i;
  if (ipme_init() != 1) return -1;
  for (i = 0;i < ipme.len;++i)
    if (ipme.ix[i].af == AF_INET && byte_equal(&ipme.ix[i].addr.ip,4,ip))
      return 1;
  return 0;
}

#ifdef INET6
int ipme_is6(ip)
struct ip6_address *ip;
{
  int i;
  if (ipme_init() != 1) return -1;
  for (i = 0;i < ipme.len;++i)
    if (ipme.ix[i].af == AF_INET6 && byte_equal(&ipme.ix[i].addr.ip6,16,ip))
      return 1;
  return 0;
}
#endif

static stralloc buf = {0};

#define ipme_init_retclean(ret) { \
  if (moreipme.ix) alloc_free(moreipme.ix); \
  if (moreipme_mask.ix) alloc_free(moreipme_mask.ix); \
  if (buf.s) alloc_free(buf.s); \
  return ret; }

int ipme_init()
{
  struct ifconf ifc;
  char *x;
  struct ifreq *ifr;
  struct sockaddr_in *sin;
#ifdef INET6
  struct sockaddr_in6 *sin6;
#endif
  int len;
  int s;
  struct ip_mx ix, ix_mask;
  ipalloc moreipme = {0};
  ipalloc moreipme_mask = {0};
  int i;

  if (ipmeok) return 1;
  if (!ipalloc_readyplus(&ipme,0)) ipme_init_retclean(0);
  if (!ipalloc_readyplus(&ipme_mask,0)) ipme_init_retclean(0);
  if (!ipalloc_readyplus(&notipme,0)) ipme_init_retclean(0);
  if (!ipalloc_readyplus(&notipme_mask,0)) ipme_init_retclean(0);
  if (!ipalloc_readyplus(&moreipme,0)) ipme_init_retclean(0);
  if (!ipalloc_readyplus(&moreipme_mask,0)) ipme_init_retclean(0);

  ipme.len = 0;
  ix.pref = ix_mask.pref = 0;

  if (!ipme_readipfile(&notipme, &notipme_mask, "control/notipme")) ipme_init_retclean(0);

  /* 127.0.0.0/255.0.0.0 is the localhost network.  Linux will treat
     every address in this range as a local interface, even if it
     isn't explicitly configured.
  */
  byte_copy(&ix.addr.ip,4,"\x7f\0\0\0");
  byte_copy(&ix_mask.addr.ip,4,"\xff\0\0\0");
  if (!ipalloc_append(&ipme,&ix)) ipme_init_retclean(0);
  if (!ipalloc_append(&ipme_mask,&ix_mask)) ipme_init_retclean(0);

  /* 0.0.0.0 is a special address which always refers to
   * "this host, this network", according to RFC 1122, Sec. 3.2.1.3a.  */
  byte_copy(&ix.addr.ip,4,"\0\0\0\0");
  byte_copy(&ix_mask.addr.ip,4,"\xff\xff\xff\xff");
  if (!ipalloc_append(&ipme,&ix)) ipme_init_retclean(0);
  if (!ipalloc_append(&ipme_mask,&ix_mask)) ipme_init_retclean(0);

  if ((s = socket(AF_INET,SOCK_STREAM,0)) == -1) ipme_init_retclean(-1);

  len = 8192; /* any value big enough to get all the interfaces in one read is good */
  for (;;) {
    if (!stralloc_ready(&buf,len)) { close(s); ipme_init_retclean(0); }
    buf.len = 0;
    ifc.ifc_buf = buf.s;
    ifc.ifc_len = len;
    if (ioctl(s,SIOCGIFCONF,&ifc) >= 0) /* > is for System V */
      if (ifc.ifc_len + sizeof(*ifr) + 64 < len) { /* what a stupid interface */
        buf.len = ifc.ifc_len;
        break;
      }
    if (len > 200000) { close(s);  ipme_init_retclean(-1); }
    len *= 2;
  }
  x = buf.s;
  while (x < buf.s + buf.len) {
    ifr = (struct ifreq *) x;
#ifdef HASSALEN
    len = sizeof(ifr->ifr_name) + ifr->ifr_addr.sa_len;
    if (len < sizeof(*ifr))
      len = sizeof(*ifr);
    if (ifr->ifr_addr.sa_family == AF_INET) {
      sin = (struct sockaddr_in *) &ifr->ifr_addr;
      byte_copy(&ix.addr.ip,4,&sin->sin_addr);
      ix.af = AF_INET;
      if (ioctl(s,SIOCGIFFLAGS,x) == 0)
        if (ifr->ifr_flags & IFF_UP)
          if (!ipalloc_append(&ipme,&ix)) { close(s); return 0; }
    }
#ifdef INET6
       else if (ifr->ifr_addr.sa_family == AF_INET6) {
      sin6 = (struct sockaddr_in6 *) &ifr->ifr_addr;
      byte_copy(&ix.addr.ip6,16,&sin6->sin6_addr);
      ix.af = AF_INET6;
      if (ioctl(s,SIOCGIFFLAGS,x) == 0)
        if (ifr->ifr_flags & IFF_UP)
        {
          if (!ipalloc_append(&ipme,&ix)) { close(s);  ipme_init_retclean(0); }
          if (!ipalloc_append(&ipme_mask,&ix_mask)) { close(s);  ipme_init_retclean(0); }
        }
    }
#endif
#else
    len = sizeof(*ifr);
    if (ioctl(s,SIOCGIFFLAGS,x) == 0)
      if (ifr->ifr_flags & IFF_UP)
        if (ioctl(s,SIOCGIFADDR,x) == 0)
	  if (ifr->ifr_addr.sa_family == AF_INET) {
	    sin = (struct sockaddr_in *) &ifr->ifr_addr;
            ix.af = AF_INET;
            byte_copy(&ix.addr.ip,4,&sin->sin_addr);
            if (!ipalloc_append(&ipme,&ix)) { close(s); return 0; }
          }
#ifdef INET6
      else if (ifr->ifr_addr.sa_family == AF_INET6) {
           sin6 = (struct sockaddr_in6 *) &ifr->ifr_addr;
           ix.af = AF_INET6;
           byte_copy(&ix.addr.ip6,16,&sin6->sin6_addr);
            if (!ipalloc_append(&ipme,&ix)) { close(s);  ipme_init_retclean(0); }
            if (!ipalloc_append(&ipme_mask,&ix_mask)) { close(s);  ipme_init_retclean(0); }
      }
#endif
#endif
    x += len;
  }
  close(s);

  if (!ipme_readipfile(&moreipme, &moreipme_mask, "control/moreipme"))  ipme_init_retclean(0);
  for(i = 0;i < moreipme.len;++i)
  {
    if (!ipalloc_append(&ipme,&moreipme.ix[i])) ipme_init_retclean(0);
    if (!ipalloc_append(&ipme_mask,&moreipme_mask.ix[i])) ipme_init_retclean(0);
  }
  ipmeok = 1;
  ipme_init_retclean(1);
}


int ipme_readipfile(ipa, ipa_mask, fn)
  ipalloc *ipa, *ipa_mask;
  char *fn;
{
  int fd = -1;
  char inbuf[1024];
  substdio ss;
  stralloc l = {0};
  int match;
  struct ip_mx ix, ix_mask;
  int ret = 1;
  int slash = 0;

  if ( (fd = open_read(fn)) != -1) {
    substdio_fdbuf(&ss, read, fd, inbuf, sizeof(inbuf));
    while ( (getln(&ss,&l,&match,'\n') != -1) && (match || l.len) ) {
      l.len--;
      if (!stralloc_0(&l)) { ret = 0; break; }
      if (l.s[slash=str_chr(l.s,'/')]!='\0')
      {
        l.s[slash]='\0';
        if (!ip_scan(l.s+slash+1,&ix_mask.addr.ip))
          continue;
      }
      else
        if (!ip_scan("255.255.255.255",&ix_mask.addr.ip)) { ret = 0; break; }

      if (!ip_scan(l.s, &ix.addr.ip)) continue;
      if (!ipalloc_append(ipa,&ix)) { ret = 0; break; }
      if (!ipalloc_append(ipa_mask,&ix_mask.addr.ip)) { ret = 0; break; }
    }
    if (l.s) alloc_free(l.s);
    if ( (fd >= 0) && (close(fd) == -1) )
      ret = 0;
  }
  return ret;
}

