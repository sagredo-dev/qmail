#include <string.h>
#include "fmt.h"
#include "scan.h"
#include "ip.h"
#include "byte.h"

const unsigned char V4mappedprefix[12]={0,0,0,0,0,0,0,0,0,0,0xff,0xff};

unsigned int ip_fmt(s,ip)
char *s;
struct ip_address *ip;
{
  unsigned int len;
  unsigned int i;
 
  len = 0;
  i = fmt_ulong(s,(unsigned long) ip->d[0]); len += i; if (s) s += i;
  i = fmt_str(s,"."); len += i; if (s) s += i;
  i = fmt_ulong(s,(unsigned long) ip->d[1]); len += i; if (s) s += i;
  i = fmt_str(s,"."); len += i; if (s) s += i;
  i = fmt_ulong(s,(unsigned long) ip->d[2]); len += i; if (s) s += i;
  i = fmt_str(s,"."); len += i; if (s) s += i;
  i = fmt_ulong(s,(unsigned long) ip->d[3]); len += i; if (s) s += i;
  return len;
}

unsigned int ip_scan(s,ip)
char *s;
struct ip_address *ip;
{
  unsigned int i;
  unsigned int len;
  unsigned long u;
 
  len = 0;
  i = scan_ulong(s,&u); if (!i) return 0; ip->d[0] = u; s += i; len += i;
  if (*s != '.') return 0; ++s; ++len;
  i = scan_ulong(s,&u); if (!i) return 0; ip->d[1] = u; s += i; len += i;
  if (*s != '.') return 0; ++s; ++len;
  i = scan_ulong(s,&u); if (!i) return 0; ip->d[2] = u; s += i; len += i;
  if (*s != '.') return 0; ++s; ++len;
  i = scan_ulong(s,&u); if (!i) return 0; ip->d[3] = u; s += i; len += i;
  return len;
}

unsigned int ip_scanbracket(s,ip)
char *s;
struct ip_address *ip;
{
  unsigned int len;
 
  if (*s != '[') return 0;
  len = ip_scan(s + 1,ip);
  if (!len) return 0;
  if (s[len + 1] != ']') return 0;
  return len + 2;
}

#ifdef INET6
unsigned int ip6_fmt(s,ip6)
char *s;
struct ip6_address *ip6;
{
  unsigned int len;
  unsigned int i;
  unsigned int temp;
  unsigned int compressing;
  struct ip_address ip4;
  int j;

  len = 0; compressing = 0;
  for (j=0; j<16; j+=2) {
    if (j==12 && byte_equal(ip6->d,12,V4mappedprefix)) {
      byte_copy(ip4.d, 4, ip6->d+12);
      temp=ip_fmt(s,ip4);
      len+=temp;
      s+=temp;
      break;
    }
    temp = ((unsigned long) (unsigned char) ip6->d[j] << 8) +
            (unsigned long) (unsigned char) ip6->d[j+1];
    if (temp == 0) {
      if (!compressing) {
   compressing=1;
   if (j==0) {
     *s=':'; s+=1; ++len;
   }
      }
    } else {
      if (compressing) {
   compressing=0;
   *s=':'; s+=1; ++len;
      }
      i = fmt_xlong(s,temp); len += i; if (s) s += i;
      if (s && j<14) { *s++ = ':'; ++len; }
    }
  }

  if (s) *s=0;
  return len;
}


/*
 * IPv6 addresses are really ugly to parse.
 * Syntax: (h = hex digit)
 *   1. hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh
 *   2. any number of 0000 may be abbreviated as "::", but only once
 *   3. The last two words may be written as IPv4 address
 */
unsigned int ip6_scan(s,ip)
char *s;
struct ip6_address *ip;
{
  unsigned int i;
  unsigned int len=0;
  unsigned int u;
  struct ip_address ip4;

  char suffix[16];
  int prefixlen=0;
  int suffixlen=0;

  for (i=0; i<4;  i++) ip4.d[i]=0;
  for (i=0; i<16; i++) ip->d[i]=0;

  for (;;) {
    if (*s == ':') {
      len++;
      if (s[1] == ':') {  /* Found "::", skip to part 2 */
        s+=2;
        len++;
        break;
      }
      s++;
    }
    i = scan_0x(s,&u);
    if (!i) return 0;
    if (prefixlen==12 && s[i]=='.') {
      i=ip_scan(s,&ip4);
      if(i) {
        byte_copy(ip->d+12,4,ip4.d);
        return i+len;
      }
      else
        return 0;
    }
    ip->d[prefixlen++] = (u >> 8);
    ip->d[prefixlen++] = (u & 255);
    s += i; len += i;
    if (prefixlen==16)
      return len;
  }
/* part 2, after "::" */
  for (;;) {
    if (*s == ':') {
      if (suffixlen==0)
  break;
      s++;
      len++;
    } else if (suffixlen!=0)
      break;
    i = scan_0x(s,&u);
    if (!i) {
      len--;
      break;
    }
    if (suffixlen+prefixlen<=12 && s[i]=='.') {
      int j=ip_scan(s,&ip4);
      if (j) {
         byte_copy(suffix+suffixlen,4,ip4.d);
  suffixlen+=4;
  len+=j;
  break;
      } else
  prefixlen=12-suffixlen; /* make end-of-loop test true */
    }
    suffix[suffixlen++] = (u >> 8);
    suffix[suffixlen++] = (u & 255);
    s += i; len += i;
    if (prefixlen+suffixlen==16)
      break;
  }
  for (i=0; i<suffixlen; i++)
    ip->d[16-suffixlen+i] = suffix[i];
  return len;
}

#endif
