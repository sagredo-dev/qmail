
#include "scan.h"


static long int fromhex(unsigned char c) {
  if (c>='0' && c<='9')
    return c-'0';
  else if (c>='A' && c<='F')
    return c-'A'+10;
  else if (c>='a' && c<='f')
    return c-'a'+10;
  return -1;
}


unsigned int scan_0x(s, u) register char *s; register unsigned int *u;
{
  register unsigned int pos = 0;
  register unsigned long result = 0;
  register long int c;
  while ((c = fromhex((unsigned char) (s[pos]))) >= 0) {
    result = (result << 4) + c;
    ++pos;
  }
  *u = result;
  return pos;
}

