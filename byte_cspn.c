#include "byte.h"

unsigned int byte_cspn(char *s, unsigned int n, char *c)
{
  while(*c)
    n = byte_chr(s,n,*c++);
  return n;
}
