#include "str.h"
#include "gfrom.h"

int gfrom(char *s, int len)
{
 while ((len > 0) && (*s == '>')) { ++s; --len; }
 return (len >= 5) && !str_diffn(s,"From ",5);
}
