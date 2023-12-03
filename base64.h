#ifndef BASE64_H
#define BASE64_H

#include "stralloc.h"
extern int b64decode(const unsigned char *, int, stralloc *);
extern int b64encode(stralloc *, stralloc *);

#endif
