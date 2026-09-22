#ifndef SUBFD_H
#define SUBFD_H

#include "substdio.h"

extern substdio *subfdin;
extern substdio *subfdinsmall;
extern substdio *subfdout;
extern substdio *subfdoutsmall;
extern substdio *subfderr;

extern ssize_t subfd_read(int, char *, int);
extern ssize_t subfd_readsmall(int, char *, int);

#endif
