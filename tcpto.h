#include "ip.h"

#ifndef TCPTO_H
#define TCPTO_H

extern int tcpto(struct ip_address *);
extern void tcpto_err(struct ip_address *, int);
extern void tcpto_clean();

#endif
