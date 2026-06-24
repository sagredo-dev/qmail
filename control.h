#include "stralloc.h"

#ifndef CONTROL_H
#define CONTROL_H

extern int control_init();
extern int control_readline(stralloc *, char *);
extern int control_readulong(unsigned long  *, char *);
extern int control_rldef(stralloc *, char *, int, char *);
extern int control_readint(int *, char *);
extern int control_readnativefile(stralloc *, char *, int);
extern int control_readfile(stralloc *, char *, int);

#endif
