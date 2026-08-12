#ifndef STRSALLOC_H
#define STRSALLOC_H

#include "stralloc.h"

#include "gen_alloc.h"

GEN_ALLOC_typedef(strsalloc,stralloc,sa,len,a)
extern int strsalloc_readyplus(strsalloc *, unsigned int);
extern int strsalloc_append(strsalloc *, stralloc *);

#endif
