#ifndef QSUTIL_H
#define QSUTIL_H

#include "deprecated.h"

extern void log1(char *);
extern void qslog2(char *, char *);

#ifdef DEPRECATED_FUNCTIONS_AVAILABLE
static inline void _deprecated_ log2(char *s1, char *s2)
{
  qslog2(s1,s2);
}
#endif
extern void log3(char *, char *, char *);
extern void logsa(stralloc *);
extern void nomem();
extern void pausedir(char *);
extern void logsafe(char *);

#endif
