#ifndef READSUBDIR_H
#define READSUBDIR_H

#include "direntry.h"

typedef struct readsubdir
 {
  DIR *dir;
  int pos;
  char *name;
  void (*pause)(char *);
 }
readsubdir;

extern void readsubdir_init(readsubdir *, char *, void (*)(char *));
extern int readsubdir_next(readsubdir *, unsigned long *);

#define READSUBDIR_NAMELEN 10

#endif
