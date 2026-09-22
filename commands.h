#ifndef COMMANDS_H
#define COMMANDS_H

#include "substdio.h"

struct commands {
  char *text;
  void (*fun)(char *);
  void (*flush)();
} ;

extern int commands(substdio *, struct commands *);

#endif
