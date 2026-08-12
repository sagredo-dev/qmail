#ifndef QMAIL_H
#define QMAIL_H

#include "substdio.h"

#define CUSTOM_ERR_FD 4
struct qmail {
  int flagerr;
  unsigned long pid;
  int fdm;
  int fde;
  int fdc;
  substdio ss;
  char buf[1024];
} ;

extern int qmail_open(struct qmail *);
extern void qmail_put(struct qmail *, char *, int);
extern void qmail_puts(struct qmail *, char *);
extern void qmail_from(struct qmail *, char *);
extern void qmail_to(struct qmail *, char *);
extern void qmail_fail(struct qmail *);
extern char *qmail_close(struct qmail *);
extern unsigned long qmail_qp(struct qmail *);

#endif
