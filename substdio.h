#include <sys/types.h>

#ifndef SUBSTDIO_H
#define SUBSTDIO_H

typedef struct substdio {
  const char *x;
  int p;
  int n;
  int fd;
  ssize_t (*op)(int, const void *, size_t);
} substdio;

#define SUBSTDIO_FDBUF(op,fd,buf,len) { (buf), 0, (len), (fd), (ssize_t (*)(int, const void *, size_t)) (op) }

extern void substdio_fdbuf(substdio *, ssize_t (*)(int, const void *, size_t), int, const char *, int);

extern int substdio_flush(substdio *);
extern int substdio_put(substdio *, const char *, int);
extern int substdio_bput(substdio *, char *, int);
extern int substdio_putflush(substdio *, char *, int);
extern int substdio_puts(substdio *, const char *);
extern int substdio_bputs(substdio *, char *);
extern int substdio_putsflush(substdio *, char *);

extern int substdio_get(substdio *, char *, int);
extern int substdio_bget(substdio *, char *, int);
extern int substdio_feed(substdio *);

extern char *substdio_peek(substdio *);
extern void substdio_seek(substdio *, int);

#define substdio_fileno(s) ((s)->fd)

#define SUBSTDIO_INSIZE 8192
#define SUBSTDIO_OUTSIZE 8192

#define substdio_PEEK(s) ( (s)->x + (s)->n )
#define substdio_SEEK(s,len) ( ( (s)->p -= (len) ) , ( (s)->n += (len) ) )

#define substdio_BPUTC(s,c) \
  ( ((s)->n != (s)->p) \
    ? ( (s)->x[(s)->p++] = (c), 0 ) \
    : substdio_bput((s),&(c),1) \
  )

extern int substdio_copy(substdio *, substdio *);

#endif
