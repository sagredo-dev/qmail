#ifndef STR_H
#define STR_H

extern unsigned int str_copyb(char *, char *, int);
#include <string.h>

#define str_copy(s,t) strcpy((s),(t))
#define str_diff(s,t) strcmp((s),(t))
#define str_diffn(s,t,len) strncmp((s),(t),(len))
#define str_len(s) strlen((s))
extern unsigned int str_chr(char *, int);
extern unsigned int str_rchr(char *, int);
extern int str_start(char *, char *);

#include <sys/types.h>
extern size_t str_cspn(const char *, const char *);

#define str_equal(s,t) (strcmp((s),(t)) == 0)

#endif
