#ifndef BYTE_H
#define BYTE_H

extern unsigned int byte_chr(char *, unsigned int, int);
extern unsigned int byte_rchr(char *, unsigned int, int);
extern unsigned int byte_cspn(char *, unsigned int, char *);
extern unsigned int byte_rcspn(char *, unsigned int, char *);
extern void byte_copy(char *, unsigned int, const char *);
extern void byte_copyr(char *, unsigned int, const char *);
extern void byte_zero(char *, unsigned int);

#define byte_equal(s,n,t) (memcmp((s),(t),(n)) == 0)

#endif
