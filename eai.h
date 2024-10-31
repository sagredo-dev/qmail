#include "stralloc.h"

extern stralloc asciihost;
extern stralloc firstpart;
extern int utf8message;

int containsutf8(unsigned char *, int);
void checkutf8message();
int get_capa(const char *);
