#include <unistd.h>
#include <sys/types.h>
#include "seek.h"

#define SET 0 /* sigh */

int seek_set(fd,pos) int fd; seek_pos pos;
{ if (lseek(fd,(off_t) pos,SET) == -1) return -1; return 0; }
