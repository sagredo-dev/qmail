#include <sys/types.h>
#include <fcntl.h>
#include "open.h"

int open_write(char *fn)
{ return open(fn,O_WRONLY | O_NDELAY); }
