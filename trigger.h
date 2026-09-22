#ifndef TRIGGER_H
#define TRIGGER_H

extern void trigger_set();
extern void trigger_selprep(int *, fd_set *);
extern int trigger_pulled(fd_set *);

#endif
