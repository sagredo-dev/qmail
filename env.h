#ifndef ENV_H
#define ENV_H

extern int env_isinit;

extern int env_init();
extern int env_put(char *);
extern int env_put2(char *, char *);
extern int env_unset(char *);
extern /*@null@*/char *env_get(char *);
extern char *env_pick();
extern void env_clear();
extern char *env_findeq(char *);

extern char **environ;

#endif
