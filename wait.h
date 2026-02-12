#ifndef WAIT_H
#define WAIT_H
#include <sys/wait.h>

extern int wait_pid();
extern int wait_nohang();
extern int wait_stop();
extern int wait_stopnohang();

/*
 *  * If the child stopped, wait_stopped is nonzero; wait_stopsig is the signal that caused the child to stop.
 *  * If the child exited by crashing, wait_stopped is zero; wait_crashed is nonzero.
 *  * If the child exited normally, wait_stopped is zero; wait_crashed is zero; and wait_exitcode is the child's exit code.
 *  *
 *  * Everything extant so far uses these same bits.
 *  */
#define wait_crashed(w)   WTERMSIG((w))
#define wait_exitcode(w)  WEXITSTATUS((w))
#define wait_exited(w)    WIFEXITED((w))
#define wait_stopsig(w)   WSTOPSIG((w))
#define wait_stopped(w)   WIFSTOPPED((w))
#define wait_continued(w) WIFCONTINUED((w))
#define wait_termsig(w)   WTERMSIG((w))
#define wait_signaled(w)  WIFSIGNALED((w))

#endif
