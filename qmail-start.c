#include <sys/stat.h>
#include <unistd.h>
#include "fd.h"
#include "prot.h"
#include "exit.h"
#include "fork.h"
#include "auto_uids.h"

#include "channels.h"

char *(qsargs[]) = { "qmail-send", 0 };
char *(qcargs[]) = { "qmail-clean", 0 };
char *(qlargs[]) = { "qmail-lspawn", "./Mailbox", 0 };
char *(qrargs[]) = { "qmail-rspawn", 0 };
#ifdef EXTERNAL_TODO
char *(qtargs[]) = { "qmail-todo", 0};
#endif

void die() { _exit(111); }

int pi0[2];
int pi1[2];
int pi2[2];
int pi3[2];
int pi4[2];
int pi5[2];
int pi6[2];
#ifdef EXTERNAL_TODO
int pi7[2];
int pi8[2];
int pi9[2];
int pi10[2];
#endif

int suppl_pi[SUPPL_CHANNELS*2][2];

void close23456() { 
  int c;
  close(2); close(3); close(4); close(5); close(6); 
#ifdef EXTERNAL_TODO
  close(7); close(8);
#endif
  for (c=1+CHANNEL_FD_OFFSET;c<=SUPPL_CHANNELS*2+CHANNEL_FD_OFFSET;c++)
  {
      close(c);
  }
}

void closepipes() {
  int c;

  close(pi1[0]); close(pi1[1]); close(pi2[0]); close(pi2[1]);
  close(pi3[0]); close(pi3[1]); close(pi4[0]); close(pi4[1]);
  close(pi5[0]); close(pi5[1]); close(pi6[0]); close(pi6[1]);
#ifdef EXTERNAL_TODO
  close(pi7[0]); close(pi7[1]); close(pi8[0]); close(pi8[1]);
	close(pi9[0]); close(pi9[1]); close(pi10[0]); close(pi10[1]);
#endif

  for (c=0;c<SUPPL_CHANNELS*2;c++)
  {
      close(suppl_pi[c][0]);
      close(suppl_pi[c][1]);
  }
}

void main(argc,argv)
int argc;
char **argv;
{
  int c, cc;

  if (chdir("/") == -1) die();
  umask(077);
  if (prot_gid(auto_gidq) == -1) die();

  if (fd_copy(2,0) == -1) die();
  if (fd_copy(3,0) == -1) die();
  if (fd_copy(4,0) == -1) die();
  if (fd_copy(5,0) == -1) die();
  if (fd_copy(6,0) == -1) die();
#ifdef EXTERNAL_TODO
  if (fd_copy(7,0) == -1) die();
  if (fd_copy(8,0) == -1) die();
#endif
  for (c=1+CHANNEL_FD_OFFSET;c<=SUPPL_CHANNELS*2+CHANNEL_FD_OFFSET;c++)
  {
      if (fd_copy(c,0) == -1) die();
  }

  if (argv[1]) {
    qlargs[1] = argv[1];
    ++argv;
  }

  if (argv[1]) {
    if (pipe(pi0) == -1) die();
    switch(fork()) {
      case -1:
	die();
      case 0:
        if (prot_gid(auto_gidn) == -1) die();
        if (prot_uid(auto_uidl) == -1) die();
        close(pi0[1]);
        if (fd_move(0,pi0[0]) == -1) die();
        close23456();
        execvp(argv[1],argv + 1);
	die();
    }
    close(pi0[0]);
    if (fd_move(1,pi0[1]) == -1) die();
  }
 
  if (pipe(pi1) == -1) die();
  if (pipe(pi2) == -1) die();
  if (pipe(pi3) == -1) die();
  if (pipe(pi4) == -1) die();
  if (pipe(pi5) == -1) die();
  if (pipe(pi6) == -1) die();
#ifdef EXTERNAL_TODO
  if (pipe(pi7) == -1) die();
  if (pipe(pi8) == -1) die();
  if (pipe(pi9) == -1) die();
  if (pipe(pi10) == -1) die();
#endif
  for (c=0;c<SUPPL_CHANNELS*2;c++)
  {
      if (SUPPL_CHANNELS>0 && pipe(suppl_pi[c]) == -1) die();
  }
 
  switch(fork()) {
    case -1: die();
    case 0:
      if (fd_copy(0,pi1[0]) == -1) die();
      if (fd_copy(1,pi2[1]) == -1) die();
      close23456();
      closepipes();
      execvp(*qlargs,qlargs);
      die();
  }
 
  switch(fork()) {
    case -1: die();
    case 0:
      if (prot_uid(auto_uidr) == -1) die();
      if (fd_copy(0,pi3[0]) == -1) die();
      if (fd_copy(1,pi4[1]) == -1) die();
      close23456();
      closepipes();
      execvp(*qrargs,qrargs);
      die();
  }
 
  switch(fork()) {
    case -1: die();
    case 0:
      if (prot_uid(auto_uidq) == -1) die();
      if (fd_copy(0,pi5[0]) == -1) die();
      if (fd_copy(1,pi6[1]) == -1) die();
      close23456();
      closepipes();
      execvp(*qcargs,qcargs);
      die();
  }
 
#ifdef EXTERNAL_TODO
  switch(fork()) {
    case -1: die();
    case 0:
      if (prot_uid(auto_uids) == -1) die();
      if (fd_copy(0,pi7[0]) == -1) die();
      if (fd_copy(1,pi8[1]) == -1) die();
      close23456();
      if (fd_copy(2,pi9[1]) == -1) die();
      if (fd_copy(3,pi10[0]) == -1) die();
      closepipes();
      execvp(*qtargs,qtargs);
      die();
  }

  switch(fork()) {
    case -1: die();
    case 0:
      if (prot_uid(auto_uidq) == -1) die();
      if (fd_copy(0,pi9[0]) == -1) die();
      if (fd_copy(1,pi10[1]) == -1) die();
      close23456();
      closepipes();
      execvp(*qcargs,qcargs);
      die();
  }
#endif

  for (c=0,cc=0;c<SUPPL_CHANNELS;++c,cc+=2)
  {
      switch(fork()) {
        case -1: die();
        case 0:
          if (prot_uid(auto_uidr) == -1) die();
          /* Does not increment cc in parent process */
          if (fd_copy(0,suppl_pi[cc++][0]) == -1) die();
          if (fd_copy(1,suppl_pi[cc][1]) == -1) die();
          close23456();
          closepipes();
          /*if (str_equal(channel_types[c],"remote"))
          {*/
              execvp(*qrargs,qrargs);
          /*}
           else
          {
             execvp(*qlargs,qlargs);
          }*/
          die();
      }
  }

  if (prot_uid(auto_uids) == -1) die();
  if (fd_copy(0,1) == -1) die();
  if (fd_copy(1,pi1[1]) == -1) die();
  if (fd_copy(2,pi2[0]) == -1) die();
  if (fd_copy(3,pi3[1]) == -1) die();
  if (fd_copy(4,pi4[0]) == -1) die();
  if (fd_copy(5,pi5[1]) == -1) die();
  if (fd_copy(6,pi6[0]) == -1) die();
#ifdef EXTERNAL_TODO
  if (fd_copy(7,pi7[1]) == -1) die();
  if (fd_copy(8,pi8[0]) == -1) die();
#endif

  for (cc=0,c=1+CHANNEL_FD_OFFSET;c<=SUPPL_CHANNELS*2+CHANNEL_FD_OFFSET;c++)
  {
      if (fd_copy(c++,suppl_pi[cc++][1]) == -1) die();
      if (fd_copy(c,suppl_pi[cc++][0]) == -1) die();
  }

  closepipes();
  execvp(*qsargs,qsargs);
  die();
}
