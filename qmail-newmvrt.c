#include <stdio.h>
#include <sys/stat.h>
#include "strerr.h"
#include "stralloc.h"
#include "substdio.h"
#include "getln.h"
#include "exit.h"
#include "readwrite.h"
#include "open.h"
#include "auto_qmail.h"
#include "cdbmss.h"
#include "case.h"

#define FATAL "qmail-newmvrt: fatal: "

extern int cdbmss_start(struct cdbmss *c, int fd);
extern int cdbmss_add(struct cdbmss *c, unsigned char *key, unsigned int keylen, unsigned char *data, unsigned int datalen);
extern int cdbmss_finish(struct cdbmss *c);

void die_read()
{
  strerr_die2sys(111,FATAL,"unable to read control/morevalidrcptto: ");
}
void die_write()
{
  strerr_die2sys(111,FATAL,"unable to write to control/morevalidrcptto.tmp: ");
}

char inbuf[1024];
substdio ssin;

int fd;
int fdtemp;

struct cdbmss cdbmss;
stralloc line = {0};
int match;

int main()
{
  umask(033);
  if (chdir(auto_qmail) == -1)
    strerr_die4sys(111,FATAL,"unable to chdir to ",auto_qmail,": ");

  fd = open_read("control/morevalidrcptto");
  if (fd == -1) die_read();

  substdio_fdbuf(&ssin,read,fd,inbuf,sizeof inbuf);

  fdtemp = open_trunc("control/morevalidrcptto.tmp");
  if (fdtemp == -1) die_write();

  if (cdbmss_start(&cdbmss,fdtemp) == -1) die_write();

  for (;;) {
    if (getln(&ssin,&line,&match,'\n') != 0) die_read();
    case_lowerb(line.s,line.len);
    while (line.len) {
      if (line.s[line.len - 1] == ' ') { --line.len; continue; }
      if (line.s[line.len - 1] == '\n') { --line.len; continue; }
      if (line.s[line.len - 1] == '\t') { --line.len; continue; }
      if (line.s[0] != '#')
	if (cdbmss_add(&cdbmss,line.s,line.len,"",0) == -1)
	  die_write();
      break;
    }
    if (!match) break;
  }

  if (cdbmss_finish(&cdbmss) == -1) die_write();
  if (fsync(fdtemp) == -1) die_write();
  if (close(fdtemp) == -1) die_write(); /* NFS stupidity */
  if (rename("control/morevalidrcptto.tmp","control/morevalidrcptto.cdb") == -1)
    strerr_die2sys(111,FATAL,"unable to move control/morevalidrcptto.tmp to control/morevalidrcptto.cdb");

  _exit(0);
}
