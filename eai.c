#include "utf8.h"
#include "case.h"
#include "str.h"
#include "stralloc.h"
#include "substdio.h"
#include "subfd.h"

extern void temp_read();
extern void temp_nomem();

/*
  returns 1 if the remote server advertises a specific verb
  tx notqmail/mbhangui-smtputf8
 */
int get_capa(const char *capa)
{
  int i = 0, len;
  len = str_len(capa);
  extern stralloc smtptext;

  for (i = 0; i < smtptext.len-len; ++i) {
    if (case_starts(smtptext.s+i,capa)) return 1;
  }
  return 0;
}

void checkutf8message()
{
  GEN_ALLOC_typedef(saa,stralloc,sa,len,a)

  int pos;
  int i;
  int r;
  char ch;
  int state;
  extern stralloc sender;
  extern saa reciplist;
  extern substdio ssin;
  extern stralloc firstpart;
  extern int utf8message;

//  if (containsutf8(sender.s, sender.len)) { utf8message = 1; return; }
  if (is_valid_utf8(sender.s)) { utf8message = 1; return; }
  for (i = 0;i < reciplist.len;++i)
    if (is_valid_utf8(reciplist.sa[i].s)) {
      utf8message = 1;
      return;
    }
  state = 0;
  pos = 0;
  for (;;) {
    r = substdio_get(&ssin,&ch,1);
    if (r == 0) break;
    if (r == -1) temp_read();
    if (ch == '\n' && !stralloc_cats(&firstpart,"\r")) temp_nomem();
    if (!stralloc_append(&firstpart,&ch)) temp_nomem();
    if (ch == '\r')
      continue;
    if (ch == '\t')
      ch = ' ';
    switch (state) {
    case 6: /* in Received, at LF but before WITH clause */
      if (ch == ' ') { state = 3; pos = 1; continue; }
      state = 0;
      /* FALL THROUGH */
    case 0: /* start of header field */
      if (ch == '\n') return;
      state = 1;
      pos = 0;
      /* FALL THROUGH */
    case 1: /* partway through "Received:" */
      if (ch != "RECEIVED:"[pos] && ch != "received:"[pos]) { state = 2; continue; }
      if (++pos == 9) { state = 3; pos = 0; }
      continue;
    case 2: /* other header field */
      if (ch == '\n') state = 0;
      continue;
    case 3: /* in Received, before WITH clause or partway though " with " */
      if (ch == '\n') { state = 6; continue; }
      if (ch != " WITH "[pos] && ch != " with "[pos]) { pos = 0; continue; }
      if (++pos == 6) { state = 4; pos = 0; }
      continue;
    case 4: /* in Received, having seen with, before the argument */
      if (pos == 0 && (ch == ' ' || ch == '\t')) continue;
      if (ch != "UTF8"[pos] && ch != "utf8"[pos]) { state = 5; continue; }
      if(++pos == 4) { utf8message = 1; state = 5; continue; }
      continue;
    case 5: /* after the RECEIVED WITH argument */
      /* blast() assumes that it copies whole lines */
      if (ch == '\n') return;
      state = 1;
      pos = 0;
      continue;
    }
  }
}
