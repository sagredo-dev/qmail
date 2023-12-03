#include <time.h>
#include "datetime.h"
#include "fmt.h"
#include "date822fmt.h"

static char *montab[12] = {
"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"
};

unsigned int date822fmt(s,dt)
char *s;
struct datetime *dt;
{
  unsigned int i;
  unsigned int len;
  time_t now;
  datetime_sec utc;
  datetime_sec local;
  struct tm *tm;
  struct datetime new_dt;
  int minutes;

  utc = datetime_untai(dt);
  now = (time_t)utc;
  tm = localtime(&now);
  new_dt.year = tm->tm_year;
  new_dt.mon = tm->tm_mon;
  new_dt.mday = tm->tm_mday;
  new_dt.hour = tm->tm_hour;
  new_dt.min = tm->tm_min;
  new_dt.sec = tm->tm_sec;
  local = datetime_untai(&new_dt);

  len = 0;
  i = fmt_uint(s,new_dt.mday); len += i; if (s) s += i;
  i = fmt_str(s," "); len += i; if (s) s += i;
  i = fmt_str(s,montab[new_dt.mon]); len += i; if (s) s += i;
  i = fmt_str(s," "); len += i; if (s) s += i;
  i = fmt_uint(s,new_dt.year + 1900); len += i; if (s) s += i;
  i = fmt_str(s," "); len += i; if (s) s += i;
  i = fmt_uint0(s,new_dt.hour,2); len += i; if (s) s += i;
  i = fmt_str(s,":"); len += i; if (s) s += i;
  i = fmt_uint0(s,new_dt.min,2); len += i; if (s) s += i;
  i = fmt_str(s,":"); len += i; if (s) s += i;
  i = fmt_uint0(s,new_dt.sec,2); len += i; if (s) s += i;

  if (local < utc) {
    minutes = (utc - local + 30) / 60;
    i = fmt_str(s," -"); len += i; if (s) s += i;
    i = fmt_uint0(s,minutes / 60,2); len += i; if (s) s += i;
    i = fmt_uint0(s,minutes % 60,2); len += i; if (s) s += i;
  }
  else {
    minutes = (local - utc + 30) / 60;
    i = fmt_str(s," +"); len += i; if (s) s += i;
    i = fmt_uint0(s,minutes / 60,2); len += i; if (s) s += i;
    i = fmt_uint0(s,minutes % 60,2); len += i; if (s) s += i;
  }

  i = fmt_str(s,"\n"); len += i; if (s) s += i;

  return len;
}
