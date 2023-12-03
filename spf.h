#ifndef SPF_H
#define SPF_H

#define SPF_OK       0
#define SPF_NONE     1
#define SPF_UNKNOWN  2
#define SPF_NEUTRAL  3
#define SPF_SOFTFAIL 4
#define SPF_FAIL     5
#define SPF_ERROR    6
#define SPF_NOMEM    7

#define SPF_DEFEXP   "SPF failure. Validate your SPF configuration here https://mxtoolbox.com/SuperTool.aspx?action=spf"

/*
                     "See http://spf.pobox.com/" \
                     "why.html?sender=%{S}&ip=%{I}&receiver=%{xR}"
*/

extern int spfcheck();
extern int spfexplanation();
extern int spfinfo();

#endif
