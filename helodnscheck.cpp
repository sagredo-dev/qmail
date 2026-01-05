/* helodnscheck.cpp - version 10.0 */

/*
* Copyright (C) 2007 Jason Frisvold <friz@godshell.com>
* Original Copyright (C) 2003-2004 Perolo Silantico <per.sil@gmx.it>
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either
* version 2 of the License, or (at your option) any later
* version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software Foundation,
* Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/***********************************************************************************
  Changelog

  (2008 v.2) modifyed by Bing Ren <bingtimren (at) gmail.com> to further check
  if the TCPREMOTEIP variable (mostly set by tcpserver) match
  any of the IP addresses the HELO resolves to.

  (2022 v.7) Roberto Puzzanghera https://www.sagredo.eu
  Deny HELOs containing one of our domains, when RELAYCLIENT is
  not defined. In addition, it is now possible to deny only not solving
  hosts in HELO/EHLO.

  (Aug 2023, v. 9) Roberto Puzzanghera https://www.sagredo.eu
  Code revision.
  Added G filter for HELO/EHLO with malformed syntax (mostly random strings).
  I filter copied to A. V filter copied to N.
  P will now disable all filters.
************************************************************************************/

/***********************************************************************************
  Depending on the environment variable HELO_DNS_CHECK, deny, log and/or
  add a header if HELO doesn't solve to an address or the addresses don't
  contain the TCPREMOTEIP

    L - (default) Log
    H - add Header "X-Helo-Check"
    D - Debug mode (use with L)
    R - (default) if "RELAYCLIENT" is set, don't do anything
    P - passthrough, never deny. Use with L and/or H.

  Filters are executed in the following order:

    G - (Garbage, default) HELO/EHLO with an invalid syntax are denied.
    A - Not solving hostname in HELO/EHLO are denied. This clients do not
        even have an A record.
        Using G together with A is redundant (just use A).
    N - (Not me, default) deny if "RELAYCLIENT" is NOT set and the HELO/EHLO hostname
        matches one of our IPs contained in control/moreipme.
        "localhost" will be denied as well.
        Using N together with A is redundant (just use A).
    B - Block if the remote IP (TCPREMOTEIP) is not contained in the
        IP addresses solved. This is the original program's mode.
        Using G and/or A and/or N is together with B is redundant (just use B).

  The above can be combined, so BL means block & log.

  If P is defined all filters G, A, B and N are ignored.

  ************* Examples

  **** tcprules usage
  111.222.333.444:allow, NOHELODNSCHECK="" // allow IP
  :allow,HELO_DNS_CHECK="LB" // block & log others

  **** qmail-smtpd run file usage
  export HELO_DNS_CHECK="" // default to GNLR
  export HELO_DNS_CHECK    // HELO_DNS_CHECK turned off. Do not use like this

  **** Most moderate choice can be:
  export HELO_DNS_CHECK=GNLR
  which denies garbage & our domains' spoofing, always allow relayclient, log

  Note: If there is no HELO/EHLO argument, it defaults to GNLR

  Compile as follows:
  g++ -o /var/qmail/plugins/helodnscheck helodnscheck.cpp
  or, on freeBSD/clang:
  clang++ -o /var/qmail/plugin/helodnscheck helodnscheck.cpp

  Test as follows:
  SMTPHELOHOST="test.tld" TCPREMOTEIP="1.2.3.4" HELO_DNS_CHECK="BLRD" ./helodnscheck

  More info here:
  https://www.sagredo.eu/en/qmail-notes-185/denying-bad-dns-heloehlos-255.html
************************************************************************************/

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstring>
#include <iostream>
#include <regex>
#include <netdb.h>
#include <pwd.h>
#include <resolv.h>
#include <sstream>
#include <string>
using namespace std;

char default_action[] = "GNLR";

char dns_answer[1023];
char *addr;
ostringstream s;


/*********************************************************
  print functions
 *********************************************************/
void out(string str, bool debug=false) {
  const string hdc = "helo-dns-check: ";
  const string dbg = (debug) ? "debug: " : "";
  cerr << hdc << dbg << str << endl;
}
void out(ostringstream &oss, bool debug=false) {
  out(oss.str(), debug);
  s.clear();
  s.str("");
}


void block_permanent(string message, const char *remote_ip) {
  /*
    Bing Ren: the original helodnscheck print command "E",
    however, if the spam connection ignore the 553 error and
    continue send further commands, qmail-spp simply accept
    message and deliver it!
  */
  cout << "R553 sorry, "<<message<<" (#5.7.1)\n";

  s << "blocked with: " << message << " [" << remote_ip << "]";
  out(s);
}


/* no longer used */
void block_temporary(const char* message, const char *remote_ip) {
  cout << "E451 sorry, "<<message<<" (#4.3.0)\n";

  s << "temporary failure: "<<message<<" ["<<remote_ip<<"]";
  out(s);
}


/* exit and possibly close file */
int my_exit(int fail, FILE *fp)
{
  // Close the file if still open
  if (fp) fclose (fp);

  return fail;
}


/***************************************************
  Check if the HELO/EHLO hostname has a valid syntax

  @return false: no match found
           true: match found
 ***************************************************/
bool valid_domain(const string &str)
{
  // Regex to check valid Domain Name
  // https://www.geeksforgeeks.org/how-to-validate-a-domain-name-using-regular-expression/
  // tld length increased to 12 (.amsterdam found)
  regex pattern("^[A-Za-z0-9-]{1,63}\\.[A-Za-z]{2,12}$");

  // Return true if the string matches the regex
  return regex_match(str, pattern);
}

/*****************************************************************************
 Search a string in a file.
 Used to check if the remote ip is included in our IPs listed in control/me.

 @return  0: match not found
          1: match found
         -1: file does not exist/error
         -2: qmaild user not found
 *****************************************************************************/
int search_in_file(char *str) {
  FILE *fp;
  int line_num = 1;
  char temp [512];
  char my_file[256];

  // get the qmail dir as the home dir of user 'qmaild'
  struct passwd* pw = getpwnam("qmaild");
  if (pw == nullptr) return -2;

  snprintf(my_file, 256, "%s/control/moreipme", pw->pw_dir);
  if ((fp = fopen(my_file, "r")) == NULL) return my_exit(-1, fp);

  while (fgets(temp, sizeof(temp), fp) != NULL) {
    if ((strstr(temp, str)) != NULL) return my_exit(1, fp);
    line_num++;
  }

  return my_exit(0, fp);
}


/********************************************************************************
  Check if the HELO/EHLO solves to one of our own IPs listed in control/moreipme

  @return 0: no match found
          1: match found
         -1: file not found
 ********************************************************************************/
int moreipme_check(struct hostent* result) {
  int matched=0;
  int count=0;

  while (result->h_addr_list[count]) {
    addr=result->h_addr_list[count];
    inet_ntop(AF_INET, addr, dns_answer, 1000);

    // check if it matches one of our own IPs listed in control/moreipme
    matched = search_in_file(dns_answer);
    if(matched != 0) break;
    count++;
  }
  return matched;
}


/****************************************************************
  A DNS record query

  @return: the number of found records (0 if any)
 ****************************************************************/
int A_check(struct hostent* result, const char *remote_ip) {
  int found=0;
  int count=0;

  while (result->h_addr_list[count] && (found==0)) {
    addr=result->h_addr_list[count];
    inet_ntop(AF_INET, addr, dns_answer, 1000);
    if (strcmp(dns_answer, remote_ip) == 0) found = 1;
    count++;
  }
  return found;
}


/********************************************************************
  Print debug information
 ********************************************************************/
void debug_info(struct hostent *result, const char *remote_ip) {
  int count=0;

  s<<"result->h_name "<<result->h_name; out(s,true);
  out("result->h_aliases:",true);
  char* alias;
  while (result->h_aliases[count]) {
    alias=result->h_aliases[count];
    s<<"["<<count<<"] "<<alias; out(s,true);
    count++;
  }

  s<<"result->h_addrtype "<<result->h_addrtype; out(s,true);
  s<<"result->h_length "<<result->h_length; out(s, true);
  out("result->h_addr_list:", true);

  while (result->h_addr_list[count]) {
    addr=result->h_addr_list[count];
    inet_ntop(AF_INET, addr, dns_answer, 1000);
    s<<"["<<count<<"] "<<dns_answer; out(s,true);
    count++;
  }

  if (*remote_ip) {s<<"remote host "<<remote_ip; out(s,true);}
  else out("no remote ip $TCPREMOTEIP");
}


int main() {
  const char *helo_domain   = getenv("SMTPHELOHOST");
  const char *remote_ip     = getenv("TCPREMOTEIP");
  const char *no_helo_check = getenv("NOHELODNSCHECK");
        char *action        = getenv("HELO_DNS_CHECK");

  unsigned char dns_answer[1023];
  struct hostent *result;
  int matched=0;

  // skip if HELO_DNS_CHECK is not defined (submission service)
  if (!action) {
    out("HELO_DNS_CHECK not defined (NULL)");
    return 0;
  }
  // specify a default action if HELO_DNS_CHECK is a zero length string
  else if (action && strlen(action)==0) action = default_action;


  char *debug       = strpbrk(action,"D");
  const char *log   = strpbrk(action,"L");
  char *header      = strpbrk(action,"H");
  char *relayclient = strpbrk(action,"R");
  char *pass        = strpbrk(action,"P");
  char *garbage     = strpbrk(action,"G");
  char *notsolving  = strpbrk(action,"A");
  char *notme       = strpbrk(action,"N");
  char *block       = strpbrk(action,"B");


  if (debug) {
    // always consider the normal log action as active if debugging
    log = "L";

    // print action
    s << "action is "        << action;        out(s,true);
    // print no_helo_check
    if (no_helo_check) s << "no_helo_check is " << no_helo_check;
    else s << "no_helo_check is not defined";
    out(s,true);
    // print helo_domain
    if (helo_domain) s << "helo_domain is "   << helo_domain;
    else s << "helo_domain is not defined";
    out(s,true);
    // print remote_ip
    if (remote_ip) s << "remote_ip is "     << remote_ip;
    else s << "remote_ip is not defined";
    out(s,true);
  }

  // skip if TCPREMOTEIP not set
  if (!remote_ip) {
    if (log) out("TCPREMOTEIP not set, let it go.");
    return 0;
  }

  // skip if it's RELAYCLIENT
  if (relayclient && getenv("RELAYCLIENT")) {
    if (debug) out("skip RELAYCLIENT", true);
    return 0;
  }

  // skip if it's allowed (NOHELODNSCHECK defined)
  if (no_helo_check) {
    if (debug) out("skip NOHELODNSCHECK", true);
    return 0;
  }

  // this should not be needed but who knows...
  if (!helo_domain && !pass) {
    if (log) {s << "No HELO sent from ["<<remote_ip<<"]"; out(s);}
    block_permanent("no HELO/EHLO hostname has been sent.", remote_ip);
    return 0;
  }


  /********************************************************
    check if the hostname is malformed
    injected by G
   ********************************************************/
  if (garbage || block || notsolving) {
    bool nomatch = valid_domain(helo_domain);
    if (debug) {s << "G filter 'nomatch': ["<<nomatch<<"]"; out(s,true);}
    if (!nomatch) {
      if (log) {s << "malformed HELO/EHLO ["<<helo_domain<<"]"<<" from ["<<remote_ip<<"]"; out(s);}
      if (!pass) {
        block_permanent("malformed HELO/EHLO hostname", remote_ip);
        return 0;
      }
    }
  }
  /********************************************************/


  // init DNS library
  res_init();
  // get A record
  result = gethostbyname(helo_domain);


  /*********************************************************************************
    check if any A record is present, not necessarily having TCPREMOTEIP
    in the address resolved.
    injected by A
   *********************************************************************************/
  if (!result) {
    out("no result in A record");

    if (notsolving || block) {
      if (h_errno == HOST_NOT_FOUND) {
        if (header) cout <<"HX-Helo-Check: HELO ["<<helo_domain<<"] from ["<<remote_ip<<"] doesn't solve\n";
        if (log) {s<<"HELO ["<<helo_domain<<"] from ["<<remote_ip<<"] doesn't solve"; out(s);}
        if (!pass) block_permanent("invalid host name in HELO/EHLO command.", remote_ip);
      }
      else if (log) {s<<"HELO ["<<helo_domain<<"] DNS CHECK for IP ["<<remote_ip<<"] temporary failed, but let it go"; out(s);}
    }
    // absolutely need to exit if no results in A record, otherwise the following tests will crash
    return 0;
  }
  // print debug information
  else if (debug) debug_info(result, remote_ip);
  /**********************************************************/


  // check if there's something left to do
  if (!strpbrk("DLHNVB", action)) return 0;


  /****************************************************************************
    check if the HELO/EHLO hostname solves to one of our IPs.
    skip if RELAYCLIENT
    injected by N
   ****************************************************************************/
  if (!getenv("RELAYCLIENT") && (notme || block)) {
    // deny localhost as HELO/EHLO
    if (strcmp(helo_domain,"localhost")==0) {
      if (log) {s<<"invalid HELO/EHLO ["<<helo_domain<<"] from ["<<remote_ip<<"]"; out(s);}
      if (!pass) {
        block_permanent("localhost HELO/EHLO doesn't match IP", remote_ip);
        return 0;
      }
    }

    // proceed to the IP check
    matched = moreipme_check(result);
    if (debug) {s<<"moreipme_check: 'matched': "<<matched; out(s,true);}
    if(matched==1) {
      if (log) {s<<"HELO ["<<helo_domain<<"] is a local domain but IP ["<<remote_ip<<"] is not a RELAYCLIENT"; out(s);}
      if ((notme || block) && !pass) {
        block_permanent("HELO doesn't match IP", remote_ip);
        return 0;
      }
    }
    else if(matched==-1 && log) {s<<"file control/moreipme not found"; out(s);}
    else if(matched==-2 && log) {s<<"qmaild user not found"; out(s);}
  }
  /****************************************************************************/


  /****************************************************************************
    A record query
    Block if TCPREMOTEIP not contained in the addresses solved.
    injected by B. This is the original program's behaviour.
   ****************************************************************************/
  matched = A_check(result, remote_ip);

  if (debug) {s<<"found = "<<matched; out(s,true);}
  if (matched == 1) return 0;
  if (header) cout << "HX-Helo-Check: HELO ["<<helo_domain<<"] doesn't match IP ["<<remote_ip<<"]\n";
  if (log) {s<<"HELO ["<<helo_domain<<"] doesn't match IP ["<<remote_ip<<"]"; out(s);}
  if (block && !pass) block_permanent("HELO/EHLO command must provide FQDN that match your IP address.", remote_ip);

  return 0;
}
