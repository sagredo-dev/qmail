/*
 * $Log: dns.h,v $
 * Revision 1.4  2017-05-16 12:40:39+05:30  Cprogrammer
 * define DNS_SOFT, DNS_HARD and DNS_MEM
 *
 * Revision 1.3  2009-03-27 20:40:16+05:30  Cprogrammer
 * removed windows definitions
 *
 * Revision 1.2  2009-03-27 19:23:01+05:30  Cprogrammer
 * added dns_text()
 *
 * Revision 1.1  2009-03-21 08:50:24+05:30  Cprogrammer
 * Initial revision
 *
 *  Copyright 2005 Alt-N Technologies, Ltd. 
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); 
 *  you may not use this file except in compliance with the License. 
 *  You may obtain a copy of the License at 
 *
 *      http://www.apache.org/licenses/LICENSE-2.0 
 *
 *  This code incorporates intellectual property owned by Yahoo! and licensed 
 *  pursuant to the Yahoo! DomainKeys Patent License Agreement.
 *
 *  Unless required by applicable law or agreed to in writing, software 
 *  distributed under the License is distributed on an "AS IS" BASIS, 
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 *  See the License for the specific language governing permissions and 
 *  limitations under the License.
 *
 */

// These DNS resolution routines are encapsulated by the API below

// return values for DNS functions:


#define MAX_DOMAIN			254

#define DNSRESP_SUCCESS					0	// DNS lookup returned sought after records
#define DNSRESP_TEMP_FAIL				1	// No response from DNS server
#define DNSRESP_PERM_FAIL				2	// DNS server returned error or no records
#define DNSRESP_DOMAIN_NAME_TOO_LONG	3	// Domain name too long
#define DNSRESP_NXDOMAIN				4	// DNS server returned Name Error
#define DNSRESP_EMPTY					5	// DNS server returned successful response but no records

#define DNS_SOFT -1
#define DNS_HARD -2
#define DNS_MEM  -3

// Pass in the FQDN to get the TXT record
int             DNSGetTXT(const char *szFQDN, char *Buffer, int nBufLen);
char           *dns_text(char *szFQDN);
