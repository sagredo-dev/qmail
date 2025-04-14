#!/bin/bash
# rcptcheck-overlimit v0.3
# Digitalmind 2017-08-23
# This script limits the number of emails sent by relayclients (authusers or ip with RELAYCLIENT in tcprules)
# You must define the variable RCPTCHECK=/var/qmail/bin/rcptcheck-overlimit.sh AND RCPTCHECKRELAYCLIENT="1"
# This script will be called for every accepted rcptto.
# If RELAYCLIENT is not defined the script terminates with the exit code 112 (ignore/accept).
# Messages sent to domains in rcpthosts will NOT be accounted for.
# For every accepted rcptto with RELAYCLIENT defined, a char 'X' will be appended to a file in the directory $OVERLIMITDIR;
# this file name will be the authuser, if defined, or  the client ip address.
# The script will look for an entry corresponding to the client (authuser or ip) in $LIMITSCONTROLFILE and use the number found
# as the maximum number of allowed outgoing emails.
# If the OVERLIMITDIR is not writable by the user running qmail-smtpd or the LIMITSCONTROLFILE cannot be read, the script terminates with 112 (ignore/accept).
# In case of overlimit, an exit code 113 (reject/overlimit) will be returned to qmail-smtpd and the connection will be dropped with a 421.
# $LIMITSCONTROLFILEFILE can contain comments, '0' means unlimited, the entry starting with ':' will be considered the default limit.
# If the default entry can't be found, the default will be set to unlimited.
# In case more lines match the client name, only the last will be used.
# A cronjob must be created to periodically cleanup files in $OVERLIMITDIR: to use daily limits, schedule the job once a day.
#
# Cronjob example: 
#   # find /var/qmail/overlimit/ -type f -exec rm -f "{}" \;
#
# $LIMITSCONTROLFILE example:
# -----
#:1000
#1.2.3.4:3000
#test@example.com:0
# -----
# Known bugs:
# - the line 'info@example.com:1000' also matches the client name 'testinfo@example.com'.

EXITIGNORE=112
EXITOVERLIMIT=113

LIMITSCONTROLFILE=/var/qmail/control/relaylimits
OVERLIMITDIR=/var/qmail/overlimit
DEBUGLOG=/var/log/overlimit/debug.log

if [ -z "${RELAYCLIENT+x}" ]; then exit $EXITIGNORE; fi
if [ ! -r "$LIMITSCONTROLFILE" ]; then exit $EXITIGNORE; fi
if [ ! -w "$OVERLIMITDIR" ]; then exit $EXITIGNORE; fi

# Read config file removing comments, blank lines, spaces and tabs
PREFILTER="sed -e 's/#.*$//g' -e '/^$/d' -e 's/[ \t]*//g' $LIMITSCONTROLFILE"

# SMTPAUTHUSER should be already validated, but just to be safe leave only alphanum, -.', '_', '-' and '@'
FILTEREDSMTPAUTHUSER=$(echo "$SMTPAUTHUSER" | tr -cd '[:alnum:].\-_@')

if [ -n "${RCPTHOSTS}" ]; then
  logger -t qmail-overlimit -p mail.info "RELAYCLIENT and RCPTHOSTS: mailfrom=$SENDER rcptto=$RECIPIENT authuser=${FILTEREDAUTHUSER} remoteip=${TCPREMOTEIP}"
  exit $EXITIGNORE
fi

if [ -n "${FILTEREDSMTPAUTHUSER}" ]; then
  value=$(eval ${PREFILTER} | grep -Fi "$FILTEREDSMTPAUTHUSER:" | tail -1); limit="${value##*:}" # specific authuser
  ##if [ -z "${limit}" ]; then value=$(eval ${PREFILTER} | grep -Fi "${FILTEREDSMTPAUTHUSER##*@}:" | tail -1); limit="${value##*:}"; fi # domain part
  client="${FILTEREDSMTPAUTHUSER}"
else
  value=$(eval ${PREFILTER} | grep -Fi "$TCPREMOTEIP:" | tail -1); limit="${value##*:}" # specific ip address
  client="${TCPREMOTEIP}"
fi
if [ -z "${limit}" ]; then value=$(eval ${PREFILTER} | grep "^:" | tail -1); limit="${value##*:}"; fi  # default ':value'
if [ -z "${limit}" ]; then limit=0; fi # if nothing else

currentnum=$(stat -c%s $OVERLIMITDIR/$client 2>/dev/null)
if [ -z "$currentnum" ]; then currentnum=1; fi

logger -t qmail-overlimit -p mail.info "client=$client limit=$limit current=$currentnum"

if [ "$currentnum" -gt "$limit" ] && [ "$limit" -ne "0" ]; then
  logger -t qmail-overlimit -p mail.info "REJECTED $client "
  exit $EXITOVERLIMIT
else
  echo -n "X" >> "$OVERLIMITDIR/$client" 2>/dev/null
fi
exit $EXITIGNORE

