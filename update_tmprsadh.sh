#!/bin/sh

# Update temporary RSA and DH keys
# Frederik Vermeulen 2004-05-31 GPL
#
# Slightly modified by Roberto Puzzanghera
#
# rsa files will be assigned to vpopmail:vchkpw by Makefile.
# Manually change this file if you are running qmail-smtpd
# as a different user.

umask 0077 || exit 0

export PATH="$PATH:/usr/local/bin/ssl:/usr/sbin"

openssl genrsa -out QMAIL/control/rsa4096.new 4096 &&
chmod 600 QMAIL/control/rsa4096.new &&
chown UGQMAILD QMAIL/control/rsa4096.new &&
mv -f QMAIL/control/rsa4096.new QMAIL/control/rsa4096.pem

openssl dhparam -2 -out QMAIL/control/dh4096.new 4096 &&
chmod 600 QMAIL/control/dh4096.new &&
chown UGQMAILD QMAIL/control/dh4096.new &&
mv -f QMAIL/control/dh4096.new QMAIL/control/dh4096.pem

