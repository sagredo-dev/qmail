
# Configure/install the following as per notes.sagredo.eu guide:
# - control scripts
# - aliases
# - SPF
# - SRS (uses control/me as the srs_domain)
# - log dirs in /var/log/qmail
# - cronjobs
# - logrotate
# - tcprules (basic, just to make initial tests)
# - supervise scripts
# - qmailctl script
# - RBL
# - DKIM control/filterargs and /control/domainkeys dir
# - SURBL
# - moreipme
# - overlimit feature
# - smtpplugins
# - helodnscheck spp plugin
# - svtools
# - qmHandle
# - queue-repair
# - SSL key file (optional)

if [ ! -d QMAIL/control ]; then
  echo "QMAIL/control dir not found. Exiting."
  exit 1
fi

if [ -f QMAIL/control/me ]; then
  echo "It seems like this is not a fresh installation,"
  echo "as the QMAIL/control/me file already exists."
  echo -n "Do you want proceed overriding the current files in QMAIL? y/n? [n] "
  read RESPONCE
  if [ "$RESPONCE" != 'y' ] && [ "$RESPONCE" != 'Y' ]; then
    echo "Exiting"
    exit 1
  fi
fi

if [ -z "$1" ]; then
  echo "You must provide your FQDN."
  echo "Usage: $0 mx.mydomain.tld"
  exit 1
fi

FQDN="$1"
SRCDIR=$(dirname $0)
BINDIR=/usr/local/bin
SBINDIR=/usr/local/sbin
LOGDIR=/var/log
MANDIR=/usr/local/share/man/man1

mkdir -p $BINDIR $SBINDIR $LOGDIR $MANDIR

echo "Your fully qualified host name is '$FQDN'"
echo
echo "Putting '$FQDN' into control/me..."
echo "$FQDN" > QMAIL/control/me
chmod 644 QMAIL/control/me

( echo "$FQDN" | sed 's/^\([^\.]*\)\.\([^\.]*\)\./\2\./' | (
  read DDOM
  echo "Putting '$DDOM' into control/defaultdomain..."
  echo "$DDOM" > QMAIL/control/defaultdomain
  chmod 644 QMAIL/control/defaultdomain
) )
DEFAULTDOMAIN=`cat QMAIL/control/defaultdomain`

( echo "$FQDN" | sed 's/^.*\.\([^\.]*\)\.\([^\.]*\)$/\1.\2/' | (
  read PDOM
  echo "Putting '$PDOM' into control/plusdomain..."
  echo "$PDOM" > QMAIL/control/plusdomain
  chmod 644 QMAIL/control/plusdomain
) )

echo "Putting '$FQDN' into control/rcpthosts..."
echo "$FQDN" >> QMAIL/control/rcpthosts
chmod 644 QMAIL/control/rcpthosts

echo "Putting '$FQDN' into control/srs_domain..."
echo "$FQDN" > QMAIL/control/srs_domain
chmod 644 QMAIL/control/srs_domain

echo "Putting '$FQDN:srs' into control/virtualdomains..."
echo "$FQDN:srs" >> QMAIL/control/virtualdomains
chmod 644 QMAIL/control/virtualdomains

echo "Putting a random string into control/srs_secrets..."
echo $(LC_ALL=C tr -dc '[:graph:]' </dev/urandom | head -c 13; echo) > QMAIL/control/srs_secrets
chmod 644 QMAIL/control/srs_secrets

echo "Creating the srs alias .qmail-srs-default..."
echo "| QMAIL/bin/srsfilter" > QMAIL/alias/.qmail-srs-default
chmod 644 QMAIL/alias/.qmail-srs-default

echo "Putting '3' in control/spfbehavior..."
echo 3 > QMAIL/control/spfbehavior

echo "Putting \"| ~vpopmail/bin/vdelivermail '' delete\" in control/defaultdelivery..."
echo "| ~vpopmail/bin/vdelivermail '' delete" > QMAIL/control/defaultdelivery

echo "Putting '200' in control/concurrencyincoming..."
echo 200 > QMAIL/control/concurrencyincoming

echo "Putting 'noreply' in control/bouncefrom..."
echo noreply > QMAIL/control/bouncefrom

echo "Putting '$DEFAULTDOMAIN' in control/bouncehost..."
echo $DEFAULTDOMAIN > QMAIL/control/bouncehost

echo "Putting '20000000' in control/databytes..."
echo 20000000 > QMAIL/control/databytes

echo "Putting '272800' in control/queuelifetime..."
echo 272800 > QMAIL/control/queuelifetime

echo "Putting '30000000' in control/softlimit..."
echo 30000000 > QMAIL/control/softlimit

echo "Putting '100' in control/maxrcpt..."
echo 100 > QMAIL/control/maxrcpt

echo "Putting '2' in control/brtlimit..."
echo 2 > QMAIL/control/brtlimit

echo "Putting 'HIGH:MEDIUM:!MD5:!RC4:!3DES:!LOW:!SSLv2:!SSLv3' in control/tlsserverciphers..."
echo 'HIGH:MEDIUM:!MD5:!RC4:!3DES:!LOW:!SSLv2:!SSLv3' > QMAIL/control/tlsserverciphers

########### aliases
echo "Putting 'postmaster@${DEFAULTDOMAIN}' in '.qmail-postmaster' '.qmail-mailer-daemon' and '.qmail-root' aliases..."
echo "postmaster@${DEFAULTDOMAIN}" > QMAIL/alias/.qmail-postmaster
ln -s QMAIL/alias/.qmail-postmaster QMAIL/alias/.qmail-mailer-daemon
ln -s QMAIL/alias/.qmail-postmaster QMAIL/alias/.qmail-root
chmod 644 QMAIL/alias/.qmail*

########### service dir
echo "Linking the services in /service..."
mkdir -p /service
# rebuild the services
rm -f /service/*
ln -s QMAIL/supervise/qmail-smtpd      /service
ln -s QMAIL/supervise/qmail-smtpsd     /service
ln -s QMAIL/supervise/qmail-submission /service
ln -s QMAIL/supervise/qmail-send       /service
ln -s QMAIL/supervise/vpopmaild        /service
ln -s QMAIL/supervise/vusaged          /service
ln -s QMAIL/supervise/clear            /service

########### supervise
if [ ! -x QMAIL/rc ] && [ ! -d QMAIL/supervise ]; then
  # if it's a fresh installation copy everything in QMAIL/
  echo "Copying the supervise scripts in QMAIL..."
  cp -rp $SRCDIR/scripts/example-supervise/rc $SRCDIR/scripts/example-supervise/supervise QMAIL/
fi
# Copy the supervise scripts in QMAIL/doc/example-supervise
echo "Copying the supervise scripts in QMAIL/doc/example-supervise..."
cp -rp $SRCDIR/scripts/example-supervise QMAIL/doc/

########### logs
echo "Configuring the $LOGDIR/qmail dir..."
mkdir -p $LOGDIR/qmail
chown -R qmaill:nofiles $LOGDIR/qmail
if [ $(getent group root) ]; then
  chgrp root $LOGDIR/qmail
elif [ $(getent group wheel) ]; then
  chgrp wheel $LOGDIR/qmail
fi
chmod -R og-wrx $LOGDIR/qmail
chmod g+rx $LOGDIR/qmail
mkdir -p $LOGDIR/qmail/backup

echo "Configuring the 'convert-multilog' feature..."
cp $SRCDIR/scripts/convert-multilog $BINDIR
ln -s $LOGDIR/qmail/send       /service/qmail-send/log/main
ln -s $LOGDIR/qmail/smtpd      /service/qmail-smtpd/log/main
ln -s $LOGDIR/qmail/smtpsd     /service/qmail-smtpsd/log/main
ln -s $LOGDIR/qmail/submission /service/qmail-submission/log/main

########### qmailctl
echo "Installing the qmailctl script in $BINDIR/qmailctl..."
cp $SRCDIR/scripts/qmailctl $BINDIR

########### cronjobs
echo "Installing cronjobs in /etc/cron.d/qmail..."
# slackware OS does not allow the user declared in /etc/cron.d cronjobs
if [ -r /etc/slackware-version ]; then
  CRONUSER=""
else
  CRONUSER="root"
fi
cat > /etc/cron.d/qmail << EOF
# convert-multilog
59 2 * * * $CRONUSER $BINDIR/convert-multilog 1> /dev/null
# qmail log
0 0 * * *  $CRONUSER $BINDIR/svc -a /service/qmail-submission/log
0 0 * * *  $CRONUSER $BINDIR/svc -a /service/qmail-smtpd/log
0 0 * * *  $CRONUSER $BINDIR/svc -a /service/qmail-smtpsd/log
0 0 * * *  $CRONUSER $BINDIR/svc -a /service/qmail-send/log
0 0 * * *  $CRONUSER $BINDIR/svc -a /service/vpopmaild/log
0 0 * * *  $CRONUSER $BINDIR/svc -a /service/vusaged/log
# rcptcheck overlimit
59 1 * * * $CRONUSER find QMAIL/overlimit/ -type f -exec rm -f "{}" \; >> $LOGDIR/cron
# surbl tlds update
2 2 23 * * $CRONUSER $BINDIR/update_tlds.sh 1> /dev/null
# surbl cache purge
2 9 * * *  $CRONUSER find QMAIL/control/cache/* -cmin +5 -exec /bin/rm -f {} \;
EOF

########### RBL
echo "Configuring RBL..."
cat > QMAIL/control/dnsbllist << EOF
-b.barracudacentral.org
-zen.spamhaus.org
-psbl.surriel.com
-bl.spamcop.net
EOF

########### moreipme
IPCOMMAND=$(which ip)
if [ ! -z "$IPCOMMAND" ]; then
  IP4=$($IPCOMMAND -o -4 addr list eth0 | awk '{print $4}' | cut -d/ -f1)
  echo "Adding $IP4 to QMAIL/control/moreipme..."
  echo $IP4 > QMAIL/control/moreipme
  IP6=$($IPCOMMAND -o -6 addr list eth0 | awk '{print $4}' | cut -d/ -f1)
  if [ -z "$IP6" ]; then
    echo "Adding $IP6 to QMAIL/control/moreipme..."
    echo $IP6 >> QMAIL/control/moreipme
  fi
fi

########### smtpplugins
# install control/smtpplugins file if not existent (unable to read control crash otherwise)
echo "Adding control/smtpplugins sample file and enabling helodnscheck plugin..."
cat > QMAIL/control/smtpplugins << EOF
# smtpplugins sample file
[connection]

[auth]

[helo]
plugins/helodnscheck

[mail]

[rcpt]

[data]
EOF
chown root:qmail QMAIL/control/smtpplugins

########### dkim
echo "Configuring control/filterargs for RSA 1024 bit long keys..."
echo "*:remote:QMAIL/bin/qmail-dkim:DKIMQUEUE=/bin/cat,DKIMSIGN=QMAIL/control/domainkeys/%/default,DKIMSIGNOPTIONS=" > QMAIL/control/filterargs

########## SURBL
echo "Configuring SURBL filter. Downloading tlds domains in QMAIL/control..."
cat > $BINDIR/update_tlds.sh << EOF
#!/bin/sh
wget -O QMAIL/control/level3-tlds https://www.surbl.org/static/three-level-tlds
wget -O QMAIL/control/level2-tlds https://www.surbl.org/static/two-level-tlds
EOF
chmod +x $BINDIR/update_tlds.sh
$BINDIR/update_tlds.sh

########## tcprules
echo "Installing the tcprules in QMAIL/control..."
if [ ! -f QMAIL/control/tcp.smtp ];then
cat > QMAIL/control/tcp.smtp << EOF
0.0.0.0:allow,RELAYCLIENT="",SMTPD_GREETDELAY="0"
127.:allow,RELAYCLIENT="",SMTPD_GREETDELAY="0"
:allow,CHKUSER_WRONGRCPTLIMIT="3"
EOF
else
echo "skipping tcp.smtp (already exists)"
fi
if [ ! -f QMAIL/control/tcp.submission ];then
cat > QMAIL/control/tcp.submission << EOF
:allow
EOF
else
echo "skipping tcp.submission (already exists)"
fi
qmailctl cdb

########## overlimit
echo "Installing and configuring the 'overlimit (limiting outgoing emails)' feature..."
cp scripts/rcptcheck-overlimit QMAIL/bin
if [ ! -f QMAIL/control/relaylimits ];then
cat > QMAIL/control/relaylimits << EOF
:1000
EOF
else
echo "skipping control/relaylimits (already exists)"
fi

############ svtools
echo "Installing svtools..."
cp -f scripts/svtools/svdir \
scripts/svtools/svinfo \
scripts/svtools/mltail \
scripts/svtools/mlcat \
scripts/svtools/mlhead \
scripts/svtools/mltac \
$BINDIR
cp -f scripts/svtools/svinitd \
scripts/svtools/svinitd-create \
scripts/svtools/svsetup \
$SBINDIR
cp -f scripts/svtools/svinitd.1 \
scripts/svtools/svinitd-create.1 \
scripts/svtools/svsetup.1 \
scripts/svtools/svdir.1 \
scripts/svtools/svinfo.1 \
scripts/svtools/mltail.1 \
scripts/svtools/mlcat.1 \
scripts/svtools/mlhead.1 \
scripts/svtools/mltac.1 \
$MANDIR

############ qmHandle
echo "Installing qmHandle in $BINDIR/qmHandle..."
cp -f scripts/qmHandle/qmHandle $BINDIR
cp -f scripts/qmHandle/README.qmHandle.md QMAIL/doc/

############ queue-repair
echo "Installing queue_repair in $BINDIR/queue_repair..."
cp -f scripts/queue_repair/queue_repair $BINDIR

############ SSL key file
echo
echo -n "Do you want to create the SSL key file y/n? [n]"
read RESPONCE
if [ "$RESPONCE" = 'y' ] || [ "$RESPONCE" = 'Y' ]; then
  echo 'Creating the SSL key file...'
  make cert
  make tmprsadh
  chown vpopmail:vchkpw QMAIL/control/*.pem
else
  echo 'Skipping the SSL key file creation'
fi

##############

echo
echo "Be sure to have a valid MX record in your DNS, to configure the reverse DNS for '${FQDN}'"
echo "and to create the SPF, DKIM and DMARC records for '${FQDN}' and for '${DEFAULTDOMAIN}'."
