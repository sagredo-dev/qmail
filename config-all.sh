# Configure/install the following as per www.sagredo.eu guide:
# - control files: me, defaultdomain, defaulthost, plusdomain, rcpthosts, spfbehavior, softlimit,
#   bouncefrom, bouncehost, databytes, queuelifetime, maxrcpt, brtlimit, defaultdelivery,
#   tlsserverciphers.
# - aliases
# - SPF
# - SRS (uses control/me as the srs_domain)
# - log dirs in /var/log/qmail
# - cronjobs
# - logrotate
# - add profile.d/qmail.sh with PATH and MANPATH
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

OVERWRITE_ALL=0

check_file() {
  FILE="$1"

  if [ -e "$FILE" ]; then
    # If user already chose "overwrite all", skip the question
    if [ "$OVERWRITE_ALL" -eq 1 ]; then
      return 0
    fi

    echo "File '$FILE' already exists. Overwrite (N default)? y/N/a=all "
    read RESPONSE

    case "$RESPONSE" in
      y|Y)
        return 0
        ;;
      a|A)
        OVERWRITE_ALL=1
        return 0
        ;;
      *)
        echo "File $FILE already existing, skipping"
        return 1
        ;;
    esac
  fi

  # File does not exist: allow caller to proceed
  return 0
}

################################# sanity check

if [ ! -e conf-qmail ]; then
  echo "Please change directory to the qmail source directory"
  echo "Exit"
  exit 1
fi

if [ ! -d QMAIL/control ]; then
  echo "QMAIL/control dir not found. Exiting."
  exit 1
fi

if [ -e QMAIL/control/me ]; then
  echo "It seems like this is not a fresh installation,"
  echo "as the QMAIL/control/me file already exists."
  echo -n "Do you want to proceed overriding the current files in QMAIL? y/n? [n] "
  read RESPONSE
  if [ "$RESPONSE" != 'y' ] && [ "$RESPONSE" != 'Y' ]; then
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
SRCDIR=$(pwd)
LOGDIR="/var/log"
BINDIR="/usr/local/bin"
GREEN='\033[1;32m'
NC='\033[0m' # No Color

mkdir -p $LOGDIR $BINDIR

# me
echo "Your fully qualified host name is '$FQDN'"
echo
echo "Putting '$FQDN' into control/me..."
echo "$FQDN" > QMAIL/control/me
chmod 644 QMAIL/control/me

# defaultdomain
if check_file "QMAIL/control/defaultdomain"; then
  ( echo "$FQDN" | sed 's/^\([^\.]*\)\.\([^\.]*\)\./\2\./' | (
    read DDOM
    echo "Putting '$DDOM' into control/defaultdomain..."
    echo "$DDOM" > QMAIL/control/defaultdomain
    chmod 644 QMAIL/control/defaultdomain
  ) )
fi
DEFAULTDOMAIN=`cat QMAIL/control/defaultdomain`

# defaulthost
if check_file "QMAIL/control/defaulthost"; then
  echo "Putting '$DEFAULTDOMAIN' into control/defaulthost..."
  echo "$DEFAULTDOMAIN" > QMAIL/control/defaulthost
  chmod 644 QMAIL/control/defaulthost
fi

# plusdomain
if check_file "QMAIL/control/plusdomain"; then
  ( echo "$FQDN" | sed 's/^.*\.\([^\.]*\)\.\([^\.]*\)$/\1.\2/' | (
    read PDOM
    echo "Putting '$PDOM' into control/plusdomain..."
    echo "$PDOM" > QMAIL/control/plusdomain
    chmod 644 QMAIL/control/plusdomain
  ) )
fi

# rcpthosts
if check_file "QMAIL/control/rcpthosts"; then
  echo "Putting '$FQDN' into control/rcpthosts..."
  echo "$FQDN" >> QMAIL/control/rcpthosts
  chmod 644 QMAIL/control/rcpthosts
fi

# srs_domain
if check_file "QMAIL/control/srs_domain"; then
  echo "Putting '$FQDN' into control/srs_domain..."
  echo "$FQDN" > QMAIL/control/srs_domain
  chmod 644 QMAIL/control/srs_domain
  echo "Putting '$FQDN:srs' into control/virtualdomains..."
  echo "$FQDN:srs" >> QMAIL/control/virtualdomains
  chmod 644 QMAIL/control/virtualdomains
fi

# srs_secrets
if check_file "QMAIL/control/srs_secrets"; then
  echo "Putting a random string into control/srs_secrets..."
  echo $(LC_ALL=C tr -dc '[:graph:]' </dev/urandom | head -c 13; echo) > QMAIL/control/srs_secrets
  chmod 644 QMAIL/control/srs_secrets
fi

# .qmail-srs-default
if check_file "QMAIL/alias/.qmail-srs-default"; then
  echo "Creating the srs alias .qmail-srs-default..."
  echo "| QMAIL/bin/srsfilter" > QMAIL/alias/.qmail-srs-default
  chmod 644 QMAIL/alias/.qmail-srs-default
fi

# .qmail-srs-root
if check_file "QMAIL/alias/.qmail-srs-root"; then
  echo "Creating the .qmail-srs-root alias..."
  cd QMAIL/alias
  ln -sf .qmail-postmaster .qmail-srs-root
  chmod 644 .qmail-srs-root
  cd $SRCDIR
fi

# spfbehavior
if check_file "QMAIL/control/spfbehavior"; then
  echo "Putting '3' in control/spfbehavior..."
  echo 3 > QMAIL/control/spfbehavior
fi

VPOPMAIL=$(getent passwd $(head -n 9 $SRCDIR/conf-users | tail -1) | cut -d: -f6)
# defaultdelivery
if check_file "QMAIL/control/defaultdelivery"; then
  echo "Putting \"| ${VPOPMAIL}/bin/vdelivermail '' delete\" in control/defaultdelivery..."
  echo "| ${VPOPMAIL}/bin/vdelivermail '' delete" > QMAIL/control/defaultdelivery
fi

# concurrencyincoming
if check_file "QMAIL/control/concurrencyincoming"; then
  echo "Putting '200' in control/concurrencyincoming..."
  echo 200 > QMAIL/control/concurrencyincoming
fi

# bouncefrom
if check_file "QMAIL/control/bouncefrom"; then
  echo "Putting 'noreply' in control/bouncefrom..."
  echo noreply > QMAIL/control/bouncefrom
fi

# bouncehost
if check_file "QMAIL/control/bouncehost"; then
  echo "Putting '$DEFAULTDOMAIN' in control/bouncehost..."
  echo $DEFAULTDOMAIN > QMAIL/control/bouncehost
fi

# databytes
if check_file "QMAIL/control/databytes"; then
  echo "Putting '20000000' in control/databytes..."
  echo 20000000 > QMAIL/control/databytes
fi

# queuelifetime
if check_file "QMAIL/control/queuelifetime"; then
  echo "Putting '272800' in control/queuelifetime..."
  echo 272800 > QMAIL/control/queuelifetime
fi

# softlimit
if check_file "QMAIL/control/softlimit"; then
  echo "Putting '30000000' in control/softlimit..."
  echo 30000000 > QMAIL/control/softlimit
fi

# maxrcpt
if check_file "QMAIL/control/maxrcpt"; then
  echo "Putting '100' in control/maxrcpt..."
  echo 100 > QMAIL/control/maxrcpt
fi

# brtlimit
if check_file "QMAIL/control/brtlimit"; then
  echo "Putting '2' in control/brtlimit..."
  echo 2 > QMAIL/control/brtlimit
fi

# tlsserverciphers
if check_file "QMAIL/control/tlsserverciphers"; then
  echo "Putting 'HIGH:MEDIUM:!MD5:!RC4:!3DES:!LOW:!SSLv2:!SSLv3' in control/tlsserverciphers..."
  echo 'HIGH:MEDIUM:!MD5:!RC4:!3DES:!LOW:!SSLv2:!SSLv3' > QMAIL/control/tlsserverciphers
fi

########### aliases
# .qmail-postmaster
if check_file "QMAIL/alias/.qmail-postmaster"; then
  echo "Putting 'postmaster@${DEFAULTDOMAIN}' in '.qmail-postmaster' '.qmail-mailer-daemon' and '.qmail-root' aliases..."
  echo "postmaster@${DEFAULTDOMAIN}" > QMAIL/alias/.qmail-postmaster
  cd QMAIL/alias
  ln -sf .qmail-postmaster .qmail-mailer-daemon
  ln -sf .qmail-postmaster .qmail-root
  chmod 644 .qmail*
  cd $SRCDIR
fi

########### service dir
echo "Linking the services in /service..."
mkdir -p /service
# rebuild the services
ln -sf QMAIL/supervise/qmail-smtpd      /service
ln -sf QMAIL/supervise/qmail-smtpsd     /service
ln -sf QMAIL/supervise/qmail-submission /service
ln -sf QMAIL/supervise/qmail-send       /service
ln -sf QMAIL/supervise/vpopmaild        /service
ln -sf QMAIL/supervise/vusaged          /service
ln -sf QMAIL/supervise/clear            /service

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
cp $SRCDIR/scripts/convert-multilog QMAIL/bin
ln -sf $LOGDIR/qmail/send       /service/qmail-send/log/main
ln -sf $LOGDIR/qmail/smtpd      /service/qmail-smtpd/log/main
ln -sf $LOGDIR/qmail/smtpsd     /service/qmail-smtpsd/log/main
ln -sf $LOGDIR/qmail/submission /service/qmail-submission/log/main

########### set PATH and MANPATH
if check_file "/etc/profile.d/qmail.sh"; then
  echo "Setting PATH and MANPATH for qmail, vpopmail and dovecot in /etc/profile.d/qmail.sh..."
  cat > /etc/profile.d/qmail.sh <<- EOF
	#!/bin/sh
	PATH=\$PATH:QMAIL/bin:$VPOPMAIL/bin:/usr/local/dovecot/bin:/usr/local/dovecot-pigeonhole/bin
	export PATH
	MANPATH=\$MANPATH:QMAIL/man:/usr/local/dovecot/share/man
	export MANPATH
EOF
  chmod +x /etc/profile.d/qmail.sh
fi

########### qmailctl
echo "Installing the qmailctl script in QMAIL/bin/qmailctl..."
cp $SRCDIR/scripts/qmailctl QMAIL/bin
# Create a symbolic link in /usr/local/bin so that qmailctl will run in the shell with no path
ln -sf QMAIL/bin/qmailctl $BINDIR/qmailctl

########### cronjobs
if check_file "/etc/cron.d/qmail"; then
  echo "Installing cronjobs in /etc/cron.d/qmail..."
  # slackware OS does not allow the user declared in /etc/cron.d cronjobs
  if [ -e /etc/slackware-version ]; then
    CRONUSER=""
  else
    CRONUSER="root"
  fi
  cat > /etc/cron.d/qmail << EOF
# convert-multilog
59 2 * * * $CRONUSER QMAIL/bin/convert-multilog 1> /dev/null
# qmail log
0 0 * * *  $CRONUSER $BINDIR/svc -a /service/qmail-submission/log
0 0 * * *  $CRONUSER $BINDIR/svc -a /service/qmail-smtpd/log
0 0 * * *  $CRONUSER $BINDIR/svc -a /service/qmail-smtpsd/log
0 0 * * *  $CRONUSER $BINDIR/svc -a /service/qmail-send/log
0 0 * * *  $CRONUSER $BINDIR/svc -a /service/vpopmaild/log
0 0 * * *  $CRONUSER $BINDIR/svc -a /service/vusaged/log
# surbl tlds update
2 2 23 * * $CRONUSER QMAIL/bin/update_tlds 1> /dev/null
# surbl cache purge
2 9 * * *  $CRONUSER find QMAIL/control/cache/* -cmin +5 -exec /bin/rm -f {} \;
EOF
fi

########### RBL
if check_file "QMAIL/control/dnsbllist"; then
  echo "Configuring RBL..."
  cat > QMAIL/control/dnsbllist <<- EOF
	-b.barracudacentral.org
	-zen.spamhaus.org
	-psbl.surriel.com
	-bl.spamcop.net
EOF
fi

########### moreipme
if check_file "QMAIL/control/moreipme"; then
  IPCOMMAND=$(command -v ip) || exit 0
  OUT=QMAIL/control/moreipme
  : > "$OUT"   # svuota il file
  # IPv4
  ip -o -4 addr show scope global |
  awk '{print $4}' | cut -d/ -f1 |
  while read -r ip4; do
    echo "Adding $ip4 to $OUT..."
    printf '%s\n' "$ip4" >> "$OUT"
  done
  # IPv6
  ip -o -6 addr show scope global |
  awk '{print $4}' | cut -d/ -f1 |
  while read -r ip6; do
    echo "Adding $ip6 to $OUT..."
    printf '%s\n' "$ip6" >> "$OUT"
  done
fi

########### smtpplugins
# install control/smtpplugins file if not existent (unable to read control crash otherwise)
if check_file "QMAIL/control/smtpplugins"; then
  echo "Adding control/smtpplugins sample file and enabling helodnscheck plugin..."
  cat > QMAIL/control/smtpplugins <<- EOF
	# smtpplugins sample file
	[connection]

	[auth]

	[helo]
	plugins/helodnscheck

	[mail]

	[rcpt]

	[pass]

	[data]
EOF
  chown root:qmail QMAIL/control/smtpplugins
fi

########### dkim
if check_file "QMAIL/control/filterargs"; then
  echo "Configuring control/filterargs for DKIM"
  echo -n "Do you want to configure DKIM for RSA 1024 or 2048 bit long keys (default 1024)? [1024/2048] "
  read RESPONSE
  if [ "$RESPONSE" = "2048" ]; then
    echo "Configuring control/filterargs for RSA 2048 bit long keys..."
    echo "*:remote:QMAIL/bin/qmail-dkim:ERROR_FD=2,DKIMQUEUE=/bin/cat,DKIMSIGN=QMAIL/control/domainkeys/%/default,DKIMSIGNOPTIONS=-z 2" > QMAIL/control/filterargs
  else
    echo "Configuring control/filterargs for RSA 1024 bit long keys..."
    echo "*:remote:QMAIL/bin/qmail-dkim:ERROR_FD=2,DKIMQUEUE=/bin/cat,DKIMSIGN=QMAIL/control/domainkeys/%/default,DKIMSIGNOPTIONS=" > QMAIL/control/filterargs
  fi
fi

########## SURBL
echo "Configuring SURBL filter. Downloading tlds domains in QMAIL/control..."
cat > QMAIL/bin/update_tlds <<- EOF
	#!/bin/sh
	wget -O QMAIL/control/level3-tlds https://www.surbl.org/static/three-level-tlds
	wget -O QMAIL/control/level2-tlds https://www.surbl.org/static/two-level-tlds
EOF
chmod +x QMAIL/bin/update_tlds
QMAIL/bin/update_tlds

########## tcprules
# tcp.smtp
if check_file "QMAIL/control/tcp.smtp"; then
  echo "Installing the tcprules in QMAIL/control..."
  cat > QMAIL/control/tcp.smtp <<- EOF
	0.0.0.0:allow,RELAYCLIENT="",SMTPD_GREETDELAY="0"
	127.:allow,RELAYCLIENT="",SMTPD_GREETDELAY="0"
	:allow,CHKUSER_WRONGRCPTLIMIT="3"
EOF
fi
# tcp.submission
if check_file "QMAIL/control/tcp.submission"; then
  cat > QMAIL/control/tcp.submission <<- EOF
	:allow
EOF
fi
QMAIL/bin/qmailctl cdb

########## overlimit

echo "Installing and configuring the 'overlimit (limiting outgoing emails)' feature..."
cp scripts/rcptcheck-overlimit QMAIL/bin
if check_file "QMAIL/control/relaylimits"; then
  cat > QMAIL/control/relaylimits <<- EOF
	:1000
EOF
fi
if check_file "/etc/cron.daily/rcptcheck-overlimit.cron.daily"; then
  echo "Installing 'overlimit' cronjob in /etc/cron.daily..."
  cp scripts/rcptcheck-overlimit.cron.daily /etc/cron.daily
fi

############ svtools
echo "Installing svtools..."
cp -f scripts/svtools/svdir \
scripts/svtools/svinfo \
scripts/svtools/mltail \
scripts/svtools/mlcat \
scripts/svtools/mlhead \
scripts/svtools/mltac \
QMAIL/bin
cp -f scripts/svtools/svinitd \
scripts/svtools/svinitd-create \
scripts/svtools/svsetup \
QMAIL/bin
cp -f scripts/svtools/svinitd.1 \
scripts/svtools/svinitd-create.1 \
scripts/svtools/svsetup.1 \
scripts/svtools/svdir.1 \
scripts/svtools/svinfo.1 \
scripts/svtools/mltail.1 \
scripts/svtools/mlcat.1 \
scripts/svtools/mlhead.1 \
scripts/svtools/mltac.1 \
QMAIL/man/man1

############ qmHandle
echo "Installing qmHandle in QMAIL/bin/qmHandle..."
cp -f scripts/qmHandle/qmHandle QMAIL/bin
cp -f scripts/qmHandle/README.qmHandle.md QMAIL/doc/

############ queue-repair
echo "Installing queue_repair in QMAIL/bin/queue_repair..."
cp -f scripts/queue_repair/queue_repair QMAIL/bin

############ SSL key file
echo
echo -n "Do you want to create the SSL key file y/n? [n] "
read RESPONSE
if [ "$RESPONSE" = 'y' ] || [ "$RESPONSE" = 'Y' ]; then
  echo 'Creating the SSL key file...'
  make cert
else
  echo 'Skipping the SSL key file creation'
fi
echo -n "Do you want to create the RSA DH key file y/n? [n] "
read RESPONSE
if [ "$RESPONSE" = 'y' ] || [ "$RESPONSE" = 'Y' ]; then
  echo 'Creating the RSA DH key file...'
  make tmprsadh
else
  echo 'Skipping the RSA DH key file creation'
fi
chown vpopmail:vchkpw QMAIL/control/*.pem

echo
echo "Be sure to have a valid MX record in your DNS, to configure the reverse DNS for '${FQDN}'"
echo "and to create the SPF, DKIM and DMARC records for '${FQDN}' and for '${DEFAULTDOMAIN}'."
echo
echo "You have to update the PATH and MANPATH in the current shell by rebooting the OS"
echo "or better by running:"
echo -e "${GREEN}PATH=\$PATH:QMAIL/bin:$VPOPMAIL/bin:/usr/local/dovecot/bin:/usr/local/dovecot-pigeonhole/bin"
echo -e "MANPATH=\$MANPATH:QMAIL/man:/usr/local/dovecot/share/man${NC}"
echo
echo "You can now start qmail by running"
echo -e "${GREEN}qmailctl boot${NC}"
