#
# $Id: dk-filter.sh,v 1.37 2023-02-17 20:17:51+05:30 Cprogrammer Exp mbhangui $
#
get_dkimkeys()
{
	domain=$1
	if [ ! -f $CONTROLDIR/dkimkeys ] ; then
		return 0
	fi
	(
	awk -F: '{print $1" "$2" "$3}' $CONTROLDIR/dkimkeys | while read line
	do
		set $line
		echo $domain | grep -E "$1" >/dev/null
		if [ $? -eq 0 ] ; then
			echo $2
			shift 2
			if [ $# -gt 0 ] ; then
				echo "$*" | tr , \\n | while read "line"
				do
					var=$(echo $line | cut -d= -f1)
					val=$(echo $line | cut -d= -f2-)
					if [ -n "$val" ] ; then
						echo "export $var=\"$val\"" 1>&3
					else
						unset $var
					fi
				done
			fi
			break
		fi
	done
	)
}

#
# replace % with domain in private key filename
# sets keyfn
#
replace_percent()
{
	percent_found=0
	echo $1|grep "%" >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		percent_found=1
	fi
	if [ $percent_found -eq 1 ] ; then
		if [ -n "$BOUNCEDOMAIN" -a -z "$_SENDER" ] ; then
			keyfn=$(echo $1 | sed "s{%{$BOUNCEDOMAIN{g")
			if [ ! -f $keyfn ] ; then # remove % and check if file exists
				t=$(echo $1 | sed "s{/%{{g")
				if [ -f $t ] ; then
					keyfn=$t
				fi
			fi
		elif [ -n " $_SENDER" ] ; then
			# replace '%' in filename with domain
			domain=$(echo $_SENDER | cut -d@ -f2)
			keyfn=$(echo $1 | sed "s{%{$domain{g")
			if [ ! -f $keyfn ] ; then # remove % and check if file exists
				t=$(echo $1 | sed "s{/%{{g")
				if [ -f $t ] ; then
					keyfn=$t
				fi
			fi
		else
			keyfn=$1
		fi
	else
		keyfn=$1
	fi
}

dkim_setoptions()
{
	# DKIMSIGNOPTIONS="-z 1 -x - -y $dkimselector -s $dkimkeyfn"
	set -- $(getopt lqthb:c:d:i:x:z:y:s: "$1")
	bopt=0
	xopt=0
	zopt=0
	yopt=0
	sopt=0
	dkimopts="$prefix/bin/dkim"
	if [ -n "$BOUNCEDOMAIN" -a -z "$_SENDER" ] ; then
		dkimopts="$dkimopts -d $BOUNCEDOMAIN"
	fi  
	while [ $1 != -- ]
	do
		case $1 in
		-l)
		dkimopts="$dkimopts -l"
		;;
		-q)
		dkimopts="$dkimopts -q"
		;;
		-t)
		dkimopts="$dkimopts -t"
		;;
		-h)
		dkimopts="$dkimopts -h"
		;;

		-b)
		bopt=1
		dkimopts="$dkimopts -b $2"
		shift
		;;

		-c)
		dkimopts="$dkimopts -c $2"
		shift
		;;

		-d)
		dkimopts="$dkimopts -d $2"
		shift
		;;

		-i)
		dkimopts="$dkimopts -i $2"
		shift
		;;

		-x)
		xopt=1
		dkimopts="$dkimopts -x $2"
		shift
		;;

		-z)
		zopt=1
		dkimopts="$dkimopts -z $2"
		shift
		;;

		-y)
		yopt=1
		dkimopts="$dkimopts -y $2"
		shift
		;;

		-s)
		sopt=1
		dkimopts="$dkimopts -s $2"
		shift
		;;
		esac
		shift   # next flag
	done
	if [ $zopt -eq 0 ] ; then
		dkimopts="$dkimopts -z 2"
	fi
	if [ $xopt -eq 0 ] ; then
		dkimopts="$dkimopts -x -"
	fi
	if [ $yopt -eq 0 ] ; then
		dkimopts="$dkimopts -y $dkimselector"
	fi
	if [ $sopt -eq 0 ] ; then
		dkimopts="$dkimopts -s $dkimkeyfn"
	fi
}

#
# sets keyfn, selector
#
set_selector()
{
	if [ -z "$1" -o -z "$2" ] ; then
		return 1
	fi
	replace_percent $2
	case $1 in
		"dkim")
		dkimkeyfn=$keyfn
		# dkimsign is first set by get_dkimfn
		if [ $dkimsign -eq 2 -a ! -f $dkimkeyfn ] ; then
			dkimkeyfn=$default_key
		fi
		if [ ! -f $dkimkeyfn ] ; then
			dkimsign=0
			if [ $percent_found -eq 0 ] ; then
				echo "private key does not exist" 1>&2
				/bin/rm -f $tmpfn
				exit $priv_key_err # private key does not exist
			else
				dkimsign=1
			fi
		else
			dkimsign=1
		fi
		dkimselector=$(basename $dkimkeyfn)
		;;
	esac
}

#
# uses dkimkeys to set DKIMSIGN. Overrides original DKIMSIGN
#
get_dkimfn()
{
# set private key for dk / dkim signing
if [ -z "$DKIMVERIFY" ] ; then
	# set DKIMSIGN from dkimkeys
	if [ -z "$NODKIMKEYS" -a -f $CONTROLDIR/dkimkeys ] ; then
		domain=$(echo $_SENDER | cut -d@ -f2)
		t=$(get_dkimkeys $domain)
		if [ -n "$t" ] ; then
			DKIMSIGN=$t
		fi
	fi
	if [ -z "$DKIMSIGN" ] ; then
		DKIMSIGN=$CONTROLDIR/domainkeys/%/default
		dkimsign=2 # key, selector selected as control/domainkeys/defaut
	elif [ " $DKIMSIGN" = " $CONTROLDIR/domainkeys/%/default" ] ; then
		dkimsign=2 # key, selector selected as control/domainkeys/defaut
	fi
fi
}

if [ -z "$QMAILREMOTE" -a -z "$QMAILLOCAL" ]; then
	echo "dk-filter should be run by spawn-filter" 1>&2
	exit 1
fi
dkimsign=0
dkimverify=0
prefix=PREFIX

if [ "$prefix" = "/usr" ] ; then
	priv_key_err=35 # indimail
else
	priv_key_err=32 # netqmail, notqmail
	if [ -z "$BOUNCEDOMAIN" -a -n "$DKIMDOMAIN" ] ; then
		BOUNCEDOMAIN=$DKIMDOMAIN
	fi
fi
if [ " $CONTROLDIR" = " " ] ; then
	CONTROLDIR=@controldir@
fi
if [ -n "$NODKIM" ] ; then
	exec /bin/cat
fi

if [ ! -f $prefix/bin/dkim ] ; then
	echo "$prefix/bin/dkim: No such file or directory" 1>&2
	exit 1
fi

if [ -z "$DEFAULT_DKIM_KEY" ] ; then
	default_key=$CONTROLDIR/domainkeys/default
else
	default_key=$DEFAULT_DKIM_KEY
fi
slash=$(echo $CONTROLDIR | cut -c1)
if [ " $slash" != " /" ] ; then
	cd SYSCONFDIR
fi

if [ -n "$DKIMVERIFY" ] ; then
	dkimverify=1
else
	envfn=$(mktemp -t envfilterXXXXXX)
	exec 3>$envfn
	get_dkimfn
	. $envfn
	/bin/rm -f $envfn
fi
tmpfn=$(mktemp -t dk-filterXXXXXX)
/bin/cat > $tmpfn
if [ -n "$DKIMSIGN" ] ; then
	set_selector "dkim" "$DKIMSIGN"
	if [ -n "$dkimkeyfn" -a -f "$dkimkeyfn" ] ; then
		dkim_setoptions "$DKIMSIGNOPTIONS"
		exec 0<$tmpfn
		eval $dkimopts
		if [ $? -ne 0 ] ; then
			/bin/rm -f $tmpfn
			echo "$prefix/bin/dkim failed" 1>&2
			exit 1
		fi
	fi
	if [ -n "$DKIMSIGNEXTRA" ] ; then
		set_selector "dkim" "$DKIMSIGNEXTRA"
		dkim_setoptions "$DKIMSIGNOPTIONSEXTRA"
		if [ -n "$dkimkeyfn" -a -f "$dkimkeyfn" ] ; then
			exec 0<$tmpfn
			eval $dkimopts
			if [ $? -ne 0 ] ; then
				/bin/rm -f $tmpfn
				echo "$prefix/bin/dkim failed" 1>&2
				exit 1
			fi
		fi
	fi
fi
if [ $dkimverify -eq 1 ] ; then
	practice=$SIGN_PRACTICE
	if [ " $practice" = " " ] ; then
		practice=0
	elif [ " $practice" = " ssp" ] ; then
		practice=1
	elif [ " $practice" = " adsp" ] ; then
		practice=2
	fi
	exec 0<$tmpfn
	dkimvargs="-p $practice"
	if [ -n "$UNSIGNED_SUBJECT" ] ; then
		dkimvargs="$dkimvargs -S"
	fi
	if [ -n "$UNSIGNED_FROM" ] ; then
		dkimvargs="$dkimvargs -f"
	fi
	if [ -n "$VERBOSE" ] ; then
		dkimvargs="$dkimvargs -V"
	fi
	if [ -n "$SELECTOR_DATA" ] ; then
		$prefix/bin/dkim $dkimvargs -v -T "$SELECTOR_DATA"
	else
		$prefix/bin/dkim $dkimvargs -v
	fi
	ret=$?
	case $ret in
		14) # permanent error
		/bin/rm -f $tmpfn
		exit 100
		;;
		88) # temporary error
		/bin/rm -f $tmpfn
		exit 111
		;;
	esac
	if [ $ret -lt 0 ] ; then
		echo "$prefix/bin/dkim failed" 1>&2
		/bin/rm -f $tmpfn
		exit 1
	fi
fi
exec 0<$tmpfn
/bin/rm -f $tmpfn
/bin/cat
exit $?
#
# $Log: dk-filter.sh,v $
# Revision 1.37  2023-02-17 20:17:51+05:30  Cprogrammer
# set environment variables from dkimkeys
#
# Revision 1.36  2023-02-13 10:07:28+05:30  Cprogrammer
# removed yahoo domainkeys
#
# Revision 1.35  2023-02-12 18:17:21+05:30  Cprogrammer
# use VERBOSE variable to turn on debug for signature verification status on fd 2
#
# Revision 1.34  2023-02-05 20:59:55+05:30  Cprogrammer
# fixed temp files not removed for private key not found
#
# Revision 1.33  2023-02-02 17:30:12+05:30  Cprogrammer
# refactored for multi-signature generation
#
# Revision 1.32  2023-01-26 22:26:01+05:30  Cprogrammer
# removed setting redundant -b option
#
# Revision 1.31  2022-11-09 20:15:17+05:30  Cprogrammer
# replaced deprecated egrep with grep -E
#
# Revision 1.30  2022-10-02 22:15:23+05:30  Cprogrammer
# don't treat missng private key as error when DKIMSIGN has %
#
# Revision 1.29  2022-09-28 15:26:32+05:30  Cprogrammer
# remove '%' from filename if dkim key file not found
#
# Revision 1.28  2021-08-28 23:15:40+05:30  Cprogrammer
# control file dkimkeys for domain specific private key, selector
#
# Revision 1.27  2020-07-30 11:29:04+05:30  Cprogrammer
# Use BOUNCEDOMAIN only for bounces
#
# Revision 1.26  2020-04-11 08:41:50+05:30  Cprogrammer
# renamed DKIMDOMAIN to BOUNCEDOMAIN
#
# Revision 1.25  2020-04-09 22:25:01+05:30  Cprogrammer
# exec cat if both NODDK and NODKIM are defined
#
# Revision 1.24  2020-04-09 21:42:09+05:30  Cprogrammer
# added variables NODK, NODKIM to disable domainkeys, dkim
#
# Revision 1.23  2019-06-26 18:39:43+05:30  Cprogrammer
# use DEFAULT_DKIM_KEY env variable for default signing key
#
# Revision 1.22  2019-06-24 23:19:57+05:30  Cprogrammer
# added code for -d option in DKIMSIGNOPTIONS
#
# Revision 1.21  2019-01-14 00:10:00+05:30  Cprogrammer
# added -S, -f option to verify signatures with unsigned subject, unsigned from
#
# Revision 1.20  2017-03-09 16:38:15+05:30  Cprogrammer
# FHS changes
#
# Revision 1.19  2016-05-17 23:11:42+05:30  Cprogrammer
# fix for configurable control directory
#
# Revision 1.18  2014-03-12 08:50:48+05:30  Cprogrammer
# bug - fixed signing when env variables DKSIGN or DKIMSIGN were set
#
# Revision 1.17  2013-09-03 23:04:30+05:30  Cprogrammer
# set signing as default if both DKSIGN and DKIMSIGN are not defined
#
# Revision 1.16  2013-08-17 15:59:21+05:30  Cprogrammer
# do not treat duplicate DomainKey-Signature as an error
#
# Revision 1.15  2013-08-17 15:02:06+05:30  Cprogrammer
# fixed syntax errors and private key lookup
#
# Revision 1.14  2011-02-10 22:47:01+05:30  Cprogrammer
# fixed exit code of dk-filter when doing verification
#
# Revision 1.13  2011-02-08 22:02:29+05:30  Cprogrammer
# use sender domain when replacing '%' in private key
#
# Revision 1.12  2010-05-04 08:37:42+05:30  Cprogrammer
# do DK signing before DKIM signing to prevent DK_SYNTAX error
#
# Revision 1.11  2009-12-10 19:25:13+05:30  Cprogrammer
# added RCS id
#
# Revision 1.10  2009-12-10 16:41:14+05:30  Cprogrammer
# continue of message gives DK_SYNTAX_ERR
#
# Revision 1.9  2009-05-04 10:30:32+05:30  Cprogrammer
# fixed argument expected error
#
# Revision 1.8  2009-04-21 20:42:44+05:30  Cprogrammer
# added check for dktest, dkim executables
#
# Revision 1.7  2009-04-20 10:06:58+05:30  Cprogrammer
# added DKSIGNOPTS
#
# Revision 1.6  2009-04-19 13:38:24+05:30  Cprogrammer
# added full set of dkim options
# replaced indimail/bin/echo with echo 1>&2
#
# Revision 1.5  2009-04-06 16:37:50+05:30  Cprogrammer
# added SIGN_PRACTICE
# use ietf standard insted of allman so that Yahoo verification does not fail
#
# Revision 1.4  2009-04-03 14:39:00+05:30  Cprogrammer
# added return status
#
# Revision 1.3  2009-04-03 08:55:29+05:30  Cprogrammer
# print error messages to stderr
#
# Revision 1.2  2009-04-02 20:36:25+05:30  Cprogrammer
# added -h option to dktest
# added -x - option to dkim
#
# Revision 1.1  2009-04-02 14:52:27+05:30  Cprogrammer
# Initial revision
