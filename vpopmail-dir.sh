#!/bin/sh
#
# Returns the vpopmail installation dir
# Roberto Puzzanghera - https://notes.sagredo.eu

# extract the vpopmail user from conf-users
VUSR=`head -9 conf-users | tail -1`

# cut path
CUT=""
for f in /bin/cut /usr/bin/cut /sbin/cut /usr/sbin/cut /usr/local/bin/cut /usr/local/sbin/cut
do
  if [ -x $f ]; then
    CUT=$f
    break
  fi
done
if [ "$CUT" = "" ]; then
  echo "/cut/binary/not/found"
  exit 1
fi

# getent path
GETENT=""
for f in /usr/bin/getent /bin/getent /usr/sbin/getent /sbin/getent /usr/local/bin/getent /usr/local/sbin/getent
do
  if [ -x $f ]; then
    GETENT=$f
    break
  fi
done
if [ "$GETENT" = "" ]; then
  echo "/getent/binary/not/found"
  exit 1
fi

VPOPMAILDIR=$($GETENT passwd $VUSR | $CUT -d: -f6)
if [ -d $VPOPMAILDIR ]; then
  echo $VPOPMAILDIR
elif [ -d /home/vpopmail ]; then
  echo "/home/vpopmail"
else
  echo "/vpopmail/dir/not/found"
  exit 1
fi

exit 0
