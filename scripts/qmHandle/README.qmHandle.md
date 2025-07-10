# qmHandle

Copyright 1998-2003 Michele Beltrame
Modified by Chan Chung Hang Christopher (June, 2007)

Intro
-----

This is a simple perl script that helps you to view and manage (within some
limits) the qmail queue.

With this script you can:

  * Read the qmail queue, like you do with the qmail-qread program. However,
    the output of this script provides more information compared to qmail-qread such as 
    the message subject and color capabilities.
  * Print queue statistics, similar to qmail-qstat, with color capabilities
  * View a message in the queue.
  * Remove a message from the queue.
  * Remove messages that meet a criterion.
  * Tell qmail to slot messages with recipients in a remote domain for earlier retry (at the cost of longer queue stay).


Configuration
-------------

There are only a few variables to configure, and this has to be done depending
on your system and qmail installation. You can find the variables at the top of
the Perl script qmHandle (there's a configuration section properly marked).
The variables are:

1) `my ($queue) = '/var/qmail/queue/';`  
This is the path of your qmail queue directory. It's located here on 99.9%
of qmail installation. If yours seems not to be there, try using the "find"
command to locate it.

2) `my ($stopqmail) = '/etc/init.d/qmail stop';`  
This is the name of the script/command which stops qmail. The one you
see works on Debian GNU/Linux, if you have other you need to change it.
In the script configuration section you'll find some examples of
common options, including the one using DJB's daemontools. If you
don't have any script to stop qmail, you *must leave this string
empty*:  
	$stopqmail = '';

3) `my ($startqmail) = "/etc/init.d/qmail start";`  
This is the name of the script/command which stops qmail. The one you
see works on Debian GNU/Linux, if you have other you need to change it.
In the script configuration section you'll find some examples of
common options, including the one using DJB's daemontools and the
standard qmail distribution.

4) `my ($pidcmd) = 'pidof qmail-send';`  
This is the command used to obtain qmail process id. The default
should work on most Unix systems, but if on yours doesn't you can
change it.

Please note that variables from 2 to 4 are only needed to set properly
if you need to use qmHandle to delete messages in the queue. The first
one is however needed in any case.


Usage
-----

Usage is fairly simple. Here goes the help screen:

Available parameters are:
```
  -a       : try to send all queued messages now (qmail must be running)
  -l       : list message queues
  -L       : list local message queue
  -R       : list remote message queue
  -s       : show some statistics
  -mN      : display message number N
  -dN      : delete message number N
  -fsender : delete message from sender
  -F're'   : delete message from senders matching regular expression re
  -Stext   : delete all messages that have/contain text as Subject
  -h're'   : delete all messages with headers matching regular expression re (case insensitive)
  -b're'   : delete all messages with body matching regular expression re (case insensitive)
  -H're'   : delete all messages with headers matching regular expression re (case sensitive)
  -B're'   : delete all messages with body matching regular expression re (case sensitive)
  -xaddr   : delete all messages where recipient address matches 'addr' (To/Cc/Bcc)
  -X're'   : delete all messages where recipient address (To/Cc/Bcc) matching regular expression re
  -t're'   : flag messages with recipients in regular expression 're' for earlier retry (note: this lengthens the time message can stay in queue)
  -D       : delete all messages in the queue (local & remote)
  -V       : print program version
```
Additional (optional) parameters are:
```
  -c     : display colored output
  -N     : list message numbers only
           (to be used either with -l, -L or -R)
```

It's possible to specify multiple parameters for multiple actions, in any
order.

Please note that you'll have to be superuser (root) in order to use this
program.

A typical output of the command:

	qmHandle -l

could be:

```
143874 (9, R)
  Return-path: m.beltrame@betamag.com
  From: Michele Beltrame <m.beltrame@betamag.com>
  To: beta-reg@nice.it
  Subject: Re: [beta-reg] Server news pubblico.
  Date: Fri, 10 Apr 1998 09:04:32 +0200
  Size: 1600 bytes
```

The first line shows the number the message has in queue (the name of the
files in which it's stored) and, between parentheses, the directory number
where it's located and the queue he's in (L=local, R=remote).


GPL software
------------

This is open source software under the GPL (see 'GPL' file included in the
distribution). For more information on the license have a look at:

http://www.gnu.org

More info
---------
More info here https://notes.sagredo.eu/en/qmail-notes-185/qmhandle-20.html
