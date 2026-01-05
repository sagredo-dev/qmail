# qmail

[`qmail`](http://cr.yp.to/qmail.html) is a secure, reliable, efficient, simple message transfer agent. It is designed for typical Internet-connected UNIX hosts.
It was developed by [D. J. Bernstein](http://cr.yp.to/djb.html).

This `qmail` distribution is part of a [complete `qmail` guide](https://www.sagredo.eu/en/qmail-notes-185/qmail-vpopmail-dovecot-roberto-s-qmail-notes-8.html).
Not everything you need to know about `qmail` or its installation is covered here so, in case of issues in the installation, have a look at the link above.

This `qmail` package contains `chkuser`, which has [`vpopmail`](https://www.sagredo.eu/en/qmail-notes-185/installing-and-configuring-vpopmail-81.html) as a prerequisite,
while `vpopmail` itself requires to be installed over the vanilla `qmail`. So the compilation chain is [`netqmail`](https://www.sagredo.eu/en/qmail-notes-185/netqmail-106-basic-setup-42.html) > [`vpopmail`](https://www.sagredo.eu/en/qmail-notes-185/installing-and-configuring-vpopmail-81.html) > patched `qmail`.

If you are looking for a `qmail` variant without `chkuser` and `vpopmail` you can switch to the [specific branch](https://github.com/sagredo-dev/qmail/tree/no-chkuser-vpopmail)
where you can find this same `qmail` without `chkuser`.  
Download like this:  

```
git clone -b no-chkuser-vpopmail https://github.com/sagredo-dev/qmail.git
```

## `qmail` package details

This distribution of `qmail` puts together `netqmail-1.06` with the following patches:

* Erwin Hoffmann's qmail-authentication patch v. 0.8.3, which updates the patches provided
  by Krysztof Dabrowski and Bjoern Kalkbrenner.  
  It provides cram-md5, login, plain authentication support for qmail-smtpd and qmail-remote.  
  http://www.fehcom.de/qmail/smtpauth.html##PATCHES
* Frederik Vermeulen's qmail-tls patch v. 20231230  
  implements SSL or TLS encrypted and authenticated SMTP.  
  The key is now 4096 bit long and the cert will be owned by vpopmail:vchkpw  
  Patched to dinamically touch control/notlshosts/\<fqdn\> if control/notlshosts_auto contains any
  number greater than 0 in order to skip the TLS connection for remote servers with an obsolete TLS version (tx Alexandre Fonceca).  
  The file update_tmprsadh was modified to chown all .pem files to vpopmail.  
  http://inoa.net/qmail-tls/
* Marcel Telka's force-tls patch v. 2016.05.15  
  optionally gets qmail to require TLS before authentication to improve security.  
  You have to declare FORCETLS=0 if you want to allow the auth without TLS  
  https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06_force-tls/force-tls_marcel.patch
* Antonio Nati's chkuser patch v. 2.0.9  
  performs, among the other things, a check for the existence of recipients during the SMTP conversation,
  bouncing emails of fake senders.  
  http://opensource.interazioni.it/qmail/chkuser.html  
  Small adjustments and a bug fix by Luca Franceschini here https://www.sagredo.eu/files/qmail/patches/dmind/20190807/:  
  Now CHKUSER_DISABLE_VARIABLE, CHKUSER_SENDER_NOCHECK_VARIABLE, CHKUSER_SENDER_FORMAT_NOCHECK,
  CHKUSER_RCPT_FORMAT_NOCHECK and CHKUSER_RCPT_MX_NOCHECK can be defined at runtime level as well.  
  chkuser' MAV program has been modified in order to be compliant with EAI (RFC 5336 SMTP Email Address Internationalization).  
  More info [here](https://www.sagredo.eu/en/qmail-notes-185/email-address-internationalization-for-qmail-mav-from-chkuser-modified-accordingly-308.html)
* Flavio Curti's qmail-queue-custom-error patch  
  enables simscan and qmail-kim to return the appropriate message for each e-mail it refuses to deliver.  
  https://www.sagredo.eu/files/qmail/patches/qmail-queue-custom-error-v2.netqmail-1.05.patch
* Christophe Saout's qmail-SPF rc5 patch  
  Modified by Manvendra Bhangui to make it IPv4-mapped IPv6 addresses compliant.  
  checks incoming mails inside the SMTP daemon, add Received-SPF lines and optionally block undesired transfers.  
  http://www.saout.de/misc/spf/
* Marcelo Coelho's qmail-SRS patch  
  implements Sender Rewriting Scheme fixing SPF break upon email forwarding.  
  http://www.mco2.com.br/opensource/qmail/srs/
* Christopher K. Davis' oversize dns patch  
  enables qmail to handle large DNS packets.  
  https://www.sagredo.eu/files/qmail/patches/qmail-bigdns-103.patch
* Jul's reread-concurrency v.2 patch  
  rereads control/concurrencylocal and control/concurrencyremote files when qmail-send receives a HUP signal.  
  http://js.hu/package/qmail/index.html
* Johannes Erdfelt's Big Concurrency patch  
  sets the spawn limit above 255  
  https://www.sagredo.eu/files/qmail/patches/big-concurrency.patch
* Bill Shupp's netqmail-maildir++.patch  
  adds maildirquota support to qmail-pop3d and qmail-local.  
  Fixed a bug where the filesize part of the S=<filesize> component of the Maildir++ compatible filename
  is wrong (tx MG). More info here:
  https://www.sagredo.eu/en/qmail-notes-185/installing-dovecot-and-sieve-on-a-vpopmail-qmail-server-28.html#comment995  
  https://www.sagredo.eu/files/qmail/patches/netqmail-maildir.patch
* Kyle B. Wheeler's "Better qmail-smtpd Logging" v.5 patch  
  facilitates diagnostics of qmail-smtpd logging its actions and decisions (search for a line with qmail-smtp:)  
  http://www.memoryhole.net/qmail/#logging
* John Simpson's (?) Greeting delay patch  
  adds a user-definable delay after SMTP clients have initiated SMTP sessions, prior to qmail-smtpd responding
  with "220 ESMTP". It can reject connections from clients which tried to send commands before greeting.  
  https://www.sagredo.eu/files/qmail/patches/qmail-greetdelay.patch  
  [Andreas Gerstlauer](https://www.sagredo.eu/en/qmail-notes-185/upgrading-qmail-82.html#comment4597) fixed a bug
  where qmail-smtpd crashes if SMTPD_GREETDELAY is defined with no DROP_PRE_GREET defined.
* Manvendra Bhangui's DKIM and SURBL filter v.1.48 patch  
  adds DKIM signing & verification and SURBL filtering support to qmail.  
  qmail-dk is based on Russ Nelson's patch: http//:www.qmail.org/qmail-1.03-dk-0.54.patch  
  qmail-dkim uses hacked libdkim libraries from libdkim project at http://libdkim.sourceforge.net/  
  surbfilter is built on djb functions and some functions have been ruthlessly borrowed from qmail surbl
  interface by Pieter Droogendijk and the surblhost program at http://surblhost.sourceforge.net/  
  (file hier.c modified to chown /var/qmail/control/cache and subdirs to vpopmail)  
  http://sourceforge.net/projects/indimail/files/netqmail-addons/qmail-dkim-1.0/  
  https://www.sagredo.eu/files/qmail/patches/ANNOUNCE.surblfilter
* Claudio Jeker and Andre Oppermann's EXTTODO patch (release 5. Jan. 2003)  
  addresses a problem known as the silly qmail (queue)  problem  
  https://www.sagredo.eu/files/qmail/patches/exttodo.README  
  https://www.sagredo.eu/files/qmail/patches/ext_todo-20030105.patch
* Russell Nelson's big-todo patch  
  makes qmail use a hashing mechanism in the todo folder similar to that used in the rest of the queue  
  https://www.sagredo.eu/files/qmail/patches/big-todo.103.patch
* Stephane Cottin's qmail-inject-null-sender patch (let's call it in this way)  
  prevents qmail-inject from rewriting the null sender, fixing an issue with sieve vacation/reject messages.  
  More info here: http://www.dovecot.org/list/dovecot/2009-June/040811.html  
  https://www.sagredo.eu/files/qmail/patches/qmail-inject-null-sender.patch
* Russell Nelson's (modified by Charles Cazabon) doublebounce-trim patch, which updates the original
  version by Russel Nelson  
  prevents double bounces from hitting your queue a second time provided that you delete the first line
  from /var/qmail/control/doublebounceto  
  https://www.sagredo.eu/files/qmail/patches/doublebounce-trim.patch
* Inter7's qmail-taps-extended patch  
  https://www.sagredo.eu/files/qmail/patches/qmail-tap.diff  
  Extended by Michai Secasiu (http://patchlog.com/patches/qmail-taps-extended/)  
  Provides the ability to archive each email that flows through the system.  
  Archiving only messages from or to certain email addresses is possible as well.  
  https://www.sagredo.eu/files/qmail/patches/qmail-taps-extended-full.patch
* Andy Repton's outgoingip patch (adjusted by Sergio Gelato)  
  by default all outgoing emails are sent through the first IP address on the interface. In case of a multiple
  IP server this patch makes qmail send outgoing emails with the IP eventually stored in control/outgoingip.  
  The ehlo domain is NOT modified by this patch.  
  https://www.sagredo.eu/files/qmail/patches/outgoingip.patch  
  Robbie Walker provided a patch to correct qmail-qmqpc.c's call to timeoutconn(), because the function
  signature was modified by the original outgoingip patch  
  https://www.sagredo.eu/en/qmail-notes-185/patching-qmail-82.html#comment373
* Matthias Andree's qmail-rfc2821 patch  
  makes qmail rfc2821 compliant  
  https://www.sagredo.eu/files/qmail/patches/qmail-1.03-rfc2821.diff  
  Ali Erturk TURKER added implicit TLS (SMTPS) support  
  https://www.sagredo.eu/files/qmail/patches/aet_qmail_remote_smtps_correction_202302271346.patch
* Jonathan de Boyne Pollard's smtpd-502-to-500 patch  
  makes qmail rfc2821 compliant  
  https://www.sagredo.eu/files/qmail/patches/smtpd-502-to-500.patch
* Fabio Busatto's qmail-dnsbl patch  
  allows you to reject spam and virus looking at the sender's ip address.  
  Modified by Luca Franceschini to add support for whitelists, TXT and A queries, configurable return codes
  451 or 553 with custom messages  
  http://qmail-dnsbl.sourceforge.net/
* Scott Gifford's qmail-moreipme patch v. 0.6  
  prevents a problem caused by an MX or other mail routing directive instructing qmail to connect to
  itself without realizing it's connecting to itself, saving CPU time.  
  https://www.sagredo.eu/files/qmail/patches/moreipme.README  
  https://www.sagredo.eu/files/qmail/patches/qmail-1.03-moreipme-0.6.patch
* Alex Nee's qmail-hide-ip-headers patch  
  It will hide your Private or Public IP in the email Headers when you are sending Mail as a Relay Client.  
  I upgraded the patch in order to hide also the sender's hostname when the sender is RELAYCLIENT or is  
  authenticated.
  - [original patch](https://www.sagredo.eu/files/qmail/patches/qmail-hide-ip-headers.patch)
  - [patch upgrade commit](https://github.com/sagredo-dev/qmail/commit/785e84b8715ee5a4c36193e1f0b0108d82f7c028)
  
* John Saunders' qmail-date-localtime patch  
  causes the various qmail programs to generate date stamps in the local timezone.  
  https://www.sagredo.eu/files/qmail/patches/qmail-date-localtime.patch
* Dean Gaudet's qmail-liberal-lf patch v. 0.95  
  allow qmail-smtpd to accept messages that are terminated with a single \n instead of the required \r\n
  sequence.  
  http://www.arctic.org/~dean/patches/qmail-0.95-liberal-lf.patch  
  Disabled by default due to smuggling vulnerability (CVE-2023-51765 https://nvd.nist.gov/vuln/detail/CVE-2023-51765).  
  Enable bare LF by defining ALLOW_BARELF in tcprules.
* Michael Samuel's maxrcpt patch  
  allows you to set a limit on how many recipients are specified for any one email message by setting
  control/maxrcpt. [RFC 2821 section 4.5.3.1](https://datatracker.ietf.org/doc/html/rfc2821#section-4.5.3.1)
  says that an MTA MUST allow at least 100 recipients for each message, since this is one of the favourite
  tricks of the spammer. If DISABLE_MAXRCPT is defined it skips the check, as outgoing messages from mailing
  lists would be rejected otherwise.  
  https://www.sagredo.eu/files/qmail/patches/maxrcpt.patch
* Inter7's qmail-eMPF patch  
  More info: https://www.sagredo.eu/files/qmail/patches/empf.README  
  eMPF follows a set of administrator-defined rules describing who can message whom.  With this,
  companies can segregate various parts of their organizations email activities, as well as provide a
  variety of security-enhancing services.  
  https://www.sagredo.eu/files/qmail/patches/qmail-empf.patch
* qregex (by  Andrew St. Jean http://www.arda.homeunix.net/downloads-qmail/, contributors: Jeremy Kitchen,
  Alex Pleiner, Thanos Massias. Original patch by Evan Borgstrom)  
  adds the ability to match address evelopes via Regular Expressions (REs) in the qmail-smtpd process.  
  Added new control file 'badhelonorelay', control/badmailto renamed control/badrcptto (Tx Luca Franceschini).
* brtlimit  
  Luca Franceschini derived this patch from https://www.sagredo.eu/files/qmail/patches/goodrcptto-12.patch  
  added control/brtlimit and BRTLIMIT variable to limit max invalid recipient errors before closing
  the connection (man qmail-control)
* validrcptto  
  https://www.sagredo.eu/files/qmail/patches/validrcptto.README  
  Luca Franceschini grabbed the code from several patches with additional features:  
  http://qmail.jms1.net/patches/validrcptto cdb.shtml,  
  https://www.sagredo.eu/files/qmail/patches/goodrcptto-ms-12.patch,  
  http://patch.be/qmail/badrcptto.html  
  It works in conjunction with chkuser with both cdb and mysql accounts.
* reject-relay-test by Russell Nelson  
  It gets qmail to reject relay probes generated by so-called anti-spammers. These relay probes have
  '!', '%' and '@' in the local (username) part of the address.  
  https://www.sagredo.eu/files/qmail//patches/qmail-smtpd-relay-reject.patch
* Luca Franceschini  
  added DISABLETLS environment variable, useful if you want to disable TLS on a desired port  
  added FORCEAUTHMAILFROM environment variable to REQUIRE that authenticated user and 'mail from' are identical  
  added SMTPAUTHMETHOD, SMTPAUTHUSER and SMTP_AUTH_USER env variables for external plugins (see
  http://qmail-spp.sourceforge.net/doc/)
* fixed little bug in 'mail from' address handling  
  patch by Andre Opperman at http://qmail.cr.yp.narkive.com/kBry6GJl/bug-in-qmail-smtpd-c-addrparse-function
* Luca Franceschini's qlog patch  
  smtpd logging with fixed format. An entry 'qlogenvelope' is generated after accepting or rejecting
  every recipients in the envelope phase.
* Luca Franceschini's reject null senders patch  
  useful in special cases if you temporarily need to reject the null sender (although breaks RFC compatibility).  
  You just need to put 1 (actually any number different from 0) in your control/rejectnullsenders or define
  REJECTNULLSENDERS to reject the null sender with 421 error message.
* Luca Franceschini's remove-cname-check patch  
  Removed dns_cname call in qmail-remote.c instead of changing the funcion in dns.c,in case another
  patch requires dns_cname().  
  https://www.sagredo.eu/files/qmail/patches/remove-cname-check.patch  
  More info here https://lists.gt.net/qmail/users/138190
* Jonathan de Boyne Pollard's any-to-cname patch  
  avoids qmail getting large amounts of DNS data we have no interest in and that may overflow our response
  buffer.  
  https://www.sagredo.eu/files/qmail/patches/any-to-cname.patch
* Luca Franceschini's rcptcheck patch  
  (based on original patch from Jay Soffian (http://www.soffian.org/downloads/qmail/qmail-smtpd-doc.html)  
  Originally designed for the purpose of receipt validation, it can also be used to limit the numbr of
  email a given IP and/or auth-user and/or domain can send in a given time interval. It has to be used
  in conjuction with the rcptcheck-overlimit.sh LF's script  
  https://www.sagredo.eu/files/qmail/rcptcheck-overlimit.sh  
  https://www.sagredo.eu/files/qmail/patches/rcptcheck.patch
* Reed Sandberg's qmail-channels patch  
  Allows you to add an arbitrary number of supplemental remote queues, each distinguished by a list of
  recipient domains and separate throttling (concurrency) capabilities. This patch also allows dynamic
  throttling of the concurrency control files so you can just send qmail-send a HUP signal instead of
  restarting the service every time.  
  This patch is useful when some email providers complain of too many emails receveid at the same time
  (in case of news letters for instance). Look here for more info
  https://www.sagredo.eu/en/qmail-notes-185/patching-qmail-82.html#comment1328  
  Edit conf-channels before compiling: Total number of channels (queues) available for delivery. Must be at
  least 2, and anything above 2 are considered supplemental channels.  
  http://www.thesmbexchange.com/eng/qmail-channels_patch.html
* Endersys R&D team's qmail-remote-logging patch  
  gets qmail-remote to log sender, recipient and IP adddress all together in the "Delivery success/failure" line
  https://web.archive.org/web/20120530051612/http://blog.endersys.com/2009/12/qmail-canonicalised-recipient-logging-and-more-patch/
* notqmail.org's cve-2005-1513 patch  
  addresses a vulnerability issue spotted by Georgi Guninski in 2005  
  https://www.qualys.com/2020/05/19/cve-2005-1513/remote-code-execution-qmail.txt
* Pawel Foremski's qmail-spp patch v. 0.42, which provides plug-in support for qmail-smtpd. It allows you to
  write external programs and use them to check SMTP command argument validity. The plug-in can trigger
  several actions, like denying a command with an error message, logging data, adding a header and much more.  
  The qmail-spp functionality is disabled by default, so that it will be transparent for ancient users of
  this patch. If you want to enable qmail-spp just export the variable ENABLE_SPP in your run file. Note that
  the variable NOSPP is not available here.  
  More info here http://qmail-spp.sourceforge.net
* Bruce Guenter's qmail-1.03-fastremote-3 patch  
  While sending individual messages with qmail consumes very little CPU, sending multiple large messages in parallel can
  effectively DoS a sender due to inefficiencies in qmail-remote's "blast" function. In its original form, this
  function scans the message one byte at a time to escape leading periods and newlines, as required by SMTP.  
  This patch modifies blast to scan the message in larger chunks. I have benchmarked before and after, and the change
  reduced the CPU time consumed by qmail-remote by a factor of 10.  
  http://untroubled.org/qmail/qmail-1.03-fastremote-3.patch  
  Added a fix for CRLF by [Andreas Gerstlauer](https://www.sagredo.eu/en/qmail-notes-185/upgrading-qmail-82.html#comment4593)
* [Arnt Gulbrandsen's smtputf8](https://github.com/arnt/qmail-smtputf8/tree/smtputf8-tls)  
  adds [RFC 5336](https://datatracker.ietf.org/doc/html/rfc5336) SMTP Email Address Internationalization support  
  - [Pull Request](https://github.com/sagredo-dev/qmail/pull/13)  
  - More info [here](https://www.sagredo.eu/en/qmail-notes-185/email-address-internationalization-for-qmail-mav-from-chkuser-modified-accordingly-308.html)
* [Andreas Gerstlauer](https://github.com/sagredo-dev/qmail/commit/f913e6da84cbab29608fc5342f1c88d29a2c12e2)'s
  Authentication-Results: header support

Install
-----

As already mentioned, this package has `vpopmail` as a prerequisite. Also it is intended that you already have
created the `qmail` users as explained [here](https://www.sagredo.eu/en/qmail-notes-185/netqmail-106-basic-setup-42.html).

This package requires the [`libidn2`](https://gitlab.com/libidn/libidn2) (GNU Internationalized Domain Name
library version 2, `libidn2-dev` on `Debian` like OS) library.

* Install libsrs2
```
wget https://www.sagredo.eu/files/qmail/tar/libsrs2-1.0.18.tar.gz
tar xzf libsrs2-1.0.18.tar.gz
cd libsrs2-1.0.18
./configure
make
make install
ldconfig
cd ../
```

* Download

Download the latest release from the [github repo](https://github.com/sagredo-dev/qmail/releases).

* Compile and install

`FreeBSD` doesn't have the libresolv.so library, which is not needed there to compile.  
Before compiling, `FreeBSD` users have to leave the very first line of the file _conf-lib_ blank  
or delete that file.

Compile and install:

```
make setup check
```

* Configure

```
./config-all <mxmydomain.tld>
```

* You have to export `SMTPAUTH` in your run file if you want to do the auth
* You have to export `SURBL=1` in your run file if you want to enable `SURBL`
* _/var/qmail/control/cache_ must be owned by the user who runs `qmail-smtpd`, `vpopmail:vchkpwd` in my case.
  Change the permissions according to your qmail configuration.

Info and support
----------------
You can find more info and ask for support [here](https://www.sagredo.eu/en/qmail-notes-185/patching-qmail-82.html).
