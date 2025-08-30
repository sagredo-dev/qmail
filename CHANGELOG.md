# ChangeLog

- unreleased
  - Fixes in SPP handling and support for [pass] plugins after RCPT accept.  
    Support for RBLRESULT environment variable and RBL ignore ('=') option.  
    ([tx Andreas Gerstlauer](https://github.com/sagredo-dev/qmail/commit/76b6306a40131cfc999457c247838e50cbb585c7))
  - Added -std=gnu17 to conf-cc, fixed some other issues and now it compiles on gcc-15.2

- Jul 10, 2025
  - Authentication-Results: header support ([Andreas Gerstlauer](https://github.com/sagredo-dev/qmail/commit/f913e6da84cbab29608fc5342f1c88d29a2c12e2))
  - DKIM: added ERROR_FD=2 in control/filterargs to send error output of qmail-dkim in stderr when acting
    as a qmail-remote filter ([Andreas Gerstlauer](https://www.sagredo.eu/en/qmail-notes-185/configuring-dkim-for-qmail-92.html#comment4607))
  - improved qmail-dkim error reporting when signing outgoing messages ([Andreas Gerstlauer](https://www.sagredo.eu/en/qmail-notes-185/configuring-dkim-for-qmail-92.html#comment4639))
  - helodnscheck.cpp: qmail dir determined dinamically
  - qmHandle: Add -x and -X parametr for remove email by To/Cc/Bcc (by [Stetinac](https://github.com/sagredo-dev/qmHandle/pull/1))
  - Added a cronjob for `rcptcheck-overlimit` that only removes cases that didn't exceed the limit, i.e. enforces a permanent ban ([tx Andreas Gerstlauer](https://github.com/sagredo-dev/qmail/commit/3ea54851acf4ff6d405b9e404e3f1fce9242d445))

- Jun 17, 2025
  - Fix for missing end of line in helodnscheck.cpp ([tx Andreas Gerstlauer](https://github.com/sagredo-dev/qmail/commit/a144829980fe1834d9b33ddc674b43e523d6d69f))

- Jun 8, 2025
  - CRLF fix for fastremote-3 patch ([thanks Andreas Gerstlauer](https://www.sagredo.eu/en/qmail-notes-185/upgrading-qmail-82.html#comment4593))
  - Bug fix to the greetdelay program ([thanks Andreas Gerstlauer](https://www.sagredo.eu/en/qmail-notes-185/upgrading-qmail-82.html#comment4597))  
    qmail-smtpd crashes if SMTPD_GREETDELAY is defined with no DROP_PRE_GREET defined.
  - turned off TLS and helo dns check on qmail-smtpsd/run script (tx Luis)

- Apr 25, 2025
  - added a configuration script [config-all.sh](https://github.com/sagredo-dev/qmail/blob/main/config-all.sh),
    which configure and installs the following:
    - main control files as per original `config-fast `script,
    - aliases,
    - RBL
    - SPF
    - SRS (uses _control/me_ as the _srs_domain_),
    - log dirs in _/var/log/qmail_, 
    - cronjobs
    - logrotate
    - PATH and MANPATH in _/etc/profile.d/qmail.sh_
    - tcprules (basic, just to make initial tests), 
    - supervise scripts, 
    - `qmailctl` script, 
    - DKIM _control/filterargs_ and _control/domainkeys_ dir, 
    - SURBL, 
    - moreipme,
    - overlimit feature
    - smtpplugins, 
    - `helodnscheck` spp plugin, 
    - `svtools`, 
    - `qmHandle`, 
    - `queue-repair`, 
    - SSL key file (optional)

Running `./config-all mx.mydomain.tld` after the compilation will get the `qmail` installation ready for testing.  
Those who prefer to manually configure everything can stick with the original `config-fast` script, which now copies
my supervise scripts to the _qmail/doc_ dir.  
Consider this feature as testing.

- Feb 11, 2025
  - Several adjustments to get freeBSD and netBSD compatibility. More info in the commit history.
    Hints/comments are welcome.
  - freeBSD users have to comment out the "LIBRESOLV" variable from the very beginning of the
    Makefile, as libresolv.so in not needed on freeBSD.
  - Dropped files install-big.c, idedit.c and BIN.* files.
  - Dropped files byte_diff.c, str_cpy.c, str_diff.c, str_diffn.c and str_len.c, which break compilation
    on clang and can be replaced by the functions shipped by the compiler (tx notqmail).
  - Old documentation moved to the "doc" dir. install.c and hier.c modified accordingly
  - conf-cc and conf-ld now have -L/usr/local/lib and -I/usr/local/include to look for srs2 library
  - conf-cc and conf-ld now have -L/usr/pkg/lib and -I/usr/pkg/include to satisfy netBSD
  - vpopmail-dir.sh: minor correction to vpopmail dir existence check
  - srs.c: #include <srs2.h> now without path

- Dec 01, 2024
  - Added support for EAI ([RFC 5336](https://datatracker.ietf.org/doc/html/rfc5336) SMTP Email Address Internationalization)
    (https://github.com/sagredo-dev/qmail/pull/13).  
    Thanks to https://github.com/arnt/qmail-smtputf8/tree/smtputf8-tls.
  - chkuser is now smtputf8 compliant. It accepts utf8 characters in sender and recipient addresses provided that the
    remote server advertises the SMTPUTF8 verb in MAIL FROM, otherwise it allows only ASCII characters plus additional
    chars from the CHKUSER_ALLOWED_CHARS set.  More info [here](https://www.sagredo.eu/en/qmail-notes-185/email-address-internationalization-for-qmail-mav-from-chkuser-modified-accordingly-308.html)  
    - dropped variables CHKUSER_ALLOW_SENDER_CHAR_xx CHKUSER_ALLOW_RCPT_CHAR_xx (replaced by CHKUSER_ALLOWED_CHARS)
    - dropped variables CHKUSER_ALLOW_SENDER_SRS and CHKUSER_ALLOW_RCPT_SRS, as we are always accepting '+' and '#' characters
    - added variables CHKUSER_INVALID_UTF8_CHARS and CHKUSER_ALLOWED_CHARS  
  - fixed compilation warnings due to deprecated SSL_CTX_use_RSAPrivateKey_file and SSL_use_RSAPrivateKey_file functions

- Oct 26, 2024
  - qmail-remote.c patched to dinamically touch control/notlshosts/\<fqdn\> if control/notlshosts_auto contains any
    number greater than 0 in order to skip the TLS connection for remote servers with an obsolete TLS version.  
    (tx Alexandre Fonceca)
  - fixed several compilation breaks/warnings on later gcc compilers (tx Pablo Murillo)
  - invalid auth fix in qmail-smtpd.c's smtp_auth function (tx Alexandre Fonceca for the advice)
  - qmail path determined dinamically in conf-policy
  - added a patch to remove chkuser and the vpopmail dependency (other-patches dir)

- Jun 8, 2024
  - conf-channels: default number of channels increased to 4 (was 2). Now qmail offers 2 additional channels
    with respect to the 2 offered by default (local and remote). More info [here](https://github.com/sagredo-dev/qmail/blob/main/CHANNELS).
  - maxrcpt: error code changed to 452 due to RFC 4.5.3.1 (was 553). If DISABLE_MAXRCPT is defined it skips the check,
    otherwise outgoing messages from mailing lists would be rejected. ([commit](https://github.com/sagredo-dev/qmail/commit/87fac634ddf3f4eb09d5fdc45e1a8bc4c10de2f9))

- May 16, 2024
  - DKIM: Make the dkimsign binary _not_ derive the "d=" domain value from the Return-Path header ([tx mpdude](https://github.com/sagredo-dev/qmail/pull/5))
  - Fixed -Wstringop-overflow on qmail-start.c line 128 (gcc-13.2) ([commit](https://github.com/sagredo-dev/qmail/commit/e5af0129bae6d19525ba8a2e750b9264139739c6))
  - Fixed -Wincompatible-pointer-types compilation warnings onsubstdio.h ([commit](https://github.com/sagredo-dev/qmail/commit/67bdb4bc109ef628733039270ab25daece4afe8c))
  - Big Concurrency fix patch removed, as it is incompatible with the above change.
  - Create a trigger to decide if your qmail-smtpd instance should respect badmailfrom regex or not. This could be very handling if you decide to have very
    strict rules for your qmail-smtpd that you don´t want to be applied to qmail-submission. Usage: add export DISABLE_BADMAILFROM=1 to run file service
    [tx brdelphus](https://github.com/sagredo-dev/qmail/pull/4)

- Feb 12, 2024
  - DKIM patch upgraded to v. 1.48
    - fixed minor bug using filterargs for local deliveries [diff](https://github.com/sagredo-dev/qmail/commit/2550509ec15049dfae09c3d27b5c4daf8ad1f644)
  - Fixed several compilation warnings [diff](https://github.com/sagredo-dev/qmail/commit/2e0095be3ede7e1e3091d9890d087a3ed16b8fb7)
  - Fixed incompatible redeclaration of library function 'log2' in qmail-send.c qsutil.c as showed by @notqmail friends [here](https://github.com/notqmail/notqmail/commit/c3d3c72e3ca7bb5102f710aad7bf9ab105bde27e)
  - removed FILES, shar target from Makefile

- Feb 6, 2023
  - DKIM patch upgraded to v. 1.47
    - fixed a bug which was preventing filterargs' wildcards to work properly on sender domain

- Jan 20, 2024 [diff](https://github.com/sagredo-dev/qmail/pull/2/commits/3caabe095eae6ab74508b3d56a0398f64a4a5c73)
  - liberal-lf: bare LF no longer allowed due to smuggling vulnerability ([CVE-2023-51765](https://nvd.nist.gov/vuln/detail/CVE-2023-51765)). Enable bare LF by defining ALLOW_BARELF in tcprules or in run file.

- Jan 15, 2024
  - TLS patch by F. Vermeulen upgraded to version 20231230 (more info at https://inoa.net/qmail-tls/)
    - support to openssl 3.0.11

- Jan 10, 2024
  - DKIM patch upgraded to v. 1.46
    - dk-filter.sh has been dropped. If signing at qmail-remote level, before upgrading, you have to review the configuration as explained below.
    - The variables USE_FROM, USE_SENDER and DKIMDOMAIN have been dropped
    - when signing at qmail-remote level qmail-dkim now has to be called directly by spawn-filter in the rc file.
      - man spawn-filter for more info
    - In case of bounces the signature will be automatically based on the from: field. This will solve issues of DMARC reject by google in case of sieve/vacation bounces.
    - In case of ordinary bounces (mailbox not found, for instance) the bounce domain will be taken from control/bouncehost and, if doesn't exist, from control/me
    - More info [here](https://www.sagredo.eu/en/qmail-notes-185/configuring-dkim-for-qmail-92.html#signing_remote)

- Jan 6, 2024
  - DKIM patch upgraded to v. 1.45
    - if USE_SENDER is passed to dk-filter it will always retrieve the domain from _SENDER and not from the From field

- Jan 4, 2024
  - DKIM patch upgraded to v. 1.44
    - fixed an issue with filterargs where spawn-filter is trying to execute remote:env xxxxx.... dk-filter. This issue happens when FILTERARGS environment variable is not defined in the qmail-send rc script.
    - dkim.c fix: https://www.sagredo.eu/en/qmail-notes-185/configuring-dkim-for-qmail-92.html#comment3668
    - adjustments fo dk-filter and dknewkey man pages

- Dec 9, 2023
  - sources moved to https://github.com/sagredo-dev/qmail

- 2023.11.20
  - dkim:
    - The patch now by default excludes X-Arc-Authentication-Results
    - dkim can additionally use the environment variable EXCLUDE_DKIMSIGN to include colon separated list of headers to be excluded from signing (just like qmail-dkim). If -X option is used with dk-filter, it overrides the value of EXCLUDE_DKIMSIGN.

- 2023.09.26
  - surblfilter logs the rejected URL in the qmail-smtpd log. It can now inspect both http and https URLs.
  - Improvements in man dkim.9, qmail-dkim.9 and surblfilter.9

- 2023.09.05
  - DKIM patch upgraded to v. 1.42
    - dk-filter.sh: "source $envfn" has been replaced with ". $envfn" in oder to work for pure bourne shells
    - minor corrections to the man pages

- 2023.08.20
  - install a sample control/smtpplugins file in case it does not exist yet,
 to avoid "unable to read control" crash.
 diff https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2023.08.20_patch.diff

- 2023.07.05
  - vpopmail-dir.sh: now uses getent to gain compatibility with alpine/docker (tx BenV https://www.sagredo.eu/en/qmail-notes-185/patching-qmail-82.html#comment3345)
 https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2023.07.05_vpopmail-auto_patch.diff

- 2023.07.03
  - bug fix in vpopmail-dir.sh: it was not searching the sed binary in /bin/sed as it is at least on Ubuntu systems (tx Mike G)

- 2023.06.30
  - DKIM patch upgraded to v. 1.41
    - dknewkey will allow domains in control/domainkey 
    - Made a few adjustments to the man pages and dkimsign.cpp for DKIMDOMAIN to work with qmail-smtpd (in case some configures qmail-smtpd to sign instead
  of the usual dk-filter/qmail-remote)
    - The broken link based on pobox.com in the default SPF error explanation was changed to https://mxtoolbox.com/SuperTool.aspx?action=spf

- 2023.06.18
  - vpopmail install directory is determined dinamically by means of a shell script.
 Now the variable in the conf-cc file is determined as well
 Feel free to post any issue in the comments as I'm not sure that /bin/sh will work in all Linux.
 diff here https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2023.06.18_patch.diff

- 2023.06.04
  - vpopmail uid and gid are determined dinamically instead of assigning 89:89 ids by default
  - vpopmail install directory is determined dinamically
diff here https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2023.06.04_patch.diff

- 2023.04.26
  - dkim patch updated to v. 1.40
  - qmail-dkim uses CUSTOM_ERR_FD as file descriptor for errors (more info https://www.sagredo.eu/en/qmail-notes-185/configuring-dkim-for-qmail-92.html#comment3076)
 
- 2023.03.27
  - chkuser.c: double hyphens "--" are now allowed also in the rcpt email (tx Ali Erturk TURKER)
  - chkuser_settings.h CHKUSER_SENDER_NOCHECK_VARIABLE commented out. Sender check is now enabled also for RELAYCLIENT
  - removed a couple of redundant log lines caused by qmail-smtpd-logging
diff here https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2023.03.27_patch.diff

- 2023.03.18
  - bugfix in dkimverify.cpp: now it checks if k= tag is missing (tx Raisa for providing detailed info)
  - dropped redundant esmtp-size patch, as the SIZE check is already done by the qmail-authentication patch (tx Ali Erturk TURKER)
 diff here https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2023.03.18_patch.diff

- 2023.03.14
  - The split_str() function in dknewkey was modified in order to work on debian 11
 tx J https://www.sagredo.eu/en/qmail-notes-185/configuring-dkim-for-qmail-92.html#comment2922

- 2023.03.12
  - The mail headers will change from "ESMTPA" to "ESMTPSA" when the user is authenticated via starttls/smtps (tx Ali Erturk TURKER)
 diff here https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2023.03.12_patch.diff
 more info here https://marc.info/?l=qmail&m=118763997501287&w=2

- 2023.03.01
  - Added qmail-1.03-fastremote-3 qmail-remote patch (tx Ali Erturk TURKER for the advice)
 While sending individual messages with qmail consumes very little CPU, sending multiple large messages in parallel can effectively DoS a sender
 due to inefficiencies in qmail-remote's "blast" function. In its original form, this function scans the message one byte at a time to escape
 leading periods and newlines, as required by SMTP.
 This patch modifies blast to scan the message in larger chunks. I have benchmarked before and after, and the change reduced the CPU time
 consumed by qmail-remote by a factor of 10.
 http://untroubled.org/qmail/qmail-1.03-fastremote-3.patch
  - qmail-remote CRLF patch removed

- 2023.02.27
  - Now qmail-remote is rfc2821 compliant even for implicit TLS (SMTPS) connections (tx Ali Erturk TURKER)
 https://www.sagredo.eu/files/qmail/patches/aet_qmail_remote_smtps_correction_202302271346.patch

- 2023.02.24
  - several missing references to control/badmailto and control/badmailtonorelay files were corrected to control/badrcptto and control/badrcpttonorelay
 (tx Ali Erturk TURKER) diff here https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2023.02.24_patch.diff

- 2023.02.19
  - dkim patch upgraded to v. 1.37
    -  ed25519 support (RFC 8463)
    -  multiple signatures/selectors via the enhanced control/dkimkeys or DKIMSIGN / DKIMSIGNEXTRA / DKIMSIGNOPTIONS  DKIMSIGNOPTIONSEXTRA variables
    -  old yahoo's domainkeys stuff removed (no longer need the libdomainkeys.a library)
    -  man pages revised and enhanced
    -  domainkeys directory moved to /var/qmail/control/domainkeys

- 2023.01.31
  - bug fix in qmail-smtpd.c. 4096 bit RSA key cannot be open (tx Ali Erturk TURKER)
 more info here https://www.sagredo.eu/en/qmail-notes-185/patching-qmail-82.html#comment2758

- 2023.01.01
  - bug fix in dk-filter. It was calling a non existent function (tx Andreas).
 More info here:
 https://www.sagredo.eu/en/qmail-notes-185/configuring-dkim-for-qmail-92.html#comment2721

- 2022.12.17
  - chkuser receipt check won't be disabled for RELAYCLIENT
  - CHKUSER_DISABLE_VARIABLE commented out from chkuser_settings.h
 More info here https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2022.12.17_patch.diff

- 2022.10.01
  - dkim patch updated to v. 1.30
    - bug fix: it was returning an error in case of domains with no key. 

- 2022.09.28
  - dkim patch updated to v. 1.29 (tx M. Bhangui and Computerism for troubleshooting)
    - Custom selector via new control file /var/qmail/control/dkimkeys and DKIMKEY or DKIMSIGN variables
   More info here https://www.sagredo.eu/en/qmail-notes-185/configuring-dkim-for-qmail-92.html#selectors

- 2022.05.22
  - "qmail-smtpd pid, qp log" (http://iain.cx/qmail/patches.html#smtpd_pidqp) patch removed,
 as its log informations are already contained in the qlogreceived line.
  - improved a couple of read_failed error messages

- 2022.02.26
  - added REJECTNULLSENDERS env variable
 diff here https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2022.02.26_patch.diff

- 2022.02.10
  - Fixed a TLS Renegotiation DoS vulnerability. Disabled all renegotiation in TLSv1.2 and earlier.
 (https://blog.qualys.com/product-tech/2011/10/31/tls-renegotiation-and-denial-of-service-attacks)
 diff here https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2022.02.10_patch.diff

- 2022.01.17
  - now qmail-smtpd logs rejects when client tries to auth when auth is not allowed, or it's not allowed without TLS
 (a closed connection with no log at all appeared before).
  - added qmail-spp.o to the TARGET file so that it will be purged with "make clean".
 diff https://www.sagredo.eu/files/qmail//patches//roberto-netqmail-1.06//2022.01.17_patch.diff

- 2021.12.19
  - qmail-spp patch added (more infor here http://qmail-spp.sourceforge.net)

- 2021.09.27
  - chkuser: now it allows double hyphens "--" in the sender email, like in y--s.co.jp
 diff here https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2021.09.27_patch.diff

- 2021.08.22
  - qlog: now it logs correctly the auth-type
 diff here https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2021.08.22_patch.diff

- 2021.06.19
  - chkuser: defined extra allowed characters in sender/rcpt addresses and added the slash to the list (tx Thomas).
 diff here https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/2021.06.19_patch.diff

- 2021.06.12
  - RSA key and DH parameters are created 4096 bit long also in Makefile-cert. qmail-smtpd.c and qmail-remote.c
 updated accordingly (tx Eric Broch).
  - Makefile-cert: the certs will be owned by vpopmail:vchkpw

- 2021.03.21
  - update_tmprsadh.sh: RSA key and DH parameters increased to 4096 bits

- 2020.12.04
  - received.c: some adjustment to compile with gcc-10
 diff here https://www.sagredo.eu/files/hacks/qmail/patches/roberto-netqmail-1.06/2020.12.04_gcc-10-compat.diff

- 2020.07.29
  - dk-filter: corrected a bug where dk-filter was using DKIMDOMAIN unconditionally. Now it uses DKIMDOMAIN
 only if _SENDER is null (tx Manvendra Bhangui).

- 2020.07.27
  - added cve-2005-1513 patch

- 2020.04.25
  - qmail-smtpd.c: added rcptcount = 0; in smtp_rset function to prevent the maxrcpto error if control/maxrcpt limit
 has been exceeded in multiple messages sent sequentially rather than in a single mail (tx Alexandre Fonceca).
 More info here: https://www.sagredo.eu/en/qmail-notes-185/patching-qmail-82.html#comment1594

- 2020.04.16
  - qmail-remote-logging patch added

- 2020.04.10
  - DKIM patch updated to v. 1.28
    - outgoing messages from null sender ("<>") will be signed as well with the domain in env variable DKIMDOMAIN
    - declaring NODK env variable disables old domainkeys signature, while defining NODKIM disables DKIM.

- 2020.01.11
  - qmail-tls patch updated to v. 20200107
    - working client cert authentication with TLSv1.3 (Rolf Eike Beer)

- 2019.12.08
  - BUG qmail-smtpd.c: now TLS is defined before chkuser.h call, to avoid errors on closing the db connection
 (tx ChangHo.Na https://www.sagredo.eu/en/qmail-notes-185/patching-qmail-82.html#comment1469)

- 2019.08.07
  - a couple of adjustments to chkuser (tx Luca Franceschini)
 more info here https://www.sagredo.eu/files/qmail/patches/dmind/20190807/
    - BUG - since any other definition of starting_string ends up as "DOMAIN", if starting_string is otherwise
   defined, chkuser will be turned off.
    - CHKUSER_ENABLE_ALIAS_DEFAULT, CHKUSER_VAUTH_OPEN_CALL and CHKUSER_DISABLE_VARIABLE are now defined in
   chkuser_settings.h
    - Now CHKUSER_DISABLE_VARIABLE, CHKUSER_SENDER_NOCHECK_VARIABLE, CHKUSER_SENDER_FORMAT_NOCHECK,
   CHKUSER_RCPT_FORMAT_NOCHECK and CHKUSER_RCPT_MX_NOCHECK can be defined at runtime level as well.

- 2019.07.12
  - qmail-channels patch added
 more info here http://www.thesmbexchange.com/eng/qmail-channels_patch.html
  - improved verbosity of die_read function in qmail-smtpd.c (qmail-smtpd: read failure)
 more info here https://www.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06/die_read.patch

- 2019.06.19
  - DKIM patch updated to v. 1.26
    - BUG - honor body length tag in verification

- 2019.05.24
  - qmail-tls updated to v. 20190517
    - bug: qmail-smtpd ssl_free before tls_out error string (K. Wheeler)

- 2019.05.23
  - DKIM patch updated to v. 1.25
    -  SIGSEGV - when the txt data for domainkeys is very large exposed a bug in the way realloc() was used incorrectly.
    -  On 32 bit systems, variable defined as time_t overflows. Now qmail-dkim will skip expiry check in such conditions.

- 2019.04.25
  - bug fixed on qmail-smtpd.c: it was selecting the wrong openssl version on line 2331 (tx ChangHo.Na)

- 2019.04.09
  - qmail-tls updated to v. 20190408
    -  make compatible with openssl 1.1.0 (Rolf Eike Beer, Dirk Engling, Alexander Hof)
    -  compiler warnings on char * casts (Kai Peter)

- 2019.03.22
  - fixed a bug causing crashes with qmail-remote when using openssl-1.1 (tx Luca Franceschini)
(https://www.sagredo.eu/files/qmail//patches//roberto-netqmail-1.06/2019.03.22-fix.patch)

- 2019.02.13
  - Port to openssl-1.1
  - DKIM patch updated to v. 1.24
    -  bug fix: restored signaturedomains/nosignaturedomains functionalities.

- 2018.08.25
  - DKIM patch updated to v. 1.23
    -  fixed a bug where including round brackets in the From: field ouside the double quotes, i.e.
   From: "Name Surname (My Company)" <name.surname@company.com>, results in a DKIMContext structure invalid
   error (tx Mirko Buffoni).
    -  qmail-dkim and dkim were issuing a failure for emails which had multiple signature with at least one good
   signature. Now qmail-dkim and dkim will issue a success if at least one good signature is found.

- 2018.08.23
  - logging patch
    -  fixed a bug in logit and logit2 functions where after a RSET command and a subsequent brutal quit
   of the smtp conversation '^]' by the client cause a segfault (tx Mirko Buffoni, more info here
   https://www.sagredo.eu/en/qmail-notes-185/patching-qmail-82.html#comment1132)
  - patch info moved to 'README.PATCH' file

- 2018.04.03
  - DKIM patch updated to v. 1.22
    -  openssl 1.1.0 port
    -  various improvements, bug fixes

- 2018.01.10
  - maildir++
    -  fixed a bug where the filesize part of the S=<filesize> component of the Maildir++ compatible filename
   is wrong (tx MG). More info here: http://www.sagredo.eu/en/qmail-notes-185/installing-dovecot-and-sieve-on-a-vpopmail-qmail-server-28.html#comment995
  - qmail-queue-extra
    -  removed, because it was causing more problems than advantages, as the domain of the log@yourdomain.tld
   had to match the system domain inside control/me and shouldn't be a virtual domain as well.

- 2017.10.11 (tx Luca Franceschini)
  - qlogfix
    -  log strings should terminate with \n to avoid trailing ^M using splogger
    -  bug reporting custom errors from qmail-queue in qlog
  - added dnscname patch
  - added rcptcheck patch

- 2017.08.18
  - qmail-smtpd now retains authentication upon rset
 (tx to Andreas http://www.sagredo.eu/qmail-notes-185/smtp-auth-qmail-tls-forcetls-patch-for-qmail-84.html#comment750)

- 2017-05-14
  - DKIM patch updated to v. 1.20
 It now manages long TXT records, avoiding the rejection of some hotmail.com messages.

- 2016-12-19
  - Several new patches and improvements added (thanks to Luca Franceschini)
More info here http://www.sagredo.eu/node/178
   - qregex patch
   - brtlimit patch
   - validrcptto patch
   - rbl patch (updates qmail-dnsbl patch)
   - reject-relay-test patch
   - added DISABLETLS environment variable, useful if you want to disable TLS on a desired port
   - added FORCEAUTHMAILFROM environment variable to REQUIRE that authenticated user and 'mail from' are identical
   - fixed little bug in 'mail from' address handling (patch by Andre Opperman at http://qmail.cr.yp.narkive.com/kBry
  6GJl/bug-in-qmail-smtpd-c-addrparse-function)
   - added SMTPAUTHMETHOD, SMTPAUTHUSER and SMTP_AUTH_USER env variables for external plugins
   - qlog patch
   - reject null senders patch
   - bouncecontrolmime patch
   - qmail-taps-extended (updates qmail-tap)

- 2016-12-02
  - fixed BUG in qmail-remote.c: in case of remote server who doesn't allow EHLO the response for an alternative
 HELO was checked twice, making the connection to die. (Thanks to Luca Franceschini)
 Patch applied: http://www.sagredo.eu/files/qmail/patches/fix_sagredo_remotehelo.patch

- 2016-09-19
  - qmail-tls patch updated to v. 20160918
     -  bug: qmail-remote accepting any dNSName, without checking that is matches (E. Surovegin)
     -  bug: documentation regarding RSA and DH keys (K. Peter, G. A. Bofill)

- 2016-05-15
  - force-tls patch improved (a big thanks to Marcel Telka). Now qmail-smtpd avoids to write the auth verb if the
 the STARTTLS command was not sent by the client

- 2016-03-09
  - DKIM patch upgraded to v. 1.19
    -  verification will not fail when a dkim signature does not include the subject provided that the
   UNSIGNED_SUBJECT environment variable is declared.

- 2015-12-26
  - qmail-tls patch updated to v. 20151215
    -  typo in #if OPENSSL_VERSION_NUMBER for 2015-12-08 patch release (V. Smith)
    -  add ECDH to qmail-smtpd
    -  increase size of RSA and DH pregenerated keys to 2048 bits
    -  qmail-smtpd sets RELAYCLIENT if relaying allowed by cert
 more info at http://inoa.net/qmail-tls/

- 2015-12-15
  - DKIM patch by Manvendra Bhangui updated to v. 1.18

- 2015-10-03
  - qmail-authentication: updated to v. 0.8.3

- 2015-08-08
  - fixed a bug on qmail-remote.c that was causing the sending of an additionale ehlo greeting (thanks to Cristoph Grover)

- 2015-04-11
  - qmail-authentication: updated to v. 0.8.2
  - qmail-tls: upgraded to v. 20141216 (POODLE vulnerability fixed)

- 2015-03-28
  - added qmail-eMPF patch

- 2014-11-19
  - security fix: the SSLv3 connection is now switched off

- 2014-11-15
  - modified the QUEUE_EXTRA variable in extra.h to improve the qmail-send's log

- 2014-04-14
  - added maxrcpt patch

- 2014-03-10
  - added qmail-0.95-liberal-lf patch

- 2013-12-30
  - added qmail-srs
  - the character "=" is now considered valid in the sender address by chkuser in order to accept SRS

- 2013-12-18
  - added qmail-date-localtime patch

- 2013-12-14
  - added qmail-hide-ip patch

- 2013-12-10
  - the original greetdelay by e.h. has been replaced with the improved patch by John Simpson. Now
 communications trying to send commands before the greeting will be closed. Premature disconnections will be
 logged as well.
  - CHKUSER_SENDER_FORMAT enabled to reject fake senders without any domain declared (like <foo>)
  - chkuser logging: I slightly modified the log line adding the variables' name just to facilitate its interpretation
  - added qmail-moreipme patch

- 2013-12-07
  - added qmail-dnsbl patch

- 2013-12-05
  - added two patches to make qmail rfc2821 compliant

- 2013-11-23
  - added any-to-cname patch

- 2013-09-27
  - DKIM patch upgraded to v. 1.17. Defined -DHAVE_SHA_256 while compiling dkimverify.cpp in the Makefile.
 This solved an issue while verifying signatures using sha256.

- 2013-09-16
  - Minor fixes to the DKIM patch.

- 2013-09-13
  - DKIM patch upgraded to v. 1.16. The signing at qmail-remote level has been revised by its author.

- 2013-08-25
  - qmail-qmqpc.c call to timeoutconn() needed a correction because the function signature was modified by the
 outgoingip patch. Thanks to Robbie Walker (diff here http://www.sagredo.eu/node/82#comment-373)

- 2013-08-21
  - fixed a bug in hier.c which caused the installation not to build properly the queue/todo dir structure (thanks to
 Scott Ramshaw)

- 2013-08-18
  - DKIM-SURBL patch by Manvendra Bhangui updated to v. 1.14

- 2013-08-12
  - DKIM patch upgraded to v. 1.12. The new patch adds surblfilter functionality.
  - added qmail-smtpd pid, qp log patch

- 2013-08-08
  - qmail-SPF modified by Manvendra Bhangui to make it IPv6-mapped IPv4 addresses compliant. In order to have it
 working with such addresses you have to patch tcpserver.c accordingly. You can use a patch fot ucspi-tcp6-0.98
 by Manvendra Bhangui at http://www.sagredo.eu/files/qmail/patches/tcpserver-ipv6mapped_ip
 v4.patch or wait for v. 0.99 relase of ucspi-tcp6
  - added outgoingip patch
  - added qmail-bounce patch

- 2013-03-31
  - qmail-auth updated to latest v. 0.8.1 Added authentication by recipient domain for qmail-remote.
Look at README.auth for further details

- 2013-02-11
  - some code adjustments in qmail-smtpd.c smtpd_ehlo() to restore total compatibility with esmtp-size patch

- 2013-02-08
  - qmail-auth updated to latest v. 0.7.6. Look at README.auth for further details

- 2013-01-28
  - fixed an issue on qmail-pop3d which was causing a double +OK after the pass command (thanks to Rakesh, Orbit
and Simplex for helping in testing and troubleshooting)

- 2013-01-06
  - environment variable GREETDELAY renamed to SMTPD_GREETDELAY

- 2012-10-31
  - qmail-auth updated to latest v. 0.7.5. Look at README.auth for further details
  - The qmail-forcetls patch was simplyfied accordingly.
  - You MUST export SMTPAUTH="" in your run file now.

- 2012-04-25
  - added qmail-remote CRLF (thanks to Pierre Lauriente for the help on testing and troubleshooting)
  - The qmail-remote CRLF patch solved a problem of broken headers after sieve forwarding that was
caused by a bad handling of the CR (carriage return) by qmail-remote.
The issue is also reported here http://www.dt.e-technik.uni-dortmund.de/~ma/qmail-bugs.html

- 2012.04.16
  - added qmail-tap

- 2012.02.08
  - added smtp-size patch

- 2012.01.29
  - added doublebounce-trim patch

- 2011.12.12
  - file update_tmprsadh modified to chown the .pem files to vpopmail to avoid hang-ups during the smtp
conversation on port 587 caused by permission problems.

- 2011.10.06
  - qmail-remote.c: fixed. It was not going into tls on authentication (thanks to Krzysztof Gajdemski)
  - force-tls now quits if the starttls command is not provided when required (thanks to Jacekalex)
