# qmail

[qmail](http://cr.yp.to/qmail.html) is a secure, reliable, efficient, simple message transfer agent. It is designed for typical Internet-connected UNIX hosts. It was developed by [D. J. Bernstein](http://cr.yp.to/djb.html).

## My patched qmail with auth+tls+forcetls

More info at https://notes.sagredo.eu/qmail-notes-185/smtp-auth-qmail-tls-forcetls-patch-for-qmail-84.html

This qmail distribution puts together netqmail-1.06 with the following patches (more info in the README file):

* Erwin Hoffmann's qmail-authentication patch v. 0.8.3, which updates the patches provided
  by Krysztof Dabrowski and Bjoern Kalkbrenner.
  It provides cram-md5, login, plain authentication support for qmail-smtpd and qmail-remote.
  http://www.fehcom.de/qmail/smtpauth.html##PATCHES
* Frederik Vermeulen's qmail-tls patch v. 20200107
  implements SSL or TLS encrypted and authenticated SMTP.
  The key is now 4096 bit long and the cert will be owned by vpopmail:vchkpw
  http://inoa.net/qmail-tls/
  The file update_tmprsadh was modified to chown all .pem files to vpopmail.
* Marcel Telka's force-tls patch v. 2016.05.15
  optionally gets qmail to require TLS before authentication to improve security.
  You have to declare FORCETLS=0 if you want to allow the auth without TLS
  https://notes.sagredo.eu/files/qmail/patches/roberto-netqmail-1.06_force-tls/force-tls_marcel.patch

## Install
```
make
make setup check
```

You have to export SMTPAUTH in your run file if you want to do the auth. For example:
```
export SMTPAUTH="!"
```

[README.auth](https://github.com/sagredo-dev/qmail-auth-tls-forcetls/blob/main/README.auth) file for more info.

## Info and support
You can find more info and ask for support here https://notes.sagredo.eu/qmail-notes-185/smtp-auth-qmail-tls-forcetls-patch-for-qmail-84.html.
