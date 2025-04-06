# qmail SRS patch

This is a SRS (Sender Rewriting Scheme) implementation for qmail using libsrs2.

Current version: qmail-srs-0.8.patch

## Install instructions

Download and install libsrs2 from http://www.libsrs2.org/download.html.

Download qmail-srs-0.8.patch.

Apply this patch:

    tar -xzf /path/to/qmail-1.03.tar.gz
    cd qmail-1.03
    patch -p1 < qmail-srs-0.8.patch

And follow your qmail instalation (config, make, make setup check, ...)

Configure some parameters in /var/qmail/control.

Required parameters:

    echo srs.YOURDOMAIN > /var/qmail/control/srs_domain
    echo SECRET > /var/qmail/control/srs_secrets

    YOURDOMAIN: Replace with your domain name, e.g. srs.foo-bar.com
    SECRET: Replace with a random string

Important! You MUST create a MX record for srs.YOURDOMAIN pointing to your server.

Optional parameters:

    echo 7 > /var/qmail/control/srs_maxage
    echo 4 > /var/qmail/control/srs_hashlength
    echo 4 > /var/qmail/control/srs_hashmin
    echo = > /var/qmail/control/srs_separator
    echo 0 > /var/qmail/control/srs_alwaysrewrite
    Configure your SRS domain.

    echo srs.YOURDOMAIN >> /var/qmail/control/rcpthosts
    echo srs.YOURDOMAIN:srs >> /var/qmail/control/virtualdomains
    echo "| /var/qmail/bin/srsfilter" > /var/qmail/alias/.qmail-srs-default

    YOURDOMAIN: Replace with your domain name, e.g. srs.foo-bar.com.

## Configuration Parameters

    Parameter      Description                                                             Example

    srs_domain     A domain to use in rewritten addresses. If not set, SRS is disabled.    srs.foo-bar.com  
    srs_secrets    A random string to generate and check SRS addresses. You can specify a list of secrets (one per line). The first secret in the list is used for generating new SRS addresses. All secrets on the list may be used to verify SRS addresses. 	foobar123  
    srs_maxage     The maximum permitted age of a rewritten address. SRS rewritten addresses expire after a specified number of days. libsrs2 default is 21, but I believe that a week is enougth to get all bounces, so I recommend you to use 7. 	7  
    srs_hashlength The hash length to generate in a rewritten address. The hash length is a measure of security in the SRS system; longer is more secure. 	4  
    srs_hashmin    The hash length to require when checking an address. If the hash length is increased, there may be SRS addresses from your MTA in the wild which use a shorter hash length. This parameter may be set to     permit checking of hashes shorter than srs_hashlength. This parameter must be at most srs_hashlength. 	4  
    srs_separator  The separator to appear immediately after SRS[01] in rewritten addresses. This must be -, + or =. Default value is =. 	=  
    srs_alwaysrewrite    Skip rcpthosts check and perform SRS rewriting for all forwarding, even when not required. This must be 0 (disabled) or 1 (enabled). Default value is 0 (disabled). 	0  
    
## Environment Variables (qmail-inject only)

By default, this patch modifies qmail-inject to rewrite the envelope sender only if EXT and HOST variables are set.

You can change this behavior using the following environment variables:

    QMAILINJECT_FORCE_SRS: qmail-inject will call srsforward() even if EXT and HOST are not set.
    QMAILINJECT_SKIP_SRS: qmail-inject will not call srsforward() even if EXT and HOST are set.

# More about SRS
- http://www.openspf.org/SRS
- http://www.libsrs2.org/
- http://wooledge.org/~greg/qmail-srs.html

## Changes

    2011-03-30 (0.8):
        Fixed bug reading configuration files. 
    2007-06-05 (0.7):
        New QMAILINJECT_FORCE_SRS and QMAILINJECT_SKIP_SRS environment variables can force or skip envelope rewriting in qmail-inject.
    2007-05-31 (0.6):
        qmail-inject only will rewrite envelope if EXT and HOST variables are set.
        Fixed bug in qmail-send handling chdir() calls (Special Thanks to Werner Fleck).
    2007-01-11 (0.5):
        Added parameters srs_separator and srs_alwaysrewrite from libsrs2.
    2007-01-10 (0.4):
        If srs_domain is empty or not set, SRS is disabled.
    2006-12-18 (0.3):
        forward and condredirect: modified to work with SRS.
    2006-12-17 (0.2):
        srsfilter: now rewrites To header with the SRS decoded address.
        srsfilter: only accepts messages from null-sender, Return-Path: <>.
        srsfilter: modified to reject messages without body.
        qmail-inject: error message detailed.
        If optional parameters are not set, will use libsrs2 defaults.
        Install instructions revised.
    2006-12-15 (0.1):
        First release.
