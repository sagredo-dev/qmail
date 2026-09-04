# ── Stage 1: builder ─────────────────────────────────────────────────────────
# The compilation chain is strictly ordered:
#   libsrs2  →  netqmail (vanilla)  →  vpopmail  →  patched qmail
#
# Why that order:
#  • netqmail must be installed first so that /var/qmail exists with the
#    correct layout and ownership before vpopmail's configure runs.
#  • vpopmail must be installed before the patched qmail because chkuser.c
#    includes vpopmail.h / vauth.h / vpopmail_config.h, and qmail-smtpd links
#    against the library list written to /home/vpopmail/etc/lib_deps.
#  • libsrs2 can be built any time before the patched qmail; doing it first
#    keeps the steps clean.
FROM debian:bookworm-slim AS builder

# All client dev libraries are installed so the image can be rebuilt for any
# vpopmail auth backend without changing the Dockerfile.
# Select the backend at build time with: --build-arg VPOPMAIL_AUTH=<module>
#   mysql   → libmariadb-dev-compat (MariaDB replaces MySQL in Debian)
#   pgsql   → libpq-dev
#   ldap    → libldap-dev
#   cdb     → no extra library
#   passwd  → no extra library
ARG VPOPMAIL_AUTH=cdb

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential wget ca-certificates autotools-dev \
        libssl-dev libidn2-dev \
        libbz2-dev liblz4-dev \
        libmariadb-dev-compat \
        libpq-dev \
        libldap-dev \
        libevent-dev \
        libcrack2-dev \
        cracklib-runtime \
        mandoc \
        groff \
    && rm -rf /var/lib/apt/lists/*

# Users/groups must exist before `make setup` in any of the qmail build steps.
# UIDs/GIDs are pinned so the runtime stage can reuse them without chown passes.
RUN groupadd -g 2107 qmail \
 && groupadd -g 2108 nofiles \
 && groupadd -g 2109 vchkpw \
 && useradd -u 2107 -g nofiles -d /var/qmail/alias -M -s /usr/sbin/nologin alias \
 && useradd -u 2108 -g nofiles -d /var/qmail       -M -s /usr/sbin/nologin qmaild \
 && useradd -u 2109 -g nofiles -d /var/qmail       -M -s /usr/sbin/nologin qmaill \
 && useradd -u 2110 -g qmail   -d /var/qmail       -M -s /usr/sbin/nologin qmailp \
 && useradd -u 2111 -g nofiles -d /var/qmail       -M -s /usr/sbin/nologin qmailq \
 && useradd -u 2112 -g qmail   -d /var/qmail       -M -s /usr/sbin/nologin qmailr \
 && useradd -u 2113 -g qmail   -d /var/qmail       -M -s /usr/sbin/nologin qmails \
 && useradd -u 89   -g vchkpw  -d /home/vpopmail   -m -s /usr/sbin/nologin vpopmail

WORKDIR /build

# Pre-downloaded external sources (non-GitHub, non-sagredo.eu).
# Avoids build-time dependency on third-party personal sites.
COPY docker/external-files/ /build/external-files/

# ── Step 1: libsrs2 ──────────────────────────────────────────────────────────
# conf-ld already carries -L/usr/local/lib, so installing here is enough.
# The shipped config.guess (2002) predates aarch64 and fails on arm64 builds —
# refresh it from autotools-dev (harmless no-op on amd64).
RUN wget -q https://www.sagredo.eu/files/qmail/tar/libsrs2-1.0.18.tar.gz \
 && tar xzf libsrs2-1.0.18.tar.gz \
 && cd libsrs2-1.0.18 \
 && cp /usr/share/misc/config.guess /usr/share/misc/config.sub . \
 && ./configure --prefix=/usr/local \
 && make \
 && make install

# ── Step 1b: fehQlibs ────────────────────────────────────────────────────────
# Required by ucspi-tcp6 v1.13+. Provides the DJB-style headers (uint_t.h,
# stralloc.h, etc.) and support libraries. Symlinked to /usr/local/qlibs so
# the ucspi-tcp6 build system finds it automatically.
ARG FEHQLIBS_VERSION=31
RUN cp /build/external-files/fehQlibs-${FEHQLIBS_VERSION}.tgz . \
 && tar xzf fehQlibs-${FEHQLIBS_VERSION}.tgz -C /usr/local \
 && make -C /usr/local/fehQlibs-${FEHQLIBS_VERSION}/src \
 && ln -s /usr/local/fehQlibs-${FEHQLIBS_VERSION} /usr/local/qlibs

# ── Step 1c: ucspi-tcp6 ──────────────────────────────────────────────────────
# IPv6-capable replacement for DJB's ucspi-tcp, by Erwin Hoffmann (fehcom.de).
# Provides tcpserver that binds on :: for dual-stack IPv4+IPv6.
# Requires mandoc (since v1.13.05) and fehQlibs. Installs tcpserver/tcpclient
# to /usr/local/bin — takes precedence over Debian's ucspi-tcp at runtime.
ARG TCP6_VERSION=1.13.07
RUN cp /build/external-files/ucspi-tcp6-${TCP6_VERSION}.tgz . \
 && tar xzf ucspi-tcp6-${TCP6_VERSION}.tgz \
 && cd net/ucspi-tcp6/ucspi-tcp6-${TCP6_VERSION} \
 && package/install \
 && rm -f /usr/local/bin/tcpserver /usr/local/bin/tcpclient \
 && cp compile/tcpserver compile/tcpclient /usr/local/bin/

# ── Step 1c: ucspi-ssl ───────────────────────────────────────────────────────
# Not in Debian's repos; build from Erwin Hoffmann's fork (OpenSSL 3.x
# compatible). package/install compiles but doesn't install anywhere
# (command-cp is empty), so we copy sslserver/sslclient to /usr/local/bin
# ourselves. The runtime stage picks them up via COPY --from=builder.
# Notes:
#  • sed patches print-cc.sh to add -fcommon (gcc 10+ changed the default to
#    -fno-common, causing multiple-definition errors on global strnum).
#  • "- sslperl" suppresses the sslperl target which requires libperl-dev.
RUN cp /build/external-files/ucspi-ssl-0.99e.tgz . \
 && tar xzf ucspi-ssl-0.99e.tgz \
 && cd host/superscript.com/net/ucspi-ssl-0.99e \
 && sed -i 's/^ccbase="cc /ccbase="cc -fcommon /' src/print-cc.sh \
 && package/install - sslperl \
 && rm -f /usr/local/bin/sslserver /usr/local/bin/sslclient /usr/local/bin/sslprint /usr/local/bin/sslconnect /usr/local/bin/sslcat \
 && cp compile/sslserver compile/sslclient /usr/local/bin/

# ── Step 2: netqmail (vanilla) ───────────────────────────────────────────────
# vpopmail's configure expects /var/qmail to exist with the correct layout and
# ownership. The patched qmail overwrites these binaries in step 4; the
# directory structure is all we need from this step.
RUN wget -q https://www.sagredo.eu/files/qmail/tar/netqmail-1.06.tar.gz \
 && tar xzf netqmail-1.06.tar.gz \
 && cd netqmail-1.06 \
 && make it \
 && make setup

# ── Step 3: vpopmail ─────────────────────────────────────────────────────────
# Now that /var/qmail exists, vpopmail's configure finds what it needs.
# After `make install-strip`:
#   /home/vpopmail/include/  — vpopmail.h, vauth.h, vpopmail_config.h
#   /home/vpopmail/etc/lib_deps — library flags consumed by the patched qmail
#
# Auth backend is selected via VPOPMAIL_AUTH build arg (default: cdb).
# Rebuild with --build-arg VPOPMAIL_AUTH=pgsql|ldap|mysql|passwd as needed.
ARG VPOPMAIL_VERSION=5.6.13
RUN ARCH=$(dpkg-architecture -qDEB_HOST_MULTIARCH) \
 && wget -q https://github.com/sagredo-dev/vpopmail/archive/refs/tags/v${VPOPMAIL_VERSION}.tar.gz \
 && tar xzf v${VPOPMAIL_VERSION}.tar.gz \
 && cd vpopmail-${VPOPMAIL_VERSION} \
 && cp /usr/share/misc/config.guess /usr/share/misc/config.sub . \
 && if [ "${VPOPMAIL_AUTH}" = "mysql" ]; then \
        EXTRA_FLAGS="--enable-incdir=/usr/include/mysql \
                     --enable-libdir=/usr/lib/${ARCH} \
                     --enable-mysql-limits \
                     --enable-valias \
                     --enable-sql-aliasdomains"; \
    elif [ "${VPOPMAIL_AUTH}" = "pgsql" ]; then \
        EXTRA_FLAGS="--enable-incdir=/usr/include/postgresql \
                     --enable-libdir=/usr/lib/${ARCH} \
                     --enable-valias \
                     --enable-sql-aliasdomains"; \
    elif [ "${VPOPMAIL_AUTH}" = "ldap" ]; then \
        EXTRA_FLAGS="--enable-libdir=/usr/lib/${ARCH}"; \
    else \
        EXTRA_FLAGS=""; \
    fi \
 && ./configure \
        --enable-vpopuser=vpopmail \
        --enable-vpopgroup=vchkpw \
        --enable-auth-module="${VPOPMAIL_AUTH}" \
        --enable-file-locking=flock \
        --enable-auth-logging \
        --enable-vusaged \
        ${EXTRA_FLAGS} \
 && make -j"$(nproc)" \
 && make install-strip

# ── Step 3b: vusaged (vpopmail usage daemon) ────────────────────────────────
# vpopmail's `make install` only prints build instructions for vusaged (see
# the vusage-msg target) — it must be compiled manually from the vusaged/
# subdir. Requires libev (Debian: libev-dev).
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends libev-dev \
 && rm -rf /var/lib/apt/lists/* \
 && cd /build/vpopmail-5.6.13/vusaged \
 && cp /usr/share/misc/config.guess /usr/share/misc/config.sub . \
 && LIBS="$(head -1 /home/vpopmail/etc/lib_deps) -lev" \
    ./configure --with-vpopmail=/home/vpopmail/ \
 && make \
 && cp -f vusaged /home/vpopmail/bin/ \
 && cp -f etc/vusaged.conf /home/vpopmail/etc/

# ── Step 3c: autorespond ─────────────────────────────────────────────────────
# Vacation/out-of-office responder required by qmailadmin.
# v2.0.9 fixes a segfault in To: header processing.
RUN wget -q https://github.com/sagredo-dev/autorespond/archive/refs/tags/v2.0.9.tar.gz \
 && tar xzf v2.0.9.tar.gz \
 && cd autorespond-2.0.9 \
 && chown -R root:root . \
 && make \
 && make install

# ── Step 4: patched qmail ────────────────────────────────────────────────────
# chkuser.c can now resolve its includes from /home/vpopmail/include, and the
# qmail-smtpd link step reads /home/vpopmail/etc/lib_deps for the vpopmail
# library flags. `make setup` overwrites the vanilla netqmail binaries from
# step 2, leaving /var/qmail in its final state.
COPY . /usr/src/qmail/
WORKDIR /usr/src/qmail
RUN make -j"$(nproc)" it && make setup

# ── Step 4b: jgreylist ───────────────────────────────────────────────────────
# File-based greylisting wrapper for qmail-smtpd by John Simpson.
# Stores greylist state in /var/qmail/jgreylist (plain files, no DB needed).
# jgreylist-clean purges expired entries; run periodically via cron/external.
RUN wget -q https://notes.sagredo.eu/files/qmail/patches/greylisting/jms/jgreylist.c \
 && cc -o /var/qmail/bin/jgreylist jgreylist.c \
 && chmod 0750 /var/qmail/bin/jgreylist \
 && wget -q -O /var/qmail/bin/jgreylist-clean \
        https://notes.sagredo.eu/files/qmail/patches/greylisting/jms/jgreylist-clean \
 && chmod 755 /var/qmail/bin/jgreylist-clean

# ── Step 4b+: rcptcheck-overlimit ────────────────────────────────────────────
# Rate-limiting script for authenticated relay clients (ports 465/587).
# Counts accepted RCPTTOs per auth user or IP; rejects with 421 when over limit.
# Limit config: control/relaylimits; state dir: /var/qmail/overlimit (writable by vpopmail).
# Reset counts by clearing the overlimit dir (e.g. daily via cron).
RUN cp /usr/src/qmail/scripts/rcptcheck-overlimit /var/qmail/bin/rcptcheck-overlimit \
 && chmod 0755 /var/qmail/bin/rcptcheck-overlimit \
 && mkdir -p /var/qmail/overlimit \
 && chown vpopmail:vchkpw /var/qmail/overlimit \
 && chmod 0750 /var/qmail/overlimit

# ── Step 4c: qmail-spp greylisting plugin ────────────────────────────────────
# MySQL-backed greylisting that runs inside qmail-smtpd via the SPP plugin
# mechanism. More flexible than jgreylist: per-IP exemptions, pass/block stats,
# and skip-for-authenticated via ifauthskip — all without a binary wrapper.
#
# Enabled at runtime by listing plugins/greylisting in control/smtpplugins and
# setting GREYLIST_USER/GREYLIST_PASS/GREYLIST_DB env vars (entrypoint writes
# control/mysql.cnf and control/greylisting from those).
WORKDIR /build
RUN mkdir -p /var/qmail/plugins \
 && cp /build/external-files/greylisting-0.5.tgz . \
 && wget -q https://notes.sagredo.eu/files/qmail/patches/greylisting_DEFAULT_SOURCE.patch \
 && tar xzf greylisting-0.5.tgz \
 && cd greylisting-0.5 \
 && patch < ../greylisting_DEFAULT_SOURCE.patch \
 && cc -std=c99 -o /var/qmail/plugins/greylisting greylisting.c \
        -I/usr/include/mysql -lmysqlclient \
 && strip /var/qmail/plugins/greylisting \
 && cp greylisting_cleanup.sh /usr/local/sbin/greylisting_cleanup.sh \
 && chmod +x /usr/local/sbin/greylisting_cleanup.sh \
 && wget -q -O ifauthskip.c \
        https://notes.sagredo.eu/files/qmail/patches/qmail-spp/plugins/ifauthskip.c \
 && cc -o /var/qmail/plugins/ifauthskip ifauthskip.c \
 && strip /var/qmail/plugins/ifauthskip

# ── Step 4d: ripMIME ──────────────────────────────────────────────────────────
# MIME attachment extractor required by simscan for --enable-attach scanning.
WORKDIR /build
RUN cp /build/external-files/ripmime-1.4.0.6.tar.gz . \
 && tar xzf ripmime-1.4.0.6.tar.gz \
 && cd ripmime-1.4.0.6 \
 && make \
 && cp ripmime /usr/local/bin/ripMIME

# simscan configure checks for clamav user, clamdscan, sigtool, spamc, and db dir.
# Install clamav in builder to satisfy all checks (builder stage is discarded).
RUN apt-get update && apt-get install -y --no-install-recommends clamav clamav-daemon \
 && rm -rf /var/lib/apt/lists/* \
 && cp /usr/src/qmail/docker/rspamd-spamc /usr/local/bin/rspamd-spamc \
 && chmod +x /usr/local/bin/rspamd-spamc \
 && mkdir -p /var/lib/clamav

# ── Step 4e: simscan ──────────────────────────────────────────────────────────
# qmail-queue wrapper that scans through ClamAV (clamdscan) and Rspamd
# (rspamd-spamc wrapper calling rspamc) before calling the real qmail-queue.
# Delivery chain: qmail-smtpd → qmail-dkim (DKIM verify, via DKIMQUEUE=simscan)
#                 → simscan (AV + spam) → /var/qmail/bin/qmail-queue
ARG SIMSCAN_VERSION=1.4.6.2
RUN wget -q https://github.com/sagredo-dev/simscan/archive/refs/tags/v${SIMSCAN_VERSION}.tar.gz \
 && tar xzf v${SIMSCAN_VERSION}.tar.gz \
 && cd simscan-${SIMSCAN_VERSION} \
 && cp /usr/share/misc/config.guess /usr/share/misc/config.sub . \
 && ./configure \
        --enable-user=clamav \
        --enable-clamav=y \
        --enable-clamdscan=/usr/bin/clamdscan \
        --enable-spam=y \
        --enable-spamc=/usr/local/bin/rspamd-spamc \
        --enable-spamassassin-path=/usr/local/bin/rspamd-spamc \
        --enable-spam-passthru=y \
        --enable-spam-hits=9.0 \
        --enable-per-domain=y \
        --enable-ripmime=/usr/local/bin/ripMIME \
        --enable-attach=y \
        --enable-custom-smtp-reject=y \
        --enable-spamc-user=y \
        --enable-clamavdb-path=/var/lib/clamav \
        --enable-received=y \
 && make -j"$(nproc)" \
 && make install

# ── Step 5: ezmlm-idx ────────────────────────────────────────────────────────
# High-speed mailing list manager for qmail.
# Requires lang/default symlink before building.
WORKDIR /build
RUN cp /build/external-files/ezmlm-idx-7.2.2.tar.gz . \
 && tar xzf ezmlm-idx-7.2.2.tar.gz \
 && cd ezmlm-idx-7.2.2 \
 && ln -s en_US lang/default \
 && make -j"$(nproc)" \
 && make man \
 && make install

# ── Step 6: qmailadmin ───────────────────────────────────────────────────────
# Web-based admin interface for vpopmail domains/users.
# Installs to /var/www/qmailadmin (CGI binary + HTML templates).
ARG QMA_VERSION=1.2.27
RUN wget -q https://github.com/sagredo-dev/qmailadmin/archive/refs/tags/v${QMA_VERSION}.tar.gz \
 && tar xzf v${QMA_VERSION}.tar.gz \
 && cd qmailadmin-${QMA_VERSION} \
 && chown -R root:root . \
 && cp /usr/share/misc/config.guess /usr/share/misc/config.sub . \
 && ./configure \
        --enable-htmldir=/var/www/qmailadmin \
        --enable-cgibindir=/var/www/qmailadmin/cgi-bin \
        --enable-cgipath=/cgi-bin/qmailadmin \
        --enable-imagedir=/var/www/qmailadmin/images \
        --enable-imageurl=/images \
        --enable-htmllibdir=/var/www/qmailadmin/html \
        --enable-qmaildir=/var/qmail \
        --enable-domain-autofill \
        --enable-vpopuser=vpopmail \
        --enable-vpopgroup=vchkpw \
        --enable-autoresponder-path=/usr/local/bin \
        --enable-ezmlmdir=/usr/local/bin/ezmlm \
        --enable-modify-quota \
        --enable-maxusersperpage=100 \
        --enable-maxaliasesperpage=100 \
        --enable-cracklib=/var/cache/cracklib/cracklib_dict \
        --with-auth-logdir \
        --disable-catchall \
        --disable-ezmlm-mysql \
        --disable-trivial-password \
 && make -j"$(nproc)" \
 && make install-strip

# ── Step 7: vqadmin ──────────────────────────────────────────────────────────
# System-level admin interface for vpopmail (add/remove domains, etc.)
# Requires HTTP basic auth — password set via VQADMIN_PASS env var on first run.
ARG VQA_VERSION=2.4.7
RUN wget -q https://github.com/sagredo-dev/vqadmin/archive/refs/tags/v${VQA_VERSION}.tar.gz \
 && tar xzf v${VQA_VERSION}.tar.gz \
 && cd vqadmin-${VQA_VERSION} \
 && chown -R root:root . \
 && cp /usr/share/misc/config.guess /usr/share/misc/config.sub . \
 && ./configure \
        --enable-cgibindir=/var/www/qmailadmin/cgi-bin \
        --enable-qmaildir=/var/qmail \
 && make -j"$(nproc)" \
 && make install-strip


# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim

ARG VPOPMAIL_AUTH=cdb

# Runtime client libraries — only the one matching the compiled-in backend
# is strictly needed, but installing all keeps the image backend-agnostic so
# you can swap the backend by rebuilding without touching this stage.
# Note: Dovecot has been split into a separate container.
RUN apt-get update && apt-get install -y --no-install-recommends \
        runit \
        ucspi-tcp \
        openssl \
        libssl3 \
        libidn2-0 \
        libbz2-1.0 liblz4-1 \
        libmariadb3 \
        libpq5 \
        libldap-2.5-0 \
        libevent-2.1-7 \
        libcrack2 \
        lighttpd \
        lighttpd-mod-authn-file \
        apache2-utils \
        netcat-openbsd \
        ca-certificates \
        clamav \
        clamav-daemon \
        python3 \
        rspamd \
        curl \
        cron \
        python3-flask \
    && rm -rf /var/lib/apt/lists/*

# Same pinned UIDs/GIDs as builder — no ownership fix-up needed.
# Cross-group memberships for qmail ↔ vpopmail interop:
#   vpopmail → qmail  : vpopmail tools can interact with qmail queue/binaries
#   qmailq   → vchkpw : qmail-queue can access vpopmail domain/user structures
# Note: Dovecot is now in a separate container.
RUN groupadd -g 2107 qmail \
 && groupadd -g 2108 nofiles \
 && groupadd -g 2109 vchkpw \
 && useradd -u 2107 -g nofiles -d /var/qmail/alias -M -s /usr/sbin/nologin alias \
 && useradd -u 2108 -g nofiles -d /var/qmail       -M -s /usr/sbin/nologin qmaild \
 && useradd -u 2109 -g nofiles -d /var/qmail       -M -s /usr/sbin/nologin qmaill \
 && useradd -u 2110 -g qmail   -d /var/qmail       -M -s /usr/sbin/nologin qmailp \
 && useradd -u 2111 -g nofiles -G vchkpw -d /var/qmail -M -s /usr/sbin/nologin qmailq \
 && useradd -u 2112 -g qmail   -d /var/qmail       -M -s /usr/sbin/nologin qmailr \
 && useradd -u 2113 -g qmail   -d /var/qmail       -M -s /usr/sbin/nologin qmails \
 && useradd -u 89   -g vchkpw  -G qmail -d /home/vpopmail -m -s /usr/sbin/nologin vpopmail

COPY --from=builder /var/qmail        /var/qmail
COPY --from=builder /home/vpopmail    /home/vpopmail
COPY --from=builder /usr/local/lib    /usr/local/lib
COPY --from=builder /usr/local/bin    /usr/local/bin
COPY --from=builder /usr/local/sbin   /usr/local/sbin
COPY --from=builder /var/www/qmailadmin /var/www/qmailadmin

# libev — runtime dep of /home/vpopmail/bin/vusaged (built against libev-dev
# in the builder stage; the .so.4 soname must be present here)
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends libev4 \
 && rm -rf /var/lib/apt/lists/* \
 && echo '/usr/local/lib' > /etc/ld.so.conf.d/usr-local.conf \
 && ldconfig \
 && ln -s /var/qmail/bin/sendmail /usr/sbin/sendmail

# Lighttpd config for qmailadmin CGI
COPY docker/lighttpd.conf /etc/lighttpd/lighttpd.conf

# clamdscan client config — points to the clamav container over TCP
COPY docker/clamdscan.conf /etc/clamav/clamd.conf

# clamdscan was removed in ClamAV 1.x; replace with a Python3 INSTREAM client
COPY docker/clamdscan-wrapper /usr/bin/clamdscan
RUN chmod +x /usr/bin/clamdscan

# rspamd-spamc: spamc-compatible wrapper that calls rspamc → rspamd container
COPY docker/rspamd-spamc /usr/local/bin/rspamd-spamc
RUN chmod +x /usr/local/bin/rspamd-spamc \
 && chown clamav:clamav /var/qmail/bin/simscan \
 && chmod 4755 /var/qmail/bin/simscan \
 && mkdir -p /var/qmail/simscan \
 && chown clamav:clamav /var/qmail/simscan \
 && chmod 750 /var/qmail/simscan

# LMTP delivery script for qmail → Dovecot (bash, uses /dev/tcp)
COPY docker/lmtp-deliver /var/qmail/bin/lmtp-deliver
RUN chmod +x /var/qmail/bin/lmtp-deliver

# Domain management REST API
COPY docker/qmailapi /opt/qmailapi

# Runit service definitions
# Note: Dovecot is now in a separate container.
COPY docker/runit /etc/sv
RUN mkdir -p /etc/service /var/log/qmail \
 && for svc in qmail-smtpd qmail-send qmail-submission qmail-smtps lighttpd vusaged cron qmailapi; do \
      chmod +x /etc/sv/$svc/run /etc/sv/$svc/log/run; \
      mkdir -p /var/log/qmail/$svc; \
      ln -s /etc/sv/$svc /etc/service/$svc; \
    done \
 && chown -R qmaill:nofiles /var/log/qmail

COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/healthcheck.sh /healthcheck.sh
RUN chmod +x /entrypoint.sh /healthcheck.sh

# Label the compiled-in vpopmail backend for introspection
LABEL vpopmail.auth="${VPOPMAIL_AUTH}"

# Ports: SMTP (25), HTTP (80), SMTPS (465), Submission (587)
# Note: IMAP/POP3/ManageSieve ports are now in the dovecot container.
EXPOSE 25 80 465 587

# Single persistent volume — all mutable data lives under /srv/mail:
#   /srv/mail/qmail/control     → symlinked from /var/qmail/control
#   /srv/mail/qmail/queue       → symlinked from /var/qmail/queue
#   /srv/mail/jgreylist         → symlinked from /var/qmail/jgreylist
#   /srv/mail/vpopmail/domains  → symlinked from /home/vpopmail/domains
#   /srv/mail/vpopmail/etc      → symlinked from /home/vpopmail/etc
# The entrypoint creates the subdirs and symlinks on first run.
VOLUME ["/srv/mail"]

HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
    CMD /healthcheck.sh

ENTRYPOINT ["/entrypoint.sh"]
