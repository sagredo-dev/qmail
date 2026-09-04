# qmail Docker

Containerised build of [sagredo-dev/qmail](https://github.com/sagredo-dev/qmail) —
a heavily patched netqmail-1.06 with TLS, DKIM, SPF, SRS, SMTP AUTH, chkuser,
SURBL, greylisting, simscan and more — running under **runit** on **Debian bookworm-slim**.

The compose stack runs up to eight containers:

| Container | Role | Ports | Profile |
|---|---|---|---|
| **qmail** | MTA — SMTP, submission, qmailadmin, vqadmin, simscan | 25, 80, 465, 587 | — |
| **dovecot** | IMAP/POP3/ManageSieve, LMTP delivery endpoint | 110, 143, 993, 995, 4190 | — |
| **mariadb** | vpopmail auth/quota backend | internal | — |
| **clamav** | `clamd` + `freshclam` antivirus (called by rspamd) | internal :3310 | — |
| **rspamd** | Spam filtering, antivirus, DKIM verify, DMARC, RBL, Bayes | :11334 (web UI) | — |
| **redis** | Rspamd Bayes + fuzzy state | internal | — |
| **tika** | Attachment text extraction for rspamd (PDF, DOCX, XLSX, …) | internal :9998 | — |
| **oletools** | Office macro scanning via olefy/olevba | internal :11343 | `macros` |

---

## Build chain

The compilation order is strictly enforced because each step depends on the
previous one being installed:

```
fehQlibs → ucspi-tcp6 → ucspi-ssl → libsrs2 → netqmail → vpopmail → vusaged → autorespond
         → patched qmail → jgreylist → rcptcheck-overlimit → spp-greylisting + ifauthskip
         → ripMIME → simscan → ezmlm-idx → qmailadmin → vqadmin
```

| Step | Why it must come first |
|---|---|
| **fehQlibs** | DJB-style headers/libs required by ucspi-tcp6 v1.13+ |
| **ucspi-tcp6** | `tcpserver` with IPv6 dual-stack support for SMTP ports |
| **ucspi-ssl** | `sslserver` binary for implicit TLS (SMTPS port 465) |
| **libsrs2** | qmail links against it at compile time (`conf-ld: -L/usr/local/lib`) |
| **netqmail** | creates `/var/qmail` layout before vpopmail's `configure` runs |
| **vpopmail** | `chkuser.c` includes `vpopmail.h`/`vauth.h`; qmail-smtpd links against `/home/vpopmail/etc/lib_deps` |
| **autorespond** | vacation responder required by qmailadmin |
| **vusaged** | vpopmail quota usage daemon — `make install` only *prints* build instructions (target `vusage-msg`); compiled manually from the `vusaged/` subdir. Needs `libev-dev` in the builder and `libev4` in the runtime (soname `libev.so.4`) |
| **patched qmail** | overwrites netqmail binaries |
| **jgreylist** | file-based greylisting wrapper compiled into `/var/qmail/bin/` |
| **rcptcheck-overlimit** | send-rate limiting script installed to `/var/qmail/bin/` — always present, active on ports 465 and 587 |
| **spp-greylisting + ifauthskip** | MySQL-backed greylisting plugin + auth-skip plugin compiled into `/var/qmail/plugins/` |
| **ripMIME** | MIME extractor required by simscan for attachment scanning |
| **simscan** | `qmail-queue` filter — calls Rspamd before queueing; rspamd owns AV via ClamAV |
| **ezmlm-idx** | mailing list manager, used by qmailadmin |
| **qmailadmin** | web UI for domain/user management |
| **vqadmin** | system-level domain admin |

---

## Prebuilt images (GHCR)

Public multi-arch images are published to **GitHub Container Registry** under
[`brdelphus/qmail`](https://github.com/brdelphus/qmail) — no login required:

| Image | Archs | Contents |
|---|---|---|
| `ghcr.io/brdelphus/qmail:latest` | amd64, arm64 | qmail image (MTA + qmailadmin) |
| `ghcr.io/brdelphus/qmail-dovecot:latest` | amd64, arm64 | Dovecot (IMAP/POP3/ManageSieve) |
| `ghcr.io/brdelphus/qmail-rspamd:latest` | amd64, arm64 | Rspamd + Tika attachment extraction |
| `ghcr.io/brdelphus/qmail-oletools:latest` | amd64, arm64 | Olefy macro scanner (optional profile) |

```sh
docker pull ghcr.io/brdelphus/qmail:latest
```

Images are rebuilt from the repo's `main` branch by the
`.github/workflows/ghcr-build.yml` GitHub Actions workflow (parallel amd64/arm64
builds + a multi-arch `latest` manifest). To rebuild, re-run the workflow —
push-to-GHCR via `GITHUB_TOKEN` is what keeps the packages public and linked to
the repository.

### arm64 notes

The stack builds and runs cleanly on arm64 (validated on OCI Ampere A1 via
k3s). The qmail sources themselves are architecture-independent — the only
arm64 friction comes from the 2002-era autoconf tarballs in the build chain:

- **`config.guess`/`config.sub`** are refreshed to current versions before
  every autoconf `configure` runs (fehQlibs, libsrs2, vpopmail, …) — the stock
  2002 copies don't know `aarch64`
- **DJB-style Makefiles must build single-threaded** — only autoconf-generated
  makefiles get `-j`; the DJB ones fail in parallel
- **MySQL backend** already resolves the multiarch lib path automatically via
  `dpkg-architecture -qDEB_HOST_MULTIARCH` (see vpopmail section)

---

## Quick start

### 1. Configure

Copy the example env file and edit it:

```sh
cp docker/.env.example docker/.env
$EDITOR docker/.env
```

The table below lists everything you should set before the first run.
MariaDB credentials are **baked into the database volume** on first start —
changing them later requires dropping the volume and re-initialising.

| Variable | Required | Default | Notes |
|---|---|---|---|
| `QMAIL_ME` | **yes** | — | FQDN of this server (`mail.example.com`) |
| `MYSQL_ROOT_PASS` | **yes** | `changeme_root` | MariaDB root password — change before first run |
| `MYSQL_PASS` | **yes** | `changeme` | vpopmail DB password — change before first run |
| `QMAIL_DOMAIN` | no | derived from `QMAIL_ME` | Primary virtual domain; defaults to everything after the first dot |
| `RSPAMD_PASSWORD` | recommended | `changeme_rspamd` | rspamd web UI password (`:11334`) |
| `VQADMIN_PASS` | no | auto-generated | vqadmin HTTP basic auth — printed to logs on first run if unset |
| `QMAIL_API_KEY` | no | — | Enables the domain management REST API (port 8080, internal); leave unset to disable |

### 2. Build and start

The image builds cleanly on `debian:bookworm-slim`. Full build time is roughly
5–10 minutes on first run (all sources downloaded and compiled from scratch).

```sh
git clone https://github.com/brdelphus/qmail
cd qmail

docker compose -f docker/docker-compose.yml build
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml logs -f
```

On **first run** the entrypoint:
- Writes all qmail control files from env vars
- Writes `vpopmail/etc/vpopmail.mysql` with the MariaDB connection string
- Generates a self-signed TLS cert for `QMAIL_ME` (replace with Let's Encrypt — see TLS section)
- Generates DKIM keys for `QMAIL_DOMAIN`
- Creates the primary vpopmail domain and postmaster account
- Compiles tcprules CDB files for all three SMTP ports
- Writes and compiles `simscan/simcontrol` from `SIMSCAN_*` env vars

On **every** startup the entrypoint also:
- Rebuilds `/var/qmail/users/assign` from the vpopmail domain directories and recompiles with `qmail-newu`
- Re-writes `/etc/cron.d/qmail` (overlimit reset; SURBL jobs when `SURBL_LAYER=qmail`)
- Re-applies feature layer toggles (`SPF_LAYER`, `DKIM_VERIFY_LAYER`, `DNSBL_LAYER`, `SURBL_LAYER`)

### 3. Add the first mail user

Via CLI inside the container:

```sh
docker compose -f docker/docker-compose.yml exec qmail \
    /home/vpopmail/bin/vadduser postmaster@example.com yourpassword
```

Or via the REST API (requires `QMAIL_API_KEY` to be set):

```sh
# Add a domain (vadddomain + DKIM + LMTP setup in one call)
curl -s -X POST http://localhost:8080/domains \
  -H "Authorization: Bearer $QMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","postmaster_password":"yourpassword"}' | jq

# Add a user
curl -s -X POST http://localhost:8080/domains/example.com/users \
  -H "Authorization: Bearer $QMAIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"user":"alice","password":"yourpassword"}' | jq
```

### 4. DNS records

| Type | Name | Value |
|---|---|---|
| A / AAAA | `mail.example.com` | server IP |
| MX | `example.com` | `mail.example.com` (priority 10) |
| TXT | `example.com` | `v=spf1 mx ~all` |
| TXT | `_dmarc.example.com` | `v=DMARC1; p=none; rua=mailto:dmarc@example.com` |
| TXT | `default._domainkey.example.com` | contents of `/srv/mail/qmail/control/domainkeys/example.com.dns.txt` |

---

## vpopmail auth backend

Switching backends requires two changes — one at build time, one at runtime:

1. **Build time** — vpopmail is compiled with a single backend: `--build-arg VPOPMAIL_AUTH=<backend>`
2. **Runtime** — Dovecot must use a matching driver: `DOVECOT_AUTH_DRIVER=<mysql|pgsql|ldap>`

No manual config file editing is needed. The Dovecot entrypoint writes the
correct auth config from env vars on every startup.

**MySQL (MariaDB) is the default** — both steps are pre-configured and nothing
extra is needed. PostgreSQL and LDAP are fully supported; rebuild the qmail image
with the matching `VPOPMAIL_AUTH` arg, set `DOVECOT_AUTH_DRIVER` and the
corresponding credential vars (`PGSQL_*` or `LDAP_*`) in `.env`. The entrypoints
of both containers write all connection files from env vars — no manual config
file editing needed. CDB is not recommended in a containerised setup.

qmailadmin, vqadmin, and chkuser go through vpopmail's C API and work with any
compiled backend. The **qmail-spp greylisting plugin** has its own MySQL connection
and only works with MySQL — on other backends, use **jgreylist** (file-based,
always available) or **rspamd's greylisting module** instead.

| Backend | `VPOPMAIL_AUTH` | `DOVECOT_AUTH_DRIVER` | qmail-spp greylisting | jgreylist / rspamd | qmailadmin |
|---|---|---|---|---|---|
| MySQL *(default)* | `mysql` | `mysql` (default) | ✓ | ✓ | ✓ |
| PostgreSQL | `pgsql` | `pgsql` + `PGSQL_*` vars | ✗ use jgreylist/rspamd | ✓ | ✓ |
| LDAP | `ldap` | `ldap` + `LDAP_*` vars | ✗ use jgreylist/rspamd | ✓ | ✓ |
| CDB | `cdb` | ✗ no CDB driver in Dovecot | ✗ | ✓ | ✓ |

> **`cdb` note:** Dovecot has no native CDB driver — you would need `vchkpw` as
> a checkpassword passdb, which loses container separation. CDB also has no
> concurrent-write safety across containers. Not recommended.

To switch to PostgreSQL, rebuild the qmail image and set the runtime var:

```sh
# 1. Rebuild qmail with pgsql vpopmail backend
docker compose -f docker/docker-compose.yml build \
    --build-arg VPOPMAIL_AUTH=pgsql

# 2. In .env, set the Dovecot driver and credentials
DOVECOT_AUTH_DRIVER=pgsql
PGSQL_HOST=postgres
PGSQL_DB=vpopmail
PGSQL_USER=vpopmail
PGSQL_PASS=yourpassword
```

> **Debian note:** the MySQL backend requires `--enable-libdir` pointing at the
> multiarch lib path (`/usr/lib/x86_64-linux-gnu` on amd64). The Dockerfile
> derives this automatically via `dpkg-architecture -qDEB_HOST_MULTIARCH`.

### vpopmail connection files

The qmail entrypoint writes the vpopmail backend connection file on every startup
from env vars so credential changes take effect without rebuilding:

| Backend | File | Env vars |
|---|---|---|
| MySQL | `/home/vpopmail/etc/vpopmail.mysql` | `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_DB`, `MYSQL_USER`, `MYSQL_PASS` |
| PostgreSQL | `/home/vpopmail/etc/vpopmail.pgsql` | `PGSQL_HOST`, `PGSQL_PORT`, `PGSQL_DB`, `PGSQL_USER`, `PGSQL_PASS` |

Both files use the same format: `host|port|user|password|database`

LDAP connection settings are compiled into the binary via vpopmail's configure
(`--enable-ldap-host` etc.) or read from `/home/vpopmail/etc/vpopmail.ldap`
depending on the vpopmail version — consult the vpopmail LDAP documentation for
the exact config format.

---

## MariaDB

The `mariadb` service is a prerequisite for the qmail container — qmail's
`depends_on` waits for the MariaDB healthcheck to pass before starting.

### Databases

| Database | User | Purpose |
|---|---|---|
| `vpopmail` | `vpopmail` | Domain/user/password/quota data for vpopmail, chkuser, qmailadmin, vqadmin |
| `greylisting` | `greylisting` | Triplet state for the qmail-spp greylisting plugin |

Both are created automatically on the first MariaDB start via scripts in
`docker/mariadb-init/`:

- `01-greylisting.sh` — creates the `greylisting` DB, user, and table schema

### Credentials

Set in `.env` (shared between the `mariadb` and `qmail` services):

```
MYSQL_ROOT_PASS=changeme_root
MYSQL_DB=vpopmail
MYSQL_USER=vpopmail
MYSQL_PASS=changeme
```

> **Important:** change all passwords before the first run — they are baked
> into the database volume and cannot be changed by simply editing `.env` after
> the volume has been initialised.

---

## Persistent volume

All mutable data lives under **named volumes** mounted at fixed paths.
On first run the entrypoint seeds each subdirectory from the image defaults
and replaces the original paths with symlinks.

| Volume | Mount path | Contents |
|---|---|---|
| `maildata:/srv/mail/qmail/control` | `/var/qmail/control` | Control files, TLS certs, DKIM keys, tcprules CDBs, Sieve globals |
| `maildata:/srv/mail/qmail/queue` | `/var/qmail/queue` | Mail queue |
| `maildata:/srv/mail/qmail/overlimit` | `/var/qmail/overlimit` | Per-user send-rate counters |
| `maildata:/srv/mail/qmail/simscan` | `/var/qmail/simscan` | `simcontrol` + compiled `simcontrol.cdb` |
| `maildata:/srv/mail/jgreylist` | `/var/qmail/jgreylist` | jgreylist state files |
| `maildata:/srv/mail/vpopmail/domains` | `/home/vpopmail/domains` | Virtual domain Maildirs (shared with Dovecot) |
| `maildata:/srv/mail/vpopmail/etc` | `/home/vpopmail/etc` | vpopmail config and DB connection strings |
| `mariadb_data` | `/var/lib/mysql` | MariaDB data directory |
| `clamav_data` | `/var/lib/clamav` | ClamAV virus definitions (~250 MB) |
| `rspamd_data` | `/var/lib/rspamd` | Rspamd state and learned data |
| `redis_data` | `/data` | Redis Bayes + fuzzy hash state |
| `acme_webroot` | `/var/www/acme` (qmail) | ACME HTTP-01 challenge tokens written by certbot, served by lighttpd |
| `letsencrypt` | `/etc/letsencrypt` (qmail) | Let's Encrypt certificates and account data |

### Backup

```sh
# qmail volume
docker run --rm \
    -v maildata:/srv/mail \
    -v $(pwd):/backup \
    debian:bookworm-slim \
    tar czf /backup/maildata-$(date +%F).tar.gz /srv/mail

# MariaDB
docker compose -f docker/docker-compose.yml exec mariadb \
    mariadb-dump -u root -p"$MYSQL_ROOT_PASS" --all-databases \
    > backup-$(date +%F).sql
```

---

## Environment variables

All variables can be set in `docker/.env` — Docker Compose loads it
automatically. See `.env.example` for a fully commented reference.

### Server identity

| Variable | Default | Description |
|---|---|---|
| `QMAIL_ME` | **required** | FQDN of this server (`mail.example.com`) |
| `QMAIL_DOMAIN` | derived from `QMAIL_ME` | Primary virtual domain, created in vpopmail on first run |

### Dovecot auth backend

| Variable | Default | Description |
|---|---|---|
| `DOVECOT_AUTH_DRIVER` | `mysql` | Auth driver for Dovecot: `mysql`, `pgsql`, or `ldap` — must match `VPOPMAIL_AUTH` build arg |

### MariaDB

Used when `DOVECOT_AUTH_DRIVER=mysql` (default).

| Variable | Default | Description |
|---|---|---|
| `MYSQL_HOST` | `mariadb` | MariaDB hostname |
| `MYSQL_PORT` | `3306` | MariaDB port |
| `MYSQL_DB` | `vpopmail` | vpopmail database name |
| `MYSQL_USER` | `vpopmail` | vpopmail database user |
| `MYSQL_PASS` | `changeme` | vpopmail database password |
| `MYSQL_ROOT_PASS` | `changeme_root` | MariaDB root password (not used by Dovecot) |

### PostgreSQL

Used when `DOVECOT_AUTH_DRIVER=pgsql`. The vpopmail schema must already exist in PostgreSQL.

| Variable | Default | Description |
|---|---|---|
| `PGSQL_HOST` | — | PostgreSQL hostname |
| `PGSQL_PORT` | `5432` | PostgreSQL port |
| `PGSQL_DB` | `vpopmail` | vpopmail database name |
| `PGSQL_USER` | — | PostgreSQL user |
| `PGSQL_PASS` | — | PostgreSQL password |

### LDAP

Used when `DOVECOT_AUTH_DRIVER=ldap`. Assumes the standard vpopmail LDAP schema
(`objectClass=qmailUser`, `mail=user@domain`). Override the filter/attr vars if
your schema differs.

| Variable | Default | Description |
|---|---|---|
| `LDAP_HOST` | — | LDAP server hostname |
| `LDAP_PORT` | `389` | LDAP port |
| `LDAP_BASE` | — | Base DN for user searches |
| `LDAP_BIND_DN` | — | Bind DN for Dovecot (leave empty for anonymous bind) |
| `LDAP_BIND_PW` | — | Bind password |
| `LDAP_TLS` | `no` | Enable STARTTLS (`yes`/`no`) |
| `LDAP_USER_FILTER` | `(&(objectClass=qmailUser)(mail=%u))` | Search filter — `%u` expands to `user@domain` |
| `LDAP_PASS_ATTRS` | `userPassword=password` | Password attribute mapping |
| `LDAP_USER_ATTRS` | `homeDirectory=home,=uid=89,=gid=2109` | User attribute mapping |

### Queue / concurrency

| Variable | Default | Description |
|---|---|---|
| `QMAIL_SOFTLIMIT` | `64000000` | Memory limit in bytes per SMTP process |
| `QMAIL_CONCURRENCY_INCOMING` | `200` | Max simultaneous inbound SMTP connections |
| `QMAIL_CONCURRENCY_REMOTE` | `20` | Max simultaneous outbound deliveries |
| `QMAIL_CONCURRENCY_LOCAL` | `10` | Max simultaneous local deliveries |
| `QMAIL_DATABYTES` | `20000000` | Max message size in bytes (`0`=unlimited) |
| `QMAIL_MAXRCPT` | `100` | Max recipients per message |
| `QMAIL_QUEUELIFETIME` | `272800` | Seconds a message stays in queue before bouncing (~3 days) |

### Feature layer toggles

SPF, DKIM verification, DNSBL, and SURBL are each implemented in both
qmail-smtpd and rspamd. These vars assign ownership to one layer; the other
is disabled automatically at container start.

| Variable | Default | Controls |
|---|---|---|
| `SPF_LAYER` | `rspamd` | SPF sender policy check |
| `DKIM_VERIFY_LAYER` | `rspamd` | DKIM signature verification on inbound mail |
| `DNSBL_LAYER` | `rspamd` | DNS/RBL blocklist queries |
| `SURBL_LAYER` | `rspamd` | URI/SURBL blocklist checks |

- **`rspamd`** (default) — rspamd module active; qmail feature disabled
- **`qmail`** — qmail-smtpd feature active; rspamd module written to `override.d` with `enabled = false;`

When `DNSBL_LAYER=qmail`, blocklist servers come from `QMAIL_DNSBL_SERVERS`
(space-separated; prefix with `-` for hard reject). If unset, defaults to
`zen.spamhaus.org`, `b.barracudacentral.org`, `psbl.surriel.com`, `bl.spamcop.net`.

When `SURBL_LAYER=qmail`, the TLD lists (`level2-tlds`, `level3-tlds`) are
downloaded from `surbl.org` on first use and cached in `control/` (volume-persisted).
Delete them to force a re-download. A monthly cron job (23rd at 02:02) keeps them
current; a daily job (09:02) purges the URI lookup cache in `control/cache/`.

### SMTP behaviour

| Variable | Default | Description |
|---|---|---|
| `QMAIL_SPFBEHAVIOR` | `3` | SPF reject mode when `SPF_LAYER=qmail`: `1`=neutral, `2`=softfail, `3`=fail→reject |
| `QMAIL_DNSBL_SERVERS` | see above | RBL servers when `DNSBL_LAYER=qmail` (space-separated, `-` prefix = hard reject) |
| `QMAIL_GREETDELAY` | `5` | Seconds to delay SMTP greeting (anti-spam) |
| `QMAIL_CHKUSER_WRONGRCPTLIMIT` | `3` | Max invalid recipients before disconnect (all ports) |
| `QMAIL_BRTLIMIT` | `2` | Max non-existent recipients before disconnect (brtlimit patch) |
| `QMAIL_BOUNCEFROM` | `noreply` | Envelope sender name for bounce messages |
| `QMAIL_RELAY_LIMIT` | `1000` | Max messages an auth user/domain/IP may send per period (`0`=unlimited) |
| `QMAIL_DUALSTACK` | `0` | Bind on `::` for IPv4+IPv6 dual-stack (`1`=on, requires Docker IPv6) |
| `QMAIL_GREYLISTING` | `0` | Enable jgreylist binary wrapper on port 25 (`1`=on) |
| `QMAIL_SPF_EXP` | — | Custom SPF failure explanation message (optional) |

### SMTP run-script env vars (passed to qmail-smtpd)

| Variable | Default | Description |
|---|---|---|
| `UNSIGNED_SUBJECT` | `1` | Allow DKIM-signed mail where Subject is absent from `h=` tag |
| `HELO_DNS_CHECK` | — | HELO hostname DNS validation modes (e.g. `PLRIV`) |
| `REJECTNULLSENDERS` | — | Reject messages with empty envelope sender (`<>`) when set |

### TLS

| Variable | Default | Description |
|---|---|---|
| `QMAIL_TLS_CERT_B64` | — | Base64-encoded TLS certificate PEM (`base64 -w0 fullchain.pem`) — takes priority over file-path vars, no volume needed |
| `QMAIL_TLS_KEY_B64` | — | Base64-encoded TLS private key PEM (`base64 -w0 privkey.pem`) |
| `QMAIL_TLS_CERT` | — | Container-internal path to TLS certificate PEM — file must be accessible via a volume or bind-mount |
| `QMAIL_TLS_KEY` | — | Container-internal path to TLS private key PEM |
| `QMAIL_DH_BITS` | `2048` | DH parameter bit size (`2048` or `4096`) |
| `QMAIL_TLS_CIPHERS` | `HIGH:MEDIUM:!MD5:!RC4:!3DES:!LOW:!SSLv2:!SSLv3` | Allowed TLS cipher suite |
| `QMAIL_SNI_CERTS` | — | Semicolon-separated `domain:cert:key` triplets for SNI (see TLS section) |

### Relay / access control

| Variable | Default | Description |
|---|---|---|
| `QMAIL_RELAY_NETS` | — | Comma-separated IPs/prefixes trusted to relay on port 25 |
| `QMAIL_TAPS` | — | Semicolon-separated tap rules `TYPE:REGEX:DEST` (`F`=from, `T`=to, `A`=all) |

### qmail-spp greylisting plugin

| Variable | Default | Description |
|---|---|---|
| `GREYLIST_USER` | — | Database user — **set this to enable the plugin** |
| `GREYLIST_PASS` | `changeme_grey` | Database password |
| `GREYLIST_DB` | `greylisting` | Database name |
| `GREYLIST_HOST` | `mariadb` | Database host |
| `GREYLIST_BLOCK_EXPIRE` | `2` | Minutes a new sender is greylisted |
| `GREYLIST_RECORD_EXPIRE` | `2000` | Minutes until an unseen triplet is purged |
| `GREYLIST_RECORD_EXPIRE_GOOD` | `36` | Hours a good sender stays whitelisted |
| `GREYLIST_LOGLEVEL` | `4` | Plugin log verbosity |

### Web admin

| Variable | Default | Description |
|---|---|---|
| `VQADMIN_USER` | `admin` | vqadmin HTTP basic auth username |
| `VQADMIN_PASS` | auto-generated | vqadmin password — printed to logs on first run if not set |

---

## Exposed ports

| Port | Protocol | Service |
|---|---|---|
| `25` | SMTP | Inbound mail |
| `80` | HTTP | qmailadmin web interface |
| `110` | POP3 | Mail retrieval |
| `143` | IMAP | Mail retrieval (Dovecot) |
| `465` | SMTPS | SMTP over implicit TLS |
| `587` | Submission | Authenticated outbound (STARTTLS required) |
| `993` | IMAPS | IMAP over TLS (Dovecot) |
| `995` | POP3S | POP3 over TLS (Dovecot) |
| `4190` | ManageSieve | Sieve script management (Dovecot) |

---

## Runit services

The **qmail** container runs eight supervised services under `runsvdir`:

| Service | Port | Notes |
|---|---|---|
| `qmail-smtpd` | 25 | chkuser, SPF, SURBL, DKIM verify → simscan → rspamd → queue; optional jgreylist + spp greylisting |
| `qmail-send` | — | Queue manager; DKIM signing via `control/filterargs` at remote delivery |
| `qmail-submission` | 587 | Auth required (`SMTPAUTH=!`), `FORCETLS=1`, rate limiting, simscan → rspamd |
| `qmail-smtps` | 465 | Auth required, implicit TLS via `sslserver`, rate limiting, simscan → rspamd |
| `lighttpd` | 80 | qmailadmin + vqadmin CGI |
| `vusaged` | — | vpopmail quota usage daemon |
| `cron` | — | Debian cron (`cron -f`); crontab written by entrypoint on every start |
| `qmailapi` | 8080 | Flask REST API for domain/user management (internal; requires `QMAIL_API_KEY`) |

For a full breakdown of every trigger, control file, and env var across all three SMTP ports see [`smtp.md`](smtp.md).

IMAP/POP3/Sieve run in the **dovecot** container (see Dovecot section below).

Logs are written via `svlogd` to `/var/log/qmail/<service>/`.

```sh
docker compose -f docker/docker-compose.yml exec qmail \
    sv status /etc/service/*
```

---

## TLS certificates

Both qmail (`sslserver`) and Dovecot read a combined PEM at
`/var/qmail/control/servercert.pem` (certificate block first, then private key).
DH parameters are stored at `/var/qmail/control/dh4096.pem`.

The entrypoint runs the cert setup on **every startup**, so a container restart
is all that's needed to pick up a renewed certificate.

| Priority | Condition | Result |
|---|---|---|
| 1 | `QMAIL_TLS_CERT_B64` + `QMAIL_TLS_KEY_B64` set | Decoded and combined into `servercert.pem` — no volume needed |
| 2 | `QMAIL_TLS_CERT` + `QMAIL_TLS_KEY` set and files exist | Combines the two files into `servercert.pem` |
| 3 | `QMAIL_TLS_CERT`/`KEY` set but files missing | Warning logged; falls through to next rule |
| 4 | `servercert.pem` already in volume | Used as-is |
| 5 | None of the above | Self-signed cert generated for `QMAIL_ME` |

### Option 1 — Self-signed (default)

Leave `QMAIL_TLS_CERT` and `QMAIL_TLS_KEY` unset. A self-signed cert is generated
for `QMAIL_ME` on first run. Fine for testing; mail clients will show a TLS warning.

### Option 2 — Ready cert (existing PEM files)

If you already have a cert from any CA (commercial, another ACME client, etc.),
there are two ways to supply it.

#### 2a — Bind-mount (files on the host)

Bind-mount the host directory containing your PEM files into the container, then
set the env vars to the **container-internal** paths.

In `docker-compose.yml`, uncomment the bind-mount in the qmail `volumes` section
and adjust the host path (left side of `:`):
```yaml
- /host/path/to/certs:/etc/ssl/mail:ro
```

In `.env`, point to the container-internal path (right side of `:`):
```
QMAIL_TLS_CERT=/etc/ssl/mail/fullchain.pem
QMAIL_TLS_KEY=/etc/ssl/mail/privkey.pem
```

#### 2b — Inline base64 (no volume needed)

Encode the PEM files and paste them directly into `.env`. Takes priority over
the file-path vars — no bind-mount or volume required.

```sh
# On the host, generate the values:
base64 -w0 fullchain.pem && echo
base64 -w0 privkey.pem && echo
```

```env
# .env
QMAIL_TLS_CERT_B64=LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t...
QMAIL_TLS_KEY_B64=LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0t...
```

Useful for CI/CD pipelines, Docker secrets passed as env vars, or any environment
where mounting host paths is inconvenient.

---

Restart qmail after any cert renewal to re-combine the PEM:
```sh
docker compose -f docker/docker-compose.yml restart qmail
```

### Option 3 — Let's Encrypt via certbot

The compose file includes an optional `certbot` service using the **HTTP-01**
challenge. It is gated behind the `certbot` profile and never starts with a
plain `docker compose up`.

lighttpd (port 80, already running for qmailadmin) serves the ACME challenge
tokens from the shared `acme_webroot` volume at `/.well-known/acme-challenge/`.

#### Initial setup

Add to `.env`:
```
CERTBOT_EMAIL=you@example.com
CERTBOT_DOMAIN=mail.yourdomain.com   # defaults to QMAIL_ME if omitted

# Container-internal paths — certbot writes to the letsencrypt named volume,
# which is mounted at /etc/letsencrypt inside the qmail container.
QMAIL_TLS_CERT=/etc/letsencrypt/live/mail.yourdomain.com/fullchain.pem
QMAIL_TLS_KEY=/etc/letsencrypt/live/mail.yourdomain.com/privkey.pem
```

Issue the certificate (the stack must be running and port 80 reachable):
```sh
docker compose -f docker/docker-compose.yml --profile certbot run --rm certbot
```

Restart qmail to install it:
```sh
docker compose -f docker/docker-compose.yml restart qmail
```

#### Renewal

Certbot uses `--keep-until-expiring` — running it again is a no-op unless the
cert is within 30 days of expiry. Add a cron job for automatic renewal:

```
# /etc/cron.d/certbot-qmail
0 3 * * * root docker compose --profile certbot \
    -f /path/to/qmail/docker/docker-compose.yml \
    run --rm certbot \
  && docker compose \
    -f /path/to/qmail/docker/docker-compose.yml \
    restart qmail
```

#### Certbot env vars

| Variable | Default | Description |
|---|---|---|
| `CERTBOT_EMAIL` | — | Contact email for Let's Encrypt expiry notices |
| `CERTBOT_DOMAIN` | `QMAIL_ME` | Domain to issue the cert for |

### SNI — multiple domains

```yaml
environment:
  QMAIL_SNI_CERTS: "mail2.example.org:/etc/letsencrypt/live/mail2.example.org/fullchain.pem:/etc/letsencrypt/live/mail2.example.org/privkey.pem"
```

Semicolon-separate multiple triplets for additional domains. On every startup
the entrypoint combines each cert+key into
`control/servercerts/<domain>/servercert.pem` and generates
`control/dovecot-sni.conf` with `local_name` blocks for Dovecot.

---

## Greylisting

Two independent greylisting mechanisms are available and can run simultaneously.

### jgreylist (file-based, port 25 only)

Wraps `qmail-smtpd` as a binary in the port 25 run script. No database required.

```yaml
environment:
  QMAIL_GREYLISTING: 1
```

State files persist in `/srv/mail/jgreylist`. Purge expired entries periodically:

```sh
docker compose -f docker/docker-compose.yml exec qmail \
    /var/qmail/bin/jgreylist-clean
```

### qmail-spp greylisting plugin (MySQL-backed, all ports)

Runs inside `qmail-smtpd` via the SPP plugin system. Uses the `greylisting`
MariaDB database. Supports per-IP exemptions, pass/block statistics, and
automatic bypass for authenticated users (`ifauthskip`).

**Enable** by setting `GREYLIST_USER` in `.env`:

```
GREYLIST_USER=greylisting
GREYLIST_PASS=strongpassword
GREYLIST_DB=greylisting
```

On first run the entrypoint writes:
- `control/mysql.cnf` — database connection config for the plugin
- `control/greylisting` — plugin settings (block/expire times, log level)
- `control/smtpplugins` — activates `plugins/ifauthskip` and `plugins/greylisting`

The `greylisting` database and schema are created automatically on the first
MariaDB start via `docker/mariadb-init/01-greylisting.sh`.

**Tune** settings via env vars or by editing `control/greylisting` in the volume:

```
mysql_default_file=control/mysql.cnf
block_expire=2          # minutes
record_expire=2000      # minutes
record_expire_good=36   # hours
loglevel=4
```

Purge stale records periodically:

```sh
docker compose -f docker/docker-compose.yml exec qmail \
    /usr/local/sbin/greylisting_cleanup.sh
```

---

## Rate limiting

`rcptcheck-overlimit` limits how many messages an authenticated user, domain,
or IP may send per reset period. It is always installed in the image and active
on ports 587 and 465. Messages to local domains (in `rcpthosts`) are never
counted — only outbound relay traffic is subject to the limit.

The default limit is set by `QMAIL_RELAY_LIMIT` (default: `1000`). On first run
the entrypoint writes `/var/qmail/control/relaylimits`:

```
# Per-user/domain/IP limits — edit directly for overrides
:1000
```

Override per user/domain/IP by editing the file:

```
poweruser@example.com:5000
example.com:2000
1.2.3.4:0          # 0 = unlimited
:1000              # catch-all default
```

> **Limit semantics:** the check is `current > limit`, so a limit of `N` allows
> `N + 1` accepted RCPT TOs before the next one is rejected with a `421`. Set
> `N` one lower than the intended cap if an exact cut-off matters.

Per-period counts are stored in `/srv/mail/qmail/overlimit` (persisted in the
volume). Reset them by purging that directory or running a cron job:

```sh
# Reset all counters (e.g. from a daily cron job)
docker compose -f docker/docker-compose.yml exec qmail \
    sh -c 'rm -f /var/qmail/overlimit/*'
```

---

## Managing virtual domains and users

```sh
# Add a domain
docker compose -f docker/docker-compose.yml exec qmail \
    /home/vpopmail/bin/vadddomain example.com

# Add a user
docker compose -f docker/docker-compose.yml exec qmail \
    /home/vpopmail/bin/vadduser user@example.com password

# Delete a user
docker compose -f docker/docker-compose.yml exec qmail \
    /home/vpopmail/bin/vdeluser user@example.com

# List users in a domain
docker compose -f docker/docker-compose.yml exec qmail \
    /home/vpopmail/bin/vdominfo example.com
```

---

## DKIM signing and verification

DKIM is automatically configured on first run:

- **Signing**: Outbound mail is signed via `spawn-filter` using keys in `control/domainkeys/<domain>/default`
- **Verification**: Inbound mail verified via `qmail-dkim`; `UNSIGNED_SUBJECT=1` allows messages where Subject is absent from the `h=` tag

### View DKIM DNS record

```
/srv/mail/qmail/control/domainkeys/<domain>.dns.txt
```

Add as `default._domainkey.<domain>` TXT record.

### Generate key for additional domain

```sh
docker compose -f docker/docker-compose.yml exec qmail \
    /var/qmail/bin/dknewkey -d newdomain.com -t rsa -b 2048 default
```

---

## DNS blocklists (DNSBL/RBL)

By default (`DNSBL_LAYER=rspamd`) rspamd handles RBL checks. To use qmail's
built-in DNSBL instead, set `DNSBL_LAYER=qmail` in `.env`. The entrypoint
will populate `control/dnsbllist` from `QMAIL_DNSBL_SERVERS`, or fall back to
the defaults (`zen.spamhaus.org`, `b.barracudacentral.org`, `psbl.surriel.com`,
`bl.spamcop.net`). Prefix a server with `-` for hard reject (553) vs soft
reject (451).

To customise the server list directly:

```sh
docker compose -f docker/docker-compose.yml exec qmail \
    vi /var/qmail/control/dnsbllist
```

---

## qmailadmin web interface

Access at `http://<server-ip>/`. Login with domain, username, and vpopmail password.

Features: add/edit/delete users and aliases, autoresponders, mail forwarding,
mailing lists (ezmlm-idx), mailbox quotas.

---

## vqadmin (system admin)

Access at `http://<server-ip>/cgi-bin/vqadmin/vqadmin.cgi`. Requires HTTP basic
auth — credentials set via `VQADMIN_USER` / `VQADMIN_PASS` (auto-generated and
printed to logs on first run if not set).

```sh
# Change password on running container
docker compose -f docker/docker-compose.yml exec qmail \
    htpasswd /var/qmail/control/vqadmin.htpasswd admin
```

---

## Domain management REST API

A Flask REST API runs inside the qmail container on port 8080 (internal only
by default). It automates the full domain and user lifecycle via the vpopmail
CLI tools.

Set `QMAIL_API_KEY` in `.env` to enable it (generate with `openssl rand -hex 16`).
Uncomment the `127.0.0.1:8080:8080` port mapping in `docker-compose.yml` to
expose it to the host.

All requests require: `Authorization: Bearer <QMAIL_API_KEY>`

### Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/domains` | List all domains |
| `POST` | `/domains` | Add domain — full setup (see below) |
| `GET` | `/domains/<domain>` | Get domain info + DNS records |
| `DELETE` | `/domains/<domain>` | Delete domain |
| `GET` | `/domains/<domain>/users` | List users |
| `POST` | `/domains/<domain>/users` | Add user |
| `DELETE` | `/domains/<domain>/users/<user>` | Delete user |
| `PUT` | `/domains/<domain>/users/<user>/password` | Change password |

### Add domain — full setup

`POST /domains` with `{"domain": "example.com", "postmaster_password": "secret"}`:

1. `vadddomain` — creates vpopmail domain, adds to `rcpthosts`
2. Replaces `.qmail-default` with LMTP delivery to Dovecot
3. `dknewkey` — generates RSA-2048 DKIM key pair
4. `qmail-newu` — rebuilds `users/assign` so qmail routes the domain

Response includes `dns_records` with all records to publish:

```json
{
  "domain": "example.com",
  "postmaster": "postmaster@example.com",
  "dns_records": {
    "MX":    {"host": "@",                 "priority": 10, "value": "mail.youserver.com"},
    "SPF":   {"host": "@",                 "type": "TXT",  "value": "v=spf1 mx ~all"},
    "DMARC": {"host": "_dmarc",            "type": "TXT",  "value": "v=DMARC1; p=none; ..."},
    "DKIM":  {"host": "default._domainkey","type": "TXT",  "record": "default._domainkey.example.com. IN TXT (...)"}
  }
}
```

### Example

```sh
API=http://127.0.0.1:8080
KEY=your-api-key

# Add domain
curl -s -X POST $API/domains \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","postmaster_password":"secret"}' | jq .

# Add user
curl -s -X POST $API/domains/example.com/users \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"user":"alice","password":"pass"}' | jq .
```

---

## Dovecot

Dovecot runs in its own container with SQL authentication against MariaDB (no
`vchkpw` binary needed). Mail is delivered from qmail via **LMTP** on TCP port 24:

```
qmail-local → /var/qmail/bin/lmtp-deliver → dovecot :24 → Sieve → Maildir
```

### Dovecot service toggles

| Variable | Default | Description |
|---|---|---|
| `DOVECOT_IMAP` | `false` | IMAP on port 143 (plaintext) |
| `DOVECOT_IMAPS` | `true` | IMAP over TLS on port 993 |
| `DOVECOT_POP3` | `false` | POP3 on port 110 (plaintext) |
| `DOVECOT_POP3S` | `true` | POP3 over TLS on port 995 |
| `DOVECOT_SIEVE` | `true` | ManageSieve on port 4190 |
| `DOVECOT_LMTP` | `true` | LMTP listener on port 24 (required for mail delivery) |

### Dovecot rspamd env vars

| Variable | Default | Description |
|---|---|---|
| `RSPAMD_HOST` | `rspamd` | rspamd container hostname for spam/ham learning |
| `RSPAMD_PORT` | `11333` | rspamd scanner HTTP API port |
| `RSPAMD_CONTROLLER_PORT` | `11334` | rspamd controller port (used by learn-spam/ham scripts) |
| `RSPAMD_PASSWORD` | `changeme_rspamd` | rspamd controller password — must match `RSPAMD_PASSWORD` in the rspamd service |

---

## Sieve filtering and ManageSieve

Mail is delivered via **Dovecot LMTP**, enabling Sieve filtering on every
inbound message:

```
qmail-local → lmtp-deliver → dovecot LMTP :24 → Sieve → Maildir
```

ManageSieve (port 4190) lets mail clients upload and manage Sieve scripts.

### Global Sieve scripts

| Directory | Runs |
|---|---|
| `/srv/mail/qmail/control/sieve/before.d/` | Before user's script |
| `/srv/mail/qmail/control/sieve/after.d/` | After user's script |

```sh
# Compile after adding/changing a global script
docker compose -f docker/docker-compose.yml exec qmail \
    sievec /var/qmail/control/sieve/before.d/10-spam.sieve
```

Example spam-to-Junk script — pairs with the IMAPSieve learning below:

```sieve
require ["fileinto", "mailbox"];
if header :contains "X-Spam-Flag" "YES" {
    fileinto :create "Junk";
    stop;
}
```

### Spam/ham learning via folder moves (IMAPSieve)

Moving a message **into** `Junk` or `Spam` via IMAP triggers rspamd Bayes
learning automatically — no client plugin needed. Moving it back out (not to
Trash) teaches ham.

```
Move to Junk/Spam   →  POST rspamd:11334/learnspam  (Password: …, User: alice@example.com)
Move out of Junk    →  POST rspamd:11334/learnham   (Password: …, User: alice@example.com)
```

The authenticated IMAP username is captured by the Sieve script and forwarded
as a `User:` header so rspamd maintains **per-user Bayes** state in Redis.
Users whose mail habits differ (e.g. mailing-list heavy vs. transactional)
each train their own classifier without cross-contamination.

The scripts live in the image at `/etc/dovecot/sieve/` and are pre-compiled at
build time. rspamd credentials are written to `/etc/dovecot/sieve/rspamd.env`
(owned by `vpopmail`, mode `0600`) at container start from the `RSPAMD_*` env
vars — they never appear in the scripts themselves.

---

## ClamAV + simscan

[ClamAV](https://www.clamav.net) runs `clamd` + `freshclam` in its own container.
[Simscan](https://github.com/sagredo-dev/simscan) is a `qmail-queue` wrapper
built into the qmail image that passes every message to Rspamd before queueing.
Rspamd owns antivirus scanning — it calls clamd directly via its `antivirus`
module, so virus verdicts combine with spam, DMARC, RBL, and Bayes signals in
one place.

### Delivery chain

```
qmail-smtpd
  → QMAILQUEUE=qmail-dkim        (DKIM verification)
  → DKIMQUEUE=simscan            (when SIMSCAN_ENABLE=true)
      └── rspamd-spamc ──HTTP──► rspamd :11333
                                     └── antivirus ──INSTREAM──► clamd :3310
  → /var/qmail/bin/qmail-queue
```

Both rspamd and clamd fail open — if either daemon is unreachable, mail passes
through rather than being rejected.

### Simscan env vars

| Variable | Default | Description |
|---|---|---|
| `SIMSCAN_ENABLE` | `true` | Master toggle — `false` bypasses simscan on all ports |
| `SIMSCAN_CLAM` | `no` | ClamAV in simscan — disabled; rspamd owns AV via its antivirus module |
| `SIMSCAN_SPAM` | `yes` | Rspamd spam scanning |
| `SIMSCAN_SPAM_HITS` | `9.0` | Spam score rejection threshold |
| `SIMSCAN_SIZE_LIMIT` | `20000000` | Max bytes to scan (`0`=unlimited) |
| `SIMSCAN_ATTACH` | — | Blocked attachment extensions, semicolon-separated (e.g. `.vbs;.lnk;.scr`) |
| `SIMSCAN_DEBUG` | `0` | Debug verbosity 0–4 |
| `RSPAMD_TAG_ONLY` | `false` | When `true`, rspamd adds headers but simscan never rejects on spam score |

These are written into `/var/qmail/simscan/simcontrol` on first run. To apply
changes on an existing volume, delete the file and restart, or edit it directly
for per-domain overrides:

```
# Format: [user@]domain:option=value,...
user@example.com:spam=yes,spam_hits=6.0,attach=.vbs:.lnk:.scr
example.com:spam=yes,spam_hits=7.0
:spam=yes,spam_hits=9.0,size_limit=20000000
```

After editing, recompile:

```sh
docker compose -f docker/docker-compose.yml exec qmail \
    /var/qmail/bin/simscanmk
```

---

## Rspamd

[Rspamd](https://rspamd.com) handles spam scoring, antivirus (via ClamAV),
DKIM verification, DMARC, SPF, RBL checks, and Bayes learning (state in Redis).
It is called by simscan via the `rspamd-spamc` wrapper over the HTTP API on
port 11333.

Web UI is available at `http://<host>:11334/`.

### Rspamd env vars

| Variable | Default | Description |
|---|---|---|
| `RSPAMD_PASSWORD` | `changeme_rspamd` | Web UI + controller password — set in `.env`, hash generated automatically at container start |
| `RSPAMD_HOST` | `rspamd` | rspamd hostname used by the `rspamd-spamc` wrapper in the qmail container |
| `RSPAMD_PORT` | `11333` | rspamd scanner HTTP API port |
| `RSPAMD_TAG_ONLY` | `false` | Tag-only mode — rspamd scores and adds headers but simscan never rejects on spam score |

### Controller password

The rspamd controller password (used by the web UI and Dovecot learn scripts)
is configured via the `RSPAMD_PASSWORD` env var. The container entrypoint
runs `rspamadm pw` at startup to hash the value and writes it to
`/etc/rspamd/override.d/worker-controller.inc`.

To change the password, update `RSPAMD_PASSWORD` in `.env` and restart:

```sh
# In .env:
RSPAMD_PASSWORD=your_strong_password

docker compose -f docker/docker-compose.yml up -d rspamd
```

### Rspamd local config

Custom overrides go in `docker/rspamd/local.d/` — mounted read-only into the
container. Files present:

| File | Purpose |
|---|---|
| `antivirus.conf` | ClamAV via clamd TCP — reject on `CLAM_VIRUS`, fail open if clamd unreachable |
| `redis.conf` | Redis backend for all modules |
| `classifier-bayes.conf` | Bayes with Redis + autolearn |
| `greylist.conf` | Greylisting disabled (qmail-spp handles it) |
| `dkim_signing.conf` | DKIM signing disabled (qmail-dkim handles it) |
| `tika.conf` | Apache Tika URL + timeout + MIME type filter for attachment extraction |
| `external_services.conf` | olefy connection + MIME type + extension filter for Office macro scanning |
| `composites.conf` | `OLETOOLS_MACRO_MRAPTOR` + `OLETOOLS_MACRO_SUSPICIOUS` composite expressions |
| `force_actions.conf` | Force reject on macro composites; soft reject on `OLETOOLS_FAIL` |

---

## Tika (attachment text extraction)

[Apache Tika](https://tika.apache.org) runs as a server and extracts plain text
from binary attachments. rspamd submits attachments over HTTP and applies spam
rules and the Bayes classifier to the extracted content, catching payloads hidden
inside documents that would otherwise be opaque.

```
rspamd :11333
  └── attachment (PDF/DOCX/XLSX/…)
        └── HTTP → tika :9998 → extracted text
                                  └── rspamd rules / Bayes
```

Tika is optional — if the container is not reachable, rspamd skips extraction
silently. Port 9998 is internal only.

### Tika env vars

| Variable | Default | Description |
|---|---|---|
| `TIKA_JAVA_OPTS` | `-Xms128m -Xmx512m` | JVM heap settings — increase `-Xmx` if Tika OOMs on large attachments |

---

## Oletools (Office macro scanning)

[olefy](https://github.com/HeinleinSupport/olefy) wraps
[olevba](https://github.com/decalage2/oletools) as a TCP daemon. rspamd submits
Office attachments via the `external_services` module, olevba analyses them for
macro capabilities, and rspamd rejects documents matching the detection composites.

```
rspamd :11333
  └── Office attachment (doc/xls/ppt/…)
        └── TCP → olefy :11343 → olevba → capability flags
                                             └── OLETOOLS_* symbols → composites → reject
```

### Enabling

Oletools is **optional** — gated behind the `macros` compose profile:

```sh
# Build the image
docker compose -f docker/docker-compose.yml --profile macros build oletools

# Start with macro scanning enabled
docker compose -f docker/docker-compose.yml --profile macros up -d
```

When the container is not running, rspamd times out connecting to olefy and
passes mail through without macro scanning (fail-open).

### Detection logic

| Composite | Expression | Score | Action |
|---|---|---|---|
| `OLETOOLS_MACRO_MRAPTOR` | `(A & W) \| (A & X) \| (W & X)` | 20.0 | reject |
| `OLETOOLS_MACRO_SUSPICIOUS` | `FLAG \| VBASTOMP \| A` | 20.0 | reject |
| `OLETOOLS_FAIL` | olevba scan error | — | soft reject |

Where: A = macro present, W = write to disk, X = execute process, FLAG = olevba suspicious keyword, VBASTOMP = VBA stomping detected.

### Rspamd config files

| File | Purpose |
|---|---|
| `external_services.conf` | olefy connection, timeout, MIME type + extension filter |
| `composites.conf` | `OLETOOLS_MACRO_MRAPTOR` and `OLETOOLS_MACRO_SUSPICIOUS` composite expressions |
| `force_actions.conf` | Force reject on composites; soft reject on `OLETOOLS_FAIL` |

### Oletools env vars

| Variable | Default | Description |
|---|---|---|
| `OLEFY_LOGLEVEL` | `20` | Python log level (`10`=DEBUG, `20`=INFO, `30`=WARNING) |

---

## tcprules (relay and recipient policy)

| File | Port | Purpose |
|---|---|---|
| `tcp.smtp` | 25 | Inbound — trusted IPs get `RELAYCLIENT=""` |
| `tcp.submission` | 587 | Auth submission — relay gated by `SMTPAUTH` |
| `tcp.smtps` | 465 | Same as submission over implicit TLS |

CDB files are seeded once on first run. To update rules on a live container:

```sh
docker compose -f docker/docker-compose.yml exec qmail \
    sh -c 'vi /var/qmail/control/tcp.smtp && \
           tcprules /var/qmail/control/tcp.smtp.cdb \
                    /var/qmail/control/tcp.smtp.tmp \
                    < /var/qmail/control/tcp.smtp'
```

To regenerate from env vars, remove the CDB files and restart:

```sh
docker compose -f docker/docker-compose.yml exec qmail \
    rm /var/qmail/control/tcp.smtp.cdb \
       /var/qmail/control/tcp.submission.cdb \
       /var/qmail/control/tcp.smtps.cdb
docker compose -f docker/docker-compose.yml restart qmail
```

---

## IPv6 / Dual-stack

```yaml
environment:
  QMAIL_DUALSTACK: 1
```

Requires IPv6 enabled in Docker (`/etc/docker/daemon.json`):

```json
{ "ipv6": true, "fixed-cidr-v6": "fd00::/80" }
```

---

## Queue management

```sh
docker compose -f docker/docker-compose.yml exec qmail \
    /var/qmail/bin/qmail-qstat

docker compose -f docker/docker-compose.yml exec qmail \
    /var/qmail/bin/qmail-qread
```
