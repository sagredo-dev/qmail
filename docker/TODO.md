# Docker TODO

## Target multi-container architecture

The goal is a clean split with **minimal shared volumes between qmail and Dovecot**.
The key enabler is the **MySQL backend** — it eliminates most filesystem coupling
between the MTA and the IMAP server. Only the Maildir volume is shared (both need
write access for domain creation and mail delivery).

```
┌──────────────────────────────────────┐
│  qmail  (MTA core)                   │  ports 25, 80, 465, 587
│                                      │
│  chkuser ──────────────────────────► │
│  qmailadmin/vqadmin ───────────────► │──── TCP ──► mariadb :3306
│  LMTP client ──────────────────────► │
│                  │                   │
│                  └── TCP ──► dovecot :24
└──────────────────────────────────────┘

┌──────────────────────────────────────┐
│  dovecot                             │  ports 110, 143, 993, 995, 4190
│                                      │
│  SQL auth ─────────────────────────► │──── TCP ──► mariadb :3306
│  LMTP listener ◄── qmail            │
│  Maildir volume (owned exclusively)  │
└──────────────────────────────────────┘

┌──────────┐  ┌──────────┐  ┌─────┐  ┌─────────┐
│  clamav  │  │  rspamd  │  │redis│  │ mariadb │
│  :3310   │  │:783/:11334│ │:6379│  │  :3306  │
└──────────┘  └──────────┘  └─────┘  └─────────┘
```

**Minimal shared volumes** — `dovecot_mail` is shared for Maildirs (qmail creates
domains, Dovecot writes mail). MariaDB handles all auth/user data over TCP.

---

## Why MySQL is the prerequisite for everything

| Problem | CDB | MySQL |
|---|---|---|
| chkuser recipient validation | needs shared vpopmail/domains volume | queries MariaDB directly — no shared volume |
| Dovecot authentication | vchkpw needs shared vpopmail binary + data | SQL driver queries MariaDB directly |
| vusaged quota tracking | cache goes stale when Dovecot deletes mail | quota stored in DB — both containers update it |
| qmail ↔ Dovecot coupling | shared filesystem | zero — only TCP to MariaDB |

MySQL backend must be implemented before the container split is attempted.

---

## ✅ Step 1 — MariaDB (vpopmail auth backend) — build verified

- [x] Spin up a `mariadb` container with healthcheck
- [x] Rebuild the qmail image with `--build-arg VPOPMAIL_AUTH=mysql`
- [x] Pass DB credentials via env vars (`MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASS`, `MYSQL_DB`)
- [x] Write `vpopmail/etc/vpopmail.mysql` from those vars in the entrypoint (format: `host|port|user|password|database`)
- [x] vpopmail configure flags: `--enable-mysql-limits`, `--enable-valias`, `--enable-sql-aliasdomains`, `--enable-incdir=/usr/include/mysql`, `--enable-libdir=/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)`
- [x] MariaDB credentials via `.env` file — compose auto-loads it
- [x] qmail service `depends_on: mariadb: condition: service_healthy`
- [x] Separate greylisting database (`greylisting` DB + user) initialised by `mariadb-init/01-greylisting.sh`
- [x] qmail-spp MySQL-backed greylisting plugin (`plugins/greylisting` + `plugins/ifauthskip`) built into image
- [x] All env vars documented in `docker-compose.yml` and `.env.example`
- [x] qmailadmin built with cracklib password strength checking (`libcrack2-dev` + `cracklib-runtime` in builder; dictionary at `/var/cache/cracklib/cracklib_dict`)
- [x] Rate limiting via `rcptcheck-overlimit` on ports 587 and 465
- [x] `vusaged` (vpopmail quota daemon) built into image — `make install` only prints instructions; compiled manually from `vusaged/` (needs `libev-dev` in builder + `libev4` in runtime)
- [x] `FORCETLS=1` on port 587; `DROP_PRE_GREET`, `SURBL`, `ENABLE_SPP` consistent across all three SMTP ports
- [x] Full image build passes cleanly on `debian:bookworm-slim`

---

## ✅ Step 2 — Dovecot split (depends on Step 1) — implemented

- [x] Dovecot in separate container (`docker/dovecot/`)
- [x] SQL auth via `driver = sql` pointing at MariaDB — no vchkpw binary needed
- [x] LMTP listener on TCP port 24 for mail delivery from qmail
- [x] Shared `dovecot_mail` volume for Maildirs (both containers have write access)
- [x] Read-only mount of `maildata` volume for TLS certs and Sieve scripts
- [x] SQL userdb query translates paths (`/home/vpopmail/domains` → `/srv/mail/vpopmail/domains`)
- [x] Bash LMTP client script (`/var/qmail/bin/lmtp-deliver`) using `/dev/tcp` — faster than Python
- [x] Service toggles via env vars:
  - `DOVECOT_IMAP`, `DOVECOT_IMAPS`, `DOVECOT_POP3`, `DOVECOT_POP3S`, `DOVECOT_SIEVE`, `DOVECOT_LMTP`
  - `QMAIL_SMTP`, `QMAIL_SMTPS`, `QMAIL_SUBMISSION`, `QMAIL_HTTP`
- [x] Default: SSL ports enabled, plaintext ports disabled
- [x] Healthchecks respect service toggles
- [x] Sieve filtering works via LMTP delivery

---

## ✅ Step 3 — ClamAV (antivirus) — implemented

- [x] `clamav/clamav:latest` container — runs `clamd` + `freshclam` in one image
- [x] `clamd` listens on TCP port 3310 (internal only — not exposed to host)
- [x] `freshclam` keeps virus definitions updated automatically
- [x] `clamav_data` volume persists definitions across restarts (~250 MB)
- [x] Healthcheck via `/usr/local/bin/clamdcheck.sh`; `start_period: 300s` (definition load)
- [x] `clamav` + `clamav-daemon` added to qmail runtime stage (ClamAV 1.4.x removed standalone `clamdscan`)
- [x] `docker/clamdscan-wrapper` (Python3 INSTREAM client) installed as `/usr/bin/clamdscan` — reads `CLAMD_HOST`/`CLAMD_PORT`
- [x] `docker/clamdscan.conf` → `/etc/clamav/clamd.conf` (TCPAddr clamav, TCPSocket 3310) — legacy path kept for reference
- [x] simscan wires `clamdscan` into the queue in Step 5

---

## ✅ Step 4 — Rspamd + Redis — implemented

- [x] `redis:7-alpine` container with healthcheck; data in `redis_data` volume
- [x] `rspamd/rspamd:latest` container depending on redis healthcheck
- [x] Redis backend for all modules (`local.d/redis.conf`)
- [x] Bayes classifier with Redis backend + autolearn (`local.d/classifier-bayes.conf`)
- [x] Greylisting disabled — handled by qmail-spp MySQL plugin (`local.d/greylist.conf`)
- [x] DKIM signing disabled — handled by qmail-dkim; verification remains active (`local.d/dkim_signing.conf`)
- [x] Web UI on port 11334 (`RSPAMD_PASSWORD` env var; hash generated automatically at container start by `docker/rspamd/entrypoint.sh` — no manual `rspamadm pw` needed)
- [x] SPF, DMARC, RBL checks enabled by default (built into rspamd)
- [x] Port 783 (spamc) is internal-only — simscan integration wired in Step 5

---

## ✅ Step 5 — Simscan (qmail-queue glue for ClamAV + Rspamd) — implemented

[Simscan](https://github.com/sagredo-dev/simscan) (v1.4.6.2) is the
`qmail-queue` wrapper that connects qmail to ClamAV and Rspamd. It rejects
viruses, spam, and bad attachments during the SMTP conversation.

```
qmail-smtpd
    └── QMAILQUEUE=qmail-dkim  (DKIM verify)
          └── DKIMQUEUE=simscan
                  ├── /usr/bin/clamdscan ──INSTREAM──► clamd   (clamav :3310)
                  └── /usr/local/bin/rspamd-spamc ────HTTP──► rspamd  (rspamd :11333)
                        └── /var/qmail/bin/qmail-queue
```

- [x] `ripMIME` compiled from source → `/usr/local/bin/ripMIME`
- [x] `rspamd` installed in runtime stage for `/usr/bin/rspamc` client binary (daemon runs in its own container)
- [x] `docker/rspamd-spamc` wrapper: calls `curl POST rspamd:11333/checkv2` (switched from `rspamc` binary which fails under 64 MB RLIMIT_AS due to libicudata mmap), inserts `X-Spam-*` headers, passes through on rspamd down
- [x] `docker/clamdscan-wrapper` (Python3): implements ClamAV INSTREAM protocol over TCP; pass-through if clamd down
- [x] simscan compiled with `--enable-spamc=/usr/local/bin/rspamd-spamc`, `--enable-clamdscan=/usr/bin/clamdscan`
- [x] clamav user + group created in builder for configure checks; clamav-daemon creates them in runtime
- [x] `/var/qmail/simscan` volume-linked (`/srv/mail/qmail/simscan`), owned by `clamav:clamav`, setuid binary
- [x] `simcontrol` written on first run from env vars; `simscanmk` runs every startup
- [x] Delivery chain: `QMAILQUEUE=qmail-dkim` → `DKIMQUEUE=simscan` → `qmail-queue` (all three SMTP ports)
- [x] `SIMSCAN_ENABLE=false` bypasses `DKIMQUEUE` entirely — mail flows direct to queue without scanning

**Simscan env vars:**

| Variable | Default | Description |
|---|---|---|
| `SIMSCAN_ENABLE` | `true` | Master toggle — `false` disables scanning on all ports |
| `SIMSCAN_CLAM` | `yes` | ClamAV scanning in simcontrol |
| `SIMSCAN_SPAM` | `yes` | Rspamd spam scanning in simcontrol |
| `SIMSCAN_SPAM_HITS` | `9.0` | Spam score threshold |
| `SIMSCAN_SIZE_LIMIT` | `20000000` | Max message bytes to scan |
| `SIMSCAN_ATTACH` | — | Blocked attachment extensions, semicolon-separated (e.g. `.vbs;.lnk;.scr`) |
| `SIMSCAN_DEBUG` | `0` | Debug verbosity 0–4 |
| `CLAMD_HOST` | `clamav` | clamd container hostname |
| `CLAMD_PORT` | `3310` | clamd TCP port |
| `RSPAMD_HOST` | `rspamd` | rspamd container hostname |
| `RSPAMD_PORT` | `11333` | rspamd HTTP API port |

---

## ✅ Step 6 — IMAPSieve spam/ham learning (Dovecot → rspamd)

When a user moves a message to/from a Junk or Spam folder via IMAP, Dovecot
fires a Sieve script that pipes the message to rspamd's HTTP API for Bayes
learning. The authenticated username is forwarded so rspamd tracks per-user
classifier state in Redis.

```
User moves message to Junk/Spam
  → imap_sieve plugin fires learn-spam.sieve
    → pipe :args ["user@example.com"] "learn-spam.sh"
      → curl POST http://rspamd:11333/learn_spam  (User: user@example.com)

User moves message out of Junk/Spam (not to Trash)
  → imap_sieve plugin fires learn-ham.sieve
    → pipe :args ["user@example.com"] "learn-ham.sh"
      → curl POST http://rspamd:11333/learn_ham   (User: user@example.com)
```

- [x] `imap_sieve` plugin enabled in `protocol imap { mail_plugins }`
- [x] `sieve_imapsieve` + `sieve_extprograms` added to Sieve plugin block
- [x] 4 mailbox rules: COPY to `Junk`/`Spam` → learn spam; COPY from `Junk`/`Spam` (not to Trash) → learn ham
- [x] `docker/dovecot/sieve/learn-spam.sieve` + `learn-ham.sieve` — IMAPSieve scripts
- [x] `imap.user` captured via `environment :matches` and passed as `:args ["${username}"]`
- [x] `docker/dovecot/sieve/scripts/learn-spam.sh` + `learn-ham.sh` — curl to rspamd controller HTTP API (`rspamd:11334/learnspam`, `/learnham`)
- [x] `User: <username>` header on every learn request — per-user Bayes state in Redis
- [x] `/etc/dovecot/sieve/rspamd.env` written at runtime by entrypoint.sh, owned `vpopmail:vchkpw`, mode `0600` — credentials out of scripts and readable by sieve pipe user
- [x] `RSPAMD_CONTROLLER_PORT=11334` written to `rspamd.env` — scripts use controller port, not scanner port
- [x] Sieve scripts pre-compiled with `sievec` in Dockerfile — syntax errors caught at build time
- [x] `curl` added to Dovecot Dockerfile
- [x] `RSPAMD_HOST`, `RSPAMD_PORT`, `RSPAMD_CONTROLLER_PORT`, `RSPAMD_PASSWORD` added to dovecot service in compose
- [x] rspamd controller password configured via `RSPAMD_PASSWORD` env var — `docker/rspamd/entrypoint.sh` generates hash and writes to `override.d/worker-controller.inc` at startup

---

## ✅ Step 7 — Tika (attachment text extraction for rspamd)

[Apache Tika](https://tika.apache.org) runs as a server and extracts plain text
from binary attachments (PDF, DOCX, XLSX, etc.). rspamd has built-in Tika
support — it submits attachments to Tika over HTTP and applies spam rules to
the extracted content. This catches spam and phishing payloads hidden inside
documents that would otherwise be opaque to content filters.

```
simscan → rspamd :11333
              └── attachment (PDF/DOCX/…)
                    └── HTTP → tika :9998 → extracted text
                                              └── rspamd rules / Bayes
```

- [x] Add `apache/tika` container to `docker-compose.yml` (port 9998, internal only)
- [x] Add `docker/rspamd/local.d/tika.conf`: `url = "http://tika:9998";` with mime type filter
- [x] Add healthcheck for tika container (`wget` against `/tika` endpoint)
- [x] Wire `tika` into rspamd `depends_on` (`service_started` — rspamd connects lazily)
- [x] `TIKA_JAVA_OPTS` env var for JVM heap tuning (default: `-Xms128m -Xmx512m`)

---

## ✅ Step 8 — Oletools / olefy (Office macro scanning via rspamd external_services)

[olefy](https://github.com/HeinleinSupport/olefy) is a TCP daemon wrapping
`olevba` from [oletools](https://github.com/decalage2/oletools). rspamd connects
to it via the `external_services` module — same pattern as ClamAV. Detects
malicious VBA macros, auto-exec routines, and VBA stomping in Office attachments
(doc, docx, xls, xlsx, ppt, pptx).

```
simscan → rspamd :11333
              └── Office attachment
                    └── TCP → olefy :11343 → olevba → macro analysis
                                                         └── OLETOOLS_* symbols
                                                               └── composite score → reject
```

**Detection logic (actual implementation):**

> Note: rspamd's `oletools.lua` produces only the base `OLETOOLS` symbol (not per-flag
> sub-symbols like `OLETOOLS_MACRO` or `OLETOOLS_WRITE`). `extended = true` mode fires
> `OLETOOLS` for any macro with any flags; default mode requires autoexec + non-hex/base64
> suspicious keywords which most real-world test files don't have.

| Composite | Triggers on | Score | Action |
|---|---|---|---|
| `OLETOOLS_DETECTED` | `OLETOOLS` (any macro in extended mode) | 20.0 | reject |
| `OLETOOLS_FAIL` | scan error | — | soft reject |

- [x] Add `oletools` container running olefy (port 11343, internal only)
- [x] Build custom image: install `oletools` via pip into a venv, download olefy.py (`docker/oletools/Dockerfile`)
- [x] Run as unprivileged user (`olefy`); use `/dev/shm` for temp files (`OLEFY_TMPDIR`)
- [x] Add healthcheck (`nc -z localhost 11343`)
- [x] Add `docker/rspamd/local.d/external_services.conf` — oletools block with mime type + extension filters; `extended = true`
- [x] Add `docker/rspamd/local.d/composites.conf` — `OLETOOLS_DETECTED` composite (wraps `OLETOOLS` with score 20.0)
- [x] Add `docker/rspamd/local.d/force_actions.conf` — reject on `OLETOOLS_DETECTED`; soft reject on `OLETOOLS_FAIL`
- [x] No hard `depends_on` — rspamd connects lazily; fail-open if oletools not running
- [x] `SCAN_MACROS` toggle implemented via compose profile `macros` — `docker compose --profile macros up`

---

## ✅ Step 9 — Feature layer toggles (qmail ↔ rspamd)

Four features are implemented in both qmail-smtpd and rspamd. Each can be owned
by exactly one layer; the other is automatically disabled at container start.

| Variable | Default | Controls |
|---|---|---|
| `SPF_LAYER` | `rspamd` | SPF sender policy check |
| `DKIM_VERIFY_LAYER` | `rspamd` | DKIM signature verification on inbound mail |
| `DNSBL_LAYER` | `rspamd` | DNS/RBL blocklist checks |
| `SURBL_LAYER` | `rspamd` | URI/SURBL blocklist checks |

- `rspamd` (default) — rspamd module active; qmail feature disabled (e.g. `spfbehavior=0`)
- `qmail` — qmail-smtpd feature active; rspamd module disabled via `override.d/*.conf`

- [x] `docker/entrypoint.sh` — writes qmail control files on every startup from `*_LAYER` vars:
  - `SPF_LAYER=qmail` → `control/spfbehavior=QMAIL_SPFBEHAVIOR` (default 3); else `0`
  - `DKIM_VERIFY_LAYER=qmail` → `control/dkimverify=FGHKLMNOQRTVWp`; else empty
  - `DNSBL_LAYER=qmail` → `control/dnsbllist` populated from `QMAIL_DNSBL_SERVERS` or default servers (`zen.spamhaus.org`, `b.barracudacentral.org`, `psbl.surriel.com`, `bl.spamcop.net`); else empty
  - `SURBL_LAYER=qmail` → `control/surbl=1`, downloads `level2-tlds` + `level3-tlds` from surbl.org into `control/` (volume-persisted; downloaded once), creates `control/cache/`; else `0`
- [x] `docker/rspamd/entrypoint.sh` — writes `override.d/*.conf` with `enabled = false;` when the peer layer is `qmail`; removes overrides when `rspamd`
- [x] `docker/runit/qmail-smtpd/run` + `qmail-smtps/run` + `qmail-submission/run` — `DKIMVERIFY` read from `control/dkimverify` at startup; `RELAYCLIENT_NODKIMVERIFY=1` set on all submission ports
- [x] All four `*_LAYER` vars passed to both `qmail` and `rspamd` services in `docker-compose.yml`
- [x] Documented in `.env.example` (Feature layer toggles section)
- [x] `qmailapi` runit service — Flask REST API for domain/user management (port 8080, internal):
  - `GET/POST /domains` — list / add domain (vadddomain + LMTP .qmail-default + dknewkey + qmail-newu)
  - `GET/DELETE /domains/<domain>` — get DNS records / delete domain
  - `GET/POST /domains/<domain>/users` — list / add user
  - `DELETE /domains/<domain>/users/<user>` — delete user
  - `PUT /domains/<domain>/users/<user>/password` — change password
  - Bearer token auth via `QMAIL_API_KEY`; 503 when unset (disabled by default)
  - `POST /domains` response includes MX, SPF, DKIM (`default.pub`), DMARC records
- [x] `cron` runit service added — writes `/etc/cron.d/qmail` on every startup:
  - **Always**: overlimit reset (daily midnight) — removes files from `/var/qmail/overlimit/`
  - **When `SURBL_LAYER=qmail`**: SURBL cache purge (daily 09:02), TLD update (monthly 23rd)

---

## Final compose stack

```
qmail        — MTA + vpopmail + qmailadmin/vqadmin + simscan   ports: 25, 80, 465, 587
dovecot      — IMAP/POP3/ManageSieve + LMTP                    ports: 110, 143, 993, 995, 4190
mariadb      — vpopmail user/domain/password/quota data         port:  3306  (internal)
clamav       — clamd antivirus                                  port:  3310  (internal)
rspamd       — spam filtering, DKIM verify, DMARC, RBL          port:  11334 (web UI)
redis        — Rspamd Bayes + fuzzy state                       port:  6379  (internal)
tika         — attachment text extraction for rspamd            port:  9998  (internal)
oletools     — Office macro scanning via olefy/olevba           port:  11343 (internal)
```

---

## Step 10 — Integration testing

### Bugs found during testing (must fix before re-testing)

| # | Bug | Impact |
|---|-----|--------|
| ~~A~~ | ~~**rspamd-spamc CRLF** — awk `/^$/` doesn't match `\r\n` blank line from qmail DATA; X-Spam headers never inserted; simscan always reads score 0.00 → CLEAN~~ | **Fixed**: root cause was `rspamc` failing to mmap `libicudata.so.72` under `chpst -m 64MB` RLIMIT_AS; switched to `curl` + `/checkv2` HTTP API |
| ~~B~~ | ~~**Tika not wired** — `local.d/tika.conf` lacks the `external_services { tika { } }` block; rspamd never submits attachments to Tika~~ | **Fixed**: rspamd 4.x has no built-in tika module; wrote `lua.local.d/tika.lua` plugin using `rspamd_http` to PUT attachments to `/tika` REST endpoint; `TIKA_EXTRACTED` symbol confirmed in scan log |
| ~~C~~ | ~~**IMAPSieve Bayes learning broken** — three bugs: (1) `rspamd.env` owned `root:root 600`, unreadable by `vpopmail` sieve pipe user; (2) scripts POSTed to scanner port 11333 instead of controller port 11334; (3) endpoint was `/learn_spam` (wrong) not `/learnspam`~~ | **Fixed**: entrypoint now chowns `rspamd.env` to `vpopmail:vchkpw`; scripts use `RSPAMD_CONTROLLER_PORT=11334` and correct `/learnspam`/`/learnham` paths; rspamd controller password is env-var driven via custom entrypoint |
| ~~D~~ | ~~**rspamd SURBL override noop** — `override.d/surbl.conf` targets the deprecated `surbl` module; rspamd 4.x SURBL checks (`SURBL_MULTI`, `SURBL_HASHBL`) are part of the `rbl` module and still scored. Also: `max_score = 0.0` is not enforced by rspamd (quirk — must use `0.001`)~~ | **Fixed**: write `override.d/surbl_group.conf` with complete group override (`max_score = 0.001`, all SURBL symbol weights explicitly `0.0`); rspamd SURBL symbols confirmed at `0.00` in scan log |
| ~~E~~ | ~~**surblqueue not in QMAILQUEUE chain** — run scripts set `SURBL=1` shell variable but kept `QMAILQUEUE=qmail-dkim`; surblqueue was never invoked~~ | **Fixed**: conditionally set `QMAILQUEUE=surblqueue` + `SURBLQUEUE=qmail-dkim` when `SURBL_VAL=1` in all three SMTP run scripts |
| ~~F~~ | ~~**`SURBL` env var not exported to surblfilter** — surblfilter source: `if (!(x = env_get("SURBL"))) do_surbl = 0;`; run scripts set a shell variable `SURBL_VAL` but never exported `SURBL` to the process environment; surblfilter silently passed all messages~~ | **Fixed**: `export SURBL=1` added to the `SURBL_VAL=1` branch in all three SMTP run scripts |

### Rspamd / simscan

- [x] Confirm `CLEAN` vs `SPAM` log entries in the qmail-smtpd log — format confirmed: `simscan:[qp]:CLEAN (score/required/max):time:subject:ip::rcpt`
- [x] `RSPAMD_TAG_ONLY=false` confirmed in process env (port 25 tcpserver)
- [x] `SIMSCAN_ENABLE=true` confirmed; `DKIMQUEUE=/var/qmail/bin/simscan`
- [x] `SIMSCAN_ATTACH` — empty; no extension blocking configured (expected default)
- [x] **GTUBE rejection** — port 25 → `554 Your email is considered spam (15.00 spam-hits)` ✓
- [x] **EICAR MIME rejection via ClamAV** — `CLAMAV{Eicar-Signature}` symbol fired; rspamd forced reject: `Virus found: Eicar-Signature`; SMTP `554` returned ✓

- [x] **Per-domain simcontrol overrides** — full investigation completed ✓
  - Added `example.com:clam=yes,spam=yes,spam_hits=5.0,size_limit=20000000`; `simscanmk` compiled CDB
  - Key format: **`example.com` NOT `@example.com`** — simscan does `cdb looking up example.com` (strips `@` when looking up recipient domain)
  - ClamAV toggle (`clam=yes/no`) and `spam` toggle verified — overrides global default `clam=no`
  - **`spam_hits` threshold is bypassed** by `--enable-spam-passthru=y` compile flag — simscan runs spamc for header tagging only; rejection happens exclusively via rspamd-spamc RC=1 (rspamd action=reject at its own 15.0 threshold), not by simscan score comparison
  - clamdscan-wrapper updated to handle directory path (simscan passes work dir when message has no MIME attachments)
  - entrypoint.sh comment updated with correct key format and passthru caveat
- [x] **Rspamd web UI** — `/stat` confirmed: 31 scanned, 17 rejected, 12 add-header, 2 greylisted, 5 learned ✓

### Tika

- [x] Tika fail-open — stopped container, mail still got `250 ok` ✓
- [x] **PDF attachment** — `TIKA_EXTRACTED(0.00){application/pdf(22b);}` confirmed in scan log ✓
- [x] **`TIKA_EXTRACTED` in rspamd symbol list** — confirmed via `/symbols` API: group `tika`, weight `0.0`, description correct ✓

### Oletools (profile: macros)

- [x] Start stack with `--profile macros` ✓
- [x] **XLS with Auto_Open macro** — `OLETOOLS_DETECTED(20.00)` fired; message rejected with score 26.20 ✓
  - File: `autostart-encrypt-standardpassword.xls` (Auto_Open + Hex/Base64 strings)
  - olevba flags: AutoExec=A, Suspicious=S (via Hex/Base64)
  - SMTP `554 Your email is considered spam (26.20 spam-hits)` ✓
  - Root cause of initial miss: stale Redis cache ("OK" from pre-`extended=true` scan) + wrong composites referencing non-existent sub-symbols
- [x] **Fail-open** — `docker stop oletools`, same XLS accepted (no OLETOOLS symbols, score ~6) ✓
- [x] **rspamd web UI** — `OLETOOLS_DETECTED` confirmed in group `oletools`; `OLETOOLS` + `OLETOOLS_FAIL` + `OLETOOLS_ENCRYPTED` in group `external_services` ✓

### Bayes autolearn via IMAPSieve

- [x] LMTP delivery to Dovecot — `nc dovecot 24` → `250 2.0.0 Saved` ✓
- [x] IMAP login, Junk folder creation, message move all work ✓
- [x] **IMAPSieve learn-spam** — COPY to Junk → sieve fires → `learn-spam.sh` → rspamd logs `learned message as spam` ✓
- [x] **Redis Bayes state** — 37 `RS_<hash>` token keys with `S` (spam) counts confirmed in Redis ✓
- [x] **learn-ham** — COPY from Junk → INBOX → rspamd logs `learned message as ham` ✓
- [x] **Bayes classifier runs on every scan** — `bayes_classify.lua` executes; currently inactive because ham class needs ≥ 200 samples (rspamd default minimum); `Currently: 1` confirms count is incrementing ✓
- [x] **Per-user Bayes** — `per_user = true` set in `classifier-bayes.conf`; per-user token keys confirmed in Redis: `RStestuser@example.com_<hash>` ✓

### qmail-smtpd trigger reference

- [x] **`smtp.md` trigger map** — complete table of every feature across ports 25/465/587: mechanism (control file, env var, tcp.cdb), which ports it applies to, and what it does. Includes single-mechanism gap analysis.

### qmail-smtpd triggers

- [x] **Greetdelay / DROP_PRE_GREET** — immediate EHLO → `554 SMTP protocol violation` ✓
- [x] **BRTLIMIT=2** — `421 too many invalid addresses` after 2nd bad RCPT ✓
- [x] **Rate limiting** — 4th relay message on port 465 → `421 you have exceeded your messaging limits` ✓
- [x] **CHKUSER_WRONGRCPTLIMIT=3** — temporarily raised BRTLIMIT to 10; 3rd bad RCPT → `550 5.7.1 sorry, you are violating our security policies (chkuser)` ✓
- [ ] **SPF reject** — skip; no DNS control in test env
- [ ] **DKIM verify** — send DKIM-signed mail, check log for `dkim=pass`; broken sig → `dkim=fail`
- [x] **SURBL** — `SURBL_LAYER=qmail`; body with `http://test.surbl.org/` → `554 message contains an URL listed in SURBL blocklist` ✓
  - surblfilter domain stripping: `test.surbl.org` stripped to `surbl.org` (2-level) → NXDOMAIN; workaround for test: add `surbl.org` to `level2-tlds` so 3-level lookup hits `127.0.0.72`
  - Bugs D, E, F found and fixed (see bugs table above)
- [x] **Greylisting (jgreylist)** — `control/jgreylist=1`; first attempt → `450 GREYLIST Try again later.`; triplet stored in `/srv/mail/jgreylist/{ip-octets}/` hierarchy as empty file; retry after delay → `250 ok` ✓
- [x] **Greylisting (qmail-spp)** — set `GREYLIST_USER` in `.env`; entrypoint writes `control/greylisting` + `control/mysql.cnf`; first attempt from non-relay IP (172.18.0.3) → `451 temporary failure (#4.3.0)`; triplet inserted in `greylisting_data` (`blocked_count=1`); retry after `block_expires` → `greylisting: ... exists (id=1) - accepting`, `passed_count=1` ✓
  - Root causes found: wrong DB schema (needed `greylisting_lists` + `greylisting_data`, not single `greylisting` table); missing `GREYLISTING=""` env var; plugin silently skips RELAYCLIENT connections (must test from non-relay IP)
- [ ] **DNSBL** — add entry to `control/dnsbllist`, send from listed IP, confirm rejection
