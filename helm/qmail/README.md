# qmail Helm Chart

Deploys the [qmail Docker stack](../../docker/README.md) as a single Helm
release: qmail (MTA) + dovecot (IMAP/POP3/Sieve) + mariadb + redis + rspamd +
clamav + tika — mirroring the compose services 1:1 and exposing **every env
var the images understand** (see `values.yaml`, a full mirror of
`docker/.env.example` grouped per component). The compose profiles map to:
`macros` → `oletools.enabled`, `certbot` → `certbot.enabled` (CronJob) or,
recommended, TLS via **cert-manager** (`tls.provider: cert-manager`) — see the
TLS section.

Images come from the public multi-arch GHCR packages
(`ghcr.io/brdelphus/{qmail,qmail-dovecot,qmail-rspamd,qmail-oletools}`, amd64 +
arm64).

## Quick start

```sh
helm repo add ...            # not needed — chart lives in this repo
cd helm/qmail

helm install qmail . \
  --set qmail.me=mail.example.com \
  --set secret.mysqlRootPass='<openssl rand -hex 16>' \
  --set secret.mysqlPass='<openssl rand -hex 16>' \
  --set secret.greylistPass='<openssl rand -hex 16>' \
  --set secret.rspamdPassword='<openssl rand -hex 16>' \
  --set secret.vqadminPass='<openssl rand -hex 16>'
```

`qmail.me` is **required**. The primary vpopmail domain defaults to everything
after the first dot of `qmail.me` (override with `qmail.domain`).

After first run, add mail users inside the qmail pod:

```sh
kubectl exec -n qmail deploy/qmail -- /home/vpopmail/bin/vadduser postmaster@example.com 'secret'
```

## Architecture

| Component | Role | Ports exposed (hostPort) |
|---|---|---|
| **qmail** | MTA: SMTP, submission, SMTPS, qmailadmin/vqadmin (lighttpd), vusaged, qmailapi | 25, 80, 465, 587 |
| **dovecot** | IMAPS/POP3S/ManageSieve + LMTP delivery endpoint | 993, 995, 4190 |
| **mariadb** | vpopmail auth/quota + greylisting backend | internal |
| **redis** | rspamd Bayes + fuzzy state | internal |
| **rspamd** | spam filtering, AV orchestration (talks to clamav + tika) | internal |
| **clamav** | clamd + freshclam | internal |
| **tika** | attachment text extraction (PDF/DOCX/…) for rspamd | internal |

By default all pods are reachable from each other via ClusterIP DNS
(`qmail`, `dovecot`, `mariadb`, …) and the public mail ports bind directly on
the node via `hostPort` (`service.useHostPort: true`) — a k3s NodePort can't
carry real SMTP/IMAP ports (30000-32767 range).

### Storage and node pinning

Mail data lives on a **RWO** volume (cluster default storage class — local-path
on k3s). The qmail and dovecot pods must therefore share a node:

- qmail and dovecot mount the same `maildata`/`maildirs` PVCs
- dovecot carries a **required podAffinity** to the qmail pod
  (`topologyKey: kubernetes.io/hostname`) — it always lands on the qmail node
- the qmail entrypoint seeds control files/queue/etc. into the volume on first
  start; dovecot's `wait-maildata` init container waits for
  `/srv/qmail/qmail/control/me` before starting

Any component can be pinned to a specific node per-deployment, e.g. to keep
auxiliary pods off masters or co-locate with big RAM:

```sh
helm upgrade qmail . -n qmail \
  --set 'tika.nodeSelector.kubernetes\.io/hostname=rworker-01' \
  --set 'clamav.nodeSelector.kubernetes\.io/hostname=rworker-01'
```

(`nodeSelector` and `tolerations` exist on every component:
`qmail`, `dovecot`, `mariadb`, `redis`, `rspamd`, `clamav`, `tika`,
`oletools`, `certbot`.)

## TLS

Three ways to get the SMTP/IMAP certificate (the entrypoint combines cert+key
into `control/servercert.pem` on every boot — dovecot reads the same combined
file from the shared volume):

**1. selfsigned (default)** — the qmail entrypoint generates a self-signed cert
for `qmail.me` on first boot. Nothing to configure; fine for testing.

**2. certbot (opt-in, `certbot.enabled: true`)** — mirrors the docker "certbot"
profile as a CronJob; useful when cert-manager isn't installed (e.g. testing
on k3s-v3). Certs land in the letsencrypt PVC via qmail's lighttpd webroot.
Point qmail at the issued cert:

```yaml
certbot:
  enabled: true
  email: you@example.com
  # domain: mail2.example.org     # defaults to qmail.me
qmail:
  env:
    QMAIL_TLS_CERT: /etc/letsencrypt/live/mail.example.com/fullchain.pem
    QMAIL_TLS_KEY:  /etc/letsencrypt/live/mail.example.com/privkey.pem
```

Renewal happens daily (schedule); servercert.pem is re-combined at qmail pod
boot, so `kubectl rollout restart deploy/qmail -n qmail` after a renewal.

**3. cert-manager (recommended on Kubernetes)** — no certbot sidecar: the chart
creates a `Certificate` for `qmail.me` (+ `dnsNames`) against your existing
Issuer/ClusterIssuer, and the qmail pod mounts the issued Secret:

```yaml
tls:
  provider: cert-manager
  certManager:
    issuerRef:
      name: letsencrypt-prod      # your ClusterIssuer
      kind: ClusterIssuer
    # dnsNames: [mail2.example.org]   # extra SANs
```

`tls.provider: cert-manager` mounts the issued Secret (`qmail-tls`) at
`/etc/qmail-tls` and sets `QMAIL_TLS_CERT`/`QMAIL_TLS_KEY` automatically.
Renewal is automatic (default at 2/3 of lifetime) but `servercert.pem` is only
rewritten at qmail pod boot — after a renewal:
`kubectl rollout restart deploy/qmail -n qmail`.

For static PEMs without cert-manager, mount your certs and set
`qmail.env.QMAIL_TLS_CERT`/`QMAIL_TLS_KEY` or the `_B64` variants.

## Service exposure — hostPort / ClusterIP / LoadBalancer

Like the Mailu chart, the way qmail/dovecot are exposed is configurable
(`service.*` in values) — nothing is hardcoded:

| Mode | Values | When to use |
|---|---|---|
| **hostPort** *(default)* | `service.useHostPort: true` | k3s/bare-metal without an LB controller. Real ports bind on the node (qmail 25/80/465/587, dovecot 993/995/4190). A NodePort can't carry SMTP/IMAP ports (30000-32767 range) |
| **ClusterIP** | `service.type: ClusterIP` + `useHostPort: false` | cluster-internal only — no external mail ports at all |
| **LoadBalancer** | `service.type: LoadBalancer` + `useHostPort: false`, optional `service.loadBalancerIP` | clusters with MetalLB or a cloud LB controller; qmail/dovecot Services get an external IP |
| **NodePort** | `service.type: NodePort` + `useHostPort: false` | high-port access on every node (e.g. in front of an external LB) |

Internal services (`mariadb`, `redis`, `rspamd`, `clamav`, `tika`, plus the
per-component ClusterIP DNS) stay ClusterIP in every mode. With `hostPort`,
qmail and dovecot keep their ClusterIP services too (pod DNS + internal
access). qmail and dovecot always share a node (RWO volumes) regardless of
mode.

## Ports / firewalling

Public mail ports on the node: **25** (SMTP), **465** (SMTPS), **587**
(submission), **993** (IMAPS), **995** (POP3S), plus **80** for qmailadmin.
**4190** (ManageSieve) also binds via hostPort but is commonly kept internal —
open it in the firewall only if Sieve clients need it from outside. 25/80/443
egress is often blocked on residential ISPs; test SMTP from a server/VPN.

## Secrets

All credentials live in `templates/secret.yaml`, driven by `secret.*`. Leave
empty → `changeme_*` defaults (fine for a test cluster, never for production):

| Value | Used by |
|---|---|
| `secret.mysqlRootPass` | mariadb root (baked into the data volume on first start) |
| `secret.mysqlPass` | vpopmail DB user |
| `secret.greylistPass` | qmail-spp greylisting plugin |
| `secret.rspamdPassword` | rspamd web UI/controller |
| `secret.vqadminPass` | vqadmin HTTP basic auth |
| `secret.qmailApiKey` | qmail REST API (port 8080, internal) |

## Key values

| Value | Default | Notes |
|---|---|---|
| `image.registry` / `image.tag` | `ghcr.io/brdelphus` / `latest` | image repo + tag for qmail, dovecot, rspamd, oletools |
| `qmail.me` | `mail.example.com` | **required** — server FQDN (`QMAIL_ME`) |
| `qmail.domain` | derived from `qmail.me` | primary vpopmail domain created on first run |
| `qmail.env.*` / `rspamd.env.*` / … | mirror of compose defaults | any env var from `docker/.env.example` — see [docker README](../../docker/README.md) |
| `service.useHostPort` | `true` | bind real ports on the node |
| `storageClass` | cluster default | PVC storage class |
| `clamav.image.*` | `ghcr.io/mailu/clamav:2.0` | **official `clamav/clamav` has no arm64 manifest** — the Mailu image is amd64+arm+arm64 and includes a TCP-ready clamd (probe is tcpSocket, no `clamamdcheck.sh`) |
| `tika.javaOpts` | `-Xms128m -Xmx512m` | JVM heap for the tika server |
| `oletools.enabled` | `false` | enable olefy macro scanning (rspamd fails open when it's down) |
| `certbot.enabled` | `false` | certbot CronJob for Let's Encrypt (see TLS section) |
| `tls.provider` | `selfsigned` | `selfsigned`, `certbot` (via certbot.enabled) or `cert-manager` |

Feature-layer ownership (`SPF_LAYER`, `DKIM_VERIFY_LAYER`, `DNSBL_LAYER`,
`SURBL_LAYER`) must stay consistent between `qmail.env` and `rspamd.env` —
qmail's feature layer toggle only works when rspamd mirrors it (see the docker
README section on feature layer toggles).

## Configuration reference

Every env var the images understand (docker/`.env.example` + compose) is
exposed in `values.yaml`, grouped per component. Each component's `env` map is
rendered into its own ConfigMap (`qmail-env`, `mariadb-env`, `rspamd-env`,
`dovecot-env`) and injected into the pod with `envFrom`. Values files and
`--set` deep-merge over the chart defaults, so any var can be overridden
without touching the chart:

```sh
helm upgrade qmail . -n qmail \
  --set qmail.env.HELO_DNS_CHECK=PLRIV \
  --set qmail.env.QMAIL_RELAY_NETS=10.0.0.0/8 \
  --set 'dovecot.env.DOVECOT_POP3S=false'
```

Empty values (`""`) are emitted as-is and behave like unset vars in the
entrypoints (`${VAR:-default}`), i.e. the image's built-in default applies —
leave unused vars empty instead of deleting them. Secrets (`MYSQL_PASS`,
`GREYLIST_PASS`, `RSPAMD_PASSWORD`, `VQADMIN_PASS`, `QMAIL_API_KEY`,
`PGSQL_PASS`, `LDAP_BIND_PW`) come from the Secret, never from `env` maps.
Full semantics of every var: [`docker/README.md`](../../docker/README.md).

### qmail.env — MTA

| Env var | What it does |
|---|---|
| `MYSQL_HOST/PORT/DB/USER` | vpopmail MySQL backend connection (service DNS `mariadb`) |
| `GREYLIST_HOST/DB/USER` | qmail-spp greylisting plugin; set `GREYLIST_USER` to activate |
| `CLAMD_HOST/PORT` | ClamAV endpoint used by simscan when `SIMSCAN_CLAM=yes` |
| `RSPAMD_HOST/PORT` | rspamd endpoint called by simscan's filter |
| `LMTP_HOST/PORT` | dovecot LMTP delivery endpoint (local deliveries) |
| `QMAIL_SOFTLIMIT` | memory limit per SMTP process (bytes) |
| `QMAIL_CONCURRENCY_INCOMING/REMOTE/LOCAL` | max simultaneous inbound / outbound / local deliveries |
| `QMAIL_DATABYTES` | max message size (bytes, `0` = unlimited) |
| `QMAIL_MAXRCPT` | max recipients per message |
| `QMAIL_QUEUELIFETIME` | seconds in queue before bounce (~3 days default) |
| `SPF_LAYER` / `DKIM_VERIFY_LAYER` / `DNSBL_LAYER` / `SURBL_LAYER` | `rspamd` or `qmail` — who owns each check (must mirror `rspamd.env`) |
| `QMAIL_DNSBL_SERVERS` | RBL servers when `DNSBL_LAYER=qmail` (space-separated, `-` = hard reject) |
| `QMAIL_SPFBEHAVIOR` | SPF reject mode when `SPF_LAYER=qmail` (`0`-`3`) |
| `QMAIL_SPF_EXP` | custom SPF failure explanation |
| `QMAIL_GREETDELAY` | seconds of greet delay before the banner (`0` = off) |
| `QMAIL_SURBL` | SURBL URI checking in the qmail layer (`0`/`1`) |
| `QMAIL_BRTLIMIT` | max non-existent recipients before disconnect |
| `QMAIL_CHKUSER_WRONGRCPTLIMIT` | max invalid recipients before disconnect (all ports) |
| `QMAIL_BOUNCEFROM` | envelope sender name for bounces |
| `QMAIL_RELAY_LIMIT` | msgs per auth user/domain/IP per period (`0` = unlimited) |
| `QMAIL_DUALSTACK` | `1` binds tcpserver on `::` (IPv4+IPv6) |
| `QMAIL_GREYLISTING` | `1` = jgreylist wrapper on port 25 |
| `UNSIGNED_SUBJECT` | allow DKIM mail whose `h=` misses Subject (`1` = allow) |
| `HELO_DNS_CHECK` | HELO hostname DNS validation modes (e.g. `PLRIV`) |
| `REJECTNULLSENDERS` | non-empty = reject empty envelope sender |
| `QMAIL_TLS_CERT/KEY` | paths to cert/key PEM — entrypoint combines into `servercert.pem` |
| `QMAIL_TLS_CERT_B64/KEY_B64` | base64 PEMs (no volume needed); wins over file paths |
| `QMAIL_TLS_CIPHERS` | TLS cipher suite |
| `QMAIL_DH_BITS` | DH parameter size (`2048`/`4096`) |
| `QMAIL_SNI_CERTS` | `domain:cert:key;...` for extra TLS domains |
| `QMAIL_RELAY_NETS` | comma-separated IPs/prefixes trusted to relay on port 25 |
| `QMAIL_TAPS` | mail-tap rules `TYPE:REGEX:DEST` (`F` from / `T` to / `A` all) |
| `GREYLIST_BLOCK_EXPIRE` / `GREYLIST_RECORD_EXPIRE` / `GREYLIST_RECORD_EXPIRE_GOOD` / `GREYLIST_LOGLEVEL` | spp plugin tuning (minutes/hours/log verbosity) |
| `SIMSCAN_ENABLE` | `true`/`false` — content filter calling rspamd before queueing |
| `SIMSCAN_CLAM` | `yes` scans attachments directly with clamd too |
| `SIMSCAN_SPAM` / `SIMSCAN_SPAM_HITS` | reject spam over the hit threshold (`9.0`) |
| `SIMSCAN_SIZE_LIMIT` / `SIMSCAN_ATTACH` | size/attachment limits |
| `SIMSCAN_DEBUG` | simscan debug level `0`-`4` |
| `RSPAMD_TAG_ONLY` | rspamd tags instead of rejecting |
| `VQADMIN_USER` | vqadmin HTTP basic-auth username |
| `QMAIL_API_PORT` | REST API listen port (internal) |
| `QMAIL_SMTP` / `QMAIL_SMTPS` / `QMAIL_SUBMISSION` / `QMAIL_HTTP` | runit service toggles (ports 25/465/587/80) |

`QMAIL_ME` / `QMAIL_DOMAIN` are not in this map — set `qmail.me` / `qmail.domain`.

### mariadb.env

| Env var | What it does |
|---|---|
| `MARIADB_DATABASE` / `MARIADB_USER` | vpopmail database/user created on first start |
| `GREYLIST_DB` / `GREYLIST_USER` | greylisting database/user (init script creates both) |

Root/password come from the Secret (`MYSQL_ROOT_PASS`, `MYSQL_PASS`,
`GREYLIST_PASS`).

### rspamd.env

| Env var | What it does |
|---|---|
| `SPF_LAYER` / `DKIM_VERIFY_LAYER` / `DNSBL_LAYER` / `SURBL_LAYER` | mirror of `qmail.env` — keep both in sync |

`RSPAMD_PASSWORD` comes from the Secret (controller + web UI).

### dovecot.env

| Env var | What it does |
|---|---|
| `DOVECOT_AUTH_DRIVER` | `mysql` (default) \| `pgsql` \| `ldap` — must match the qmail image's `VPOPMAIL_AUTH` |
| `MYSQL_HOST/PORT/DB/USER` | mysql backend connection |
| `PGSQL_HOST/PORT/DB/USER` | pgsql backend (`DOVECOT_AUTH_DRIVER=pgsql`, pass via `secret.pgsqlPass`) |
| `LDAP_HOST/PORT/BASE/BIND_DN/TLS` + `LDAP_USER_FILTER/PASS_ATTRS/USER_ATTRS` | ldap backend (`DOVECOT_AUTH_DRIVER=ldap`, bind pw via `secret.ldapBindPw`) |
| `RSPAMD_HOST/PORT/CONTROLLER_PORT` | rspamd integration (learn/spam folders, controller for admin) |
| `DOVECOT_IMAP` / `DOVECOT_IMAPS` / `DOVECOT_POP3` / `DOVECOT_POP3S` / `DOVECOT_SIEVE` / `DOVECOT_LMTP` | service toggles (`true`/`false`) |

### oletools.env / clamav.env / tika

| Var | What it does |
|---|---|
| `OLEFY_BINDADDRESS/BINDPORT/TMPDIR/LOGLEVEL` | olefy macro scanner (only when `oletools.enabled: true`) |
| — | clamav image has no env knobs; tika takes `javaOpts` (JVM heap) only |

## Operation

```sh
helm upgrade qmail . -n qmail -f my-values.yaml    # upgrade
helm rollback qmail -n qmail <revision>            # rollback
kubectl -n qmail logs deploy/qmail                 # MTA logs (svlogd under /var/log/qmail)
kubectl -n qmail exec deploy/qmail -- sv status /etc/service/*
kubectl -n qmail get pods -o wide                  # where pods landed
```

Dovecot and qmail deployments use `Recreate` (no rolling update) because they
share RWO volumes and only one copy may mount them at a time. Expect a brief
mail outage during upgrades of those two.

## arm64

Validated end-to-end on OCI Ampere A1 (k3s, arm64): all seven pods run from the
arm64 image variants. See the "arm64 notes" section of the docker README for
the build-side details (config.guess refresh, single-threaded DJB makefiles).
