# qmail Helm Chart

Deploys the [qmail Docker stack](../../docker/README.md) as a single Helm
release: qmail (MTA) + dovecot (IMAP/POP3/Sieve) + mariadb + redis + rspamd +
clamav + tika — mirroring the compose services 1:1, minus the compose profiles
(`macros`, `certbot`) which are opt-in via `oletools.enabled` /
`certbot.enabled`.

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
| `certbot.enabled` | `false` | Let's Encrypt issuance/renewal sidecar (`certbot.email`, `certbot.domain`, `certbot.schedule`) |

Feature-layer ownership (`SPF_LAYER`, `DKIM_VERIFY_LAYER`, `DNSBL_LAYER`,
`SURBL_LAYER`) must stay consistent between `qmail.env` and `rspamd.env` —
qmail's feature layer toggle only works when rspamd mirrors it (see the docker
README section on feature layer toggles).

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
