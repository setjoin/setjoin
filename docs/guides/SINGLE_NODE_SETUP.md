# Single-Node Production Setup

> **Profile: one host, < 100 users.** The simplest production deployment: all
> components on a single machine, no failover. For **100+ users or HA** (zero
> single points of failure, automatic failover) use
> [`HA_OVERVIEW.md`](HA_OVERVIEW.md) instead.

This is a counted runbook. The installer `deploy/scripts/install.sh`
(`mailserver/deploy/scripts/install.sh` in the repo) automates steps 4–10; this
guide explains each step so you understand — and can repair — what it does. The
installer is **idempotent**: re-running it preserves your existing
`/etc/setjoin/config.env`, secrets, TLS cert, and database unless you pass
`--force` (and even then it asks before rotating any secret).

---

## What runs on the box

| Component   | Role                                              | Default endpoint     |
|-------------|---------------------------------------------------|----------------------|
| PostgreSQL  | All data + business logic (PL/pgSQL reducers)     | `127.0.0.1:5432`     |
| SeaweedFS   | Content-addressed blob (attachment) storage (S3)  | `127.0.0.1:9000`     |
| `mailserverd` | The Go gateway (HTTP/JMAP/SMTP/IMAP/CalDAV/CardDAV) — systemd unit `setjoin` | `:443`             |
| `authserverd` | Auth server (login, MFA, SSO) — fronted by the gateway; systemd unit `setjoin-auth` | `127.0.0.1:8443` (loopback only) |
| `livekit-server` | setjoin Meet's SFU sidecar (WebRTC conferencing, `feature.meet`) — systemd unit `setjoin-sfu`; the gateway reverse-proxies `/rtc` to it | `127.0.0.1:7880` (loopback only — never exposed) |
| `valkey-server` | setjoin Meet's message bus (SFU↔Egress, recording, `feature.meet_recording`) — systemd unit `setjoin-valkey` | `127.0.0.1:6390` (loopback only, password-protected) |
| `livekit/egress` (container) | setjoin Meet's recording sidecar (headless Chromium + GStreamer) — systemd unit `setjoin-egress`, podman/docker, digest-pinned | host network (loopback services only; no port of its own) |
| webmail     | SvelteKit SPA, served by the gateway              | `https://<host>/`    |

> **Auth port standard: `8443`** — authserverd's stock listen port (which also
> happens to be the gateway's compiled default upstream). The installer still
> writes `AUTHSERVER_URL=http://127.0.0.1:8443` **explicitly** into
> `config.env` and `LISTEN_ADDR=127.0.0.1:8443` into `auth.env` so the pair
> can never drift apart (a 2026-07-06 real deploy 502'd every login because
> nothing pinned them together). The dev reference
> `scripts/deploy-and-test.sh` runs auth on `8444` only because *its* gateway
> occupies `8443` — do not copy that port into a production config.

> **setjoin Meet's SFU is provisioned unconditionally, even with `feature.meet`
> OFF.** The installer downloads the pinned, checksum-verified
> `livekit-server` v1.13.5 release binary, generates `LIVEKIT_API_SECRET`
> once and writes the SAME value into both `config.env` and
> `/etc/setjoin/livekit.yaml` (never two prompts — a mismatch there is
> silent total meeting failure), and installs `setjoin-sfu.service`. Signal
> port `7880` binds loopback-only and must **never** be opened on the
> firewall; the gateway reverse-proxies `/rtc` to it. Open instead:
> `7881/tcp` (ICE/TCP fallback), the RTC UDP port range (`50000-60000/udp` by
> default), `3478/udp` (TURN) and `5349/tcp` (TURN/TLS). NAT fallback ladder:
> direct UDP → ICE/TCP `7881` → TURN/UDP `3478` → TURN/TLS `5349`. TURN
> itself only turns on once a cert pair exists at
> `/etc/setjoin/certs/fullchain.pem` / `privkey.pem` (a fresh install's
> self-signed mail cert does not satisfy this by default) — a missing pair
> degrades to no-TURN, never no-SFU, with a loud installer note.
> Internet-facing/NAT deployments keep `USE_EXTERNAL_IP=true` (the default).
> A private-LAN or verification host with no discoverable public mapping must
> run the installer with `USE_EXTERNAL_IP=false`; the installer persists this
> choice, along with `RTC_PORT_START`/`RTC_PORT_END`, so later re-runs do not
> silently revert it.
> **Remote guests behind 443-only-egress firewalls are not served in v1**
> (roadmap: TURN/TLS on 443). On the 信创/SM compliance question: WebRTC
> media is keyed by DTLS-SRTP (AES only — no SM4/SM3 profile exists in any
> browser or SFU stack); the SM requirement is carried at the layers setjoin
> controls instead — outer signaling TLS (guomi-TLS on the gateway's `/rtc`
> proxy), at-rest storage (SM4 via Drive where mandated), and token/audit
> HMAC. See `retired-docs:superpowers/research/2026-07-12-B1-livekit-C0-spike.md` §3.

> **setjoin Meet recording (B2) is likewise provisioned unconditionally, even
> with `feature.meet_recording` OFF.** The installer installs `valkey-server`
> (a loopback-only, password-protected message bus LiveKit requires between
> the SFU and Egress — **Valkey, not Redis**: the BSD-3 Linux Foundation
> fork, wire-compatible with the RESP protocol LiveKit's client speaks;
> Redis 7.4+'s RSALv2/SSPL licensing is awkward to redistribute on-prem),
> detects a container runtime **once, at install time** (podman first —
> packaged in every 信创/EL distro this product targets, daemonless; docker
> as the fallback — baked into the `setjoin-egress` unit, never
> autodetected again at service start), pulls the **digest-pinned**
> `livekit/egress` image (the tag alone is mutable; the digest is the trust
> root, same posture as the SFU binary checksum), and generates
> `VALKEY_PASSWORD` **once**, writing the identical value into
> `/etc/setjoin/valkey.conf`, `/etc/setjoin/egress.yaml`, and
> `/etc/setjoin/livekit.yaml`'s `redis:` block in the same run (law 3 — the
> same one-secret-one-generation-step discipline as `LIVEKIT_API_SECRET`).
> **Blast radius, named honestly:** configuring `livekit.yaml`'s `redis:`
> block converts the SFU *itself* to bus-backed — a dead/unreachable Valkey
> degrades every B1 meeting, not just recording. Mitigated by: a
> loopback-only unit, `Restart=always`, and `/health` watching both the
> `sfu` and `egress` components (the `egress` probe round-trips
> SFU→Valkey→back via `ListEgress`). See "Recording sizing & concurrency"
> below for the CPU/Valkey capacity story.

> **Why no PgBouncer on a single node?** PgBouncer is the query pool for
> high-concurrency / HA. On one host with < 100 users you may point `DB_DSN` and
> `DB_DIRECT_DSN` at the same direct Postgres (`127.0.0.1:5432`). Add PgBouncer
> later if you outgrow it.

---

## Prerequisites

| Tool        | Version | Notes                                              |
|-------------|---------|----------------------------------------------------|
| PostgreSQL  | 18+     | `psql` client + server; role `mail` (or your own). **Also the contrib + pgTAP extension packages** (Debian/Ubuntu: `postgresql-contrib postgresql-18-pgtap`) — the baseline schema does `CREATE EXTENSION pg_stat_statements, pg_trgm, pgcrypto, pgtap`. The installer **verifies pgtap before loading the schema** and auto-installs the version-matched package on apt systems; on other distros it stops with the exact package to install instead of failing mid-load. |
| SeaweedFS   | 4.40    | Run the verified digest below; do not deploy the mutable `latest` tag. |
| Go          | 1.26.6+ | only to **build** the binaries (skip if prebuilt)  |
| Node + npm  | 20+     | only to build the webmail bundle                   |
| openssl, curl | any   | secret + self-signed-cert generation, health check, downloading the pinned `livekit-server` SFU binary |
| podman (or docker) | any | Meet B2 recording — runs the pinned `livekit/egress` container (`setjoin-egress.service`). Podman preferred (packaged in every 信创/EL distro, daemonless); docker is the fallback. Detected once at install time. |
| valkey-server, valkey-cli | any | Meet B2 recording — the SFU↔Egress message bus (`setjoin-valkey.service`), loopback-only; `valkey-cli` runs the installer's post-start `PING` health probe. Ubuntu 24.04+: `apt install valkey-server`; RHEL/信创: `dnf install valkey` (both binaries ship in the named package). |

Hardware floor for < 100 users: 4 CPU / 8 GB RAM / SSD (add 2–4 dedicated
cores if you enable Meet recording — see "Recording sizing & concurrency"
below). Run on Linux with systemd (the installer writes the
`setjoin.service` + `setjoin-auth.service` + `setjoin-sfu.service` +
`setjoin-valkey.service` + `setjoin-egress.service` units).

---

## The 10 steps

### 1. Get the code and build

```bash
git clone https://github.com/setjoin/setjoin.git && cd setjoin
bash scripts/build.sh                       # → mailserver/mailserverd, authserver/authserverd
cd mailserver/webmail && npm ci && npm run build && cd ../..
```

`install.sh` will build the binaries for you if they are missing, but it cannot
build the webmail bundle — do that here.

### 2. Provision PostgreSQL

Install PostgreSQL 18+, start it, and create the login role the DSN will use:

```bash
sudo -u postgres createuser -s mail        # superuser role 'mail' (matches the default DSN)
```

The installer creates the `mailserver` database itself (step 6). The default
direct DSN is `postgres://mail@127.0.0.1:5432/mailserver?sslmode=disable`.

> **Stock Debian/Ubuntu packages need one auth step more.** Their default
> `pg_hba.conf` uses `scram-sha-256` for TCP connections on `127.0.0.1`, so the
> passwordless default DSN above cannot authenticate. Pick one:
>
> - give the role a password and enter the matching DSN at install time:
>   `sudo -u postgres psql -c "ALTER ROLE mail PASSWORD 'S3cret'"` → DSN
>   `postgres://mail:S3cret@127.0.0.1:5432/mailserver?sslmode=disable`; or
> - trust loopback for this role (single-node only — the DB port must not be
>   exposed): add `host all mail 127.0.0.1/32 trust` **above** the default
>   `host` rules in `pg_hba.conf`, then `sudo systemctl reload postgresql`.

### 3. Provision SeaweedFS (blob storage)

Create the S3 IAM file at `/etc/setjoin/seaweedfs-s3.json`, then start the
verified single-node image with the S3 gateway published only on loopback.
The digest is intentional: `latest` is mutable and makes two installs on
different days non-reproducible.

```bash
SEAWEEDFS_IMAGE='chrislusf/seaweedfs@sha256:52194fba4fecd0083c842158b3a902ba6e04a63619b2b0efcd08007bdb6a4602'

sudo install -d -m 0750 /var/lib/seaweedfs
sudo docker pull "$SEAWEEDFS_IMAGE"
sudo docker run -d \
  --name setjoin-seaweedfs \
  --restart unless-stopped \
  -p 127.0.0.1:9000:9000 \
  -v /var/lib/seaweedfs:/data \
  -v /etc/setjoin/seaweedfs-s3.json:/etc/seaweedfs-s3.json:ro \
  "$SEAWEEDFS_IMAGE" \
  server -dir=/data -s3 -s3.port=9000 \
  -s3.config=/etc/seaweedfs-s3.json
```

Use `podman` in place of `docker` when Podman is the selected container
runtime. First boot can take about 20 seconds while the single-node Raft leader,
volume server, filer, and S3 listener come up. An unauthenticated request to
`http://127.0.0.1:9000/` returning `403` proves the authenticated S3 listener is
ready; a connection reset means startup is still in progress.

The installer's generated `S3_ACCESS_KEY`/`S3_SECRET_KEY` are written to
`config.env`; point your SeaweedFS S3 config at the same keys.

### 4. Run the installer (root)

```bash
sudo bash mailserver/deploy/scripts/install.sh
```

It prompts for the **core settings** — hostname/mail domain, HTTPS listen
address, the **owner/admin DB DSN** (the schema-owner credential from step 2;
it loads and migrates the schema, and stays in `config.env` as `DB_OWNER_DSN`
— the *runtime* connects as the constrained roles, see step 7), S3 endpoint,
and the **initial admin email + password**. In `NONINTERACTIVE=1` mode it
takes the defaults / existing `config.env` values. Steps 5–10 below are what
it then does.

### 5. Generated secrets

The installer generates and **persists** (to `/etc/setjoin/config.env`, mode
`0600`): `DB_ENCRYPTION_KEY` (32 hex = 16 bytes, the standard AES-256-GCM
profile minimum), `JWT_SECRET`, `INTERNAL_API_KEY`, the S3 access/secret
keys, `LIVEKIT_API_SECRET` (setjoin Meet's SFU key — the SAME value is
also rendered into `/etc/setjoin/livekit.yaml` in the config-write step
below, one generation step, never two), and `VALKEY_PASSWORD` (setjoin Meet
recording's bus password — the SAME value is also rendered into
`/etc/setjoin/valkey.conf`, `/etc/setjoin/egress.yaml`, and
`/etc/setjoin/livekit.yaml`'s `redis:` block, one generation step, never
three). On a re-run these are **kept** — back up `config.env`, because
rotating `DB_ENCRYPTION_KEY` makes existing encrypted data unreadable.

### 6. Self-signed TLS (replace with a real cert)

A self-signed cert for your hostname is written to
`/etc/setjoin/tls/server.pem` + `server-key.pem` (valid 825 days). For a
**publicly-trusted** cert, either:

- enable ACME: set `TLS_AUTOCERT_DOMAINS=<host>` in `config.env` and open `:80`
  for the HTTP-01 challenge; or
- drop a real cert/key at the `TLS_CERT` / `TLS_KEY` paths and restart.

### 7. Load the schema + constrained runtime roles

The installer verifies the `pgtap` extension is available (auto-installing
`postgresql-<ver>-pgtap` on apt systems, failing loud otherwise), creates the
`mailserver` database, provisions the cluster-global native-RLS roles
(`scripts/provision-roles.sql`, idempotent — forward migrations GRANT to
`setjoin_app` and fail without them), loads
`mailserver/sql/dbschema/V001__baseline.sql` (the collapsed combined schema +
seed data) only when the database is uninitialized, then uses the matching,
just-built `mailctl schema apply --yes` over the owner DSN to apply only pending
forward migrations. It loads current reducers only after the schema is current,
using `scripts/reload-reducers.sh` **once** (the loader iterates to a fixed
point internally, so forward references resolve without a second pass) and
re-runs the role script so its per-table GRANTs land. If the
schema is already at version ≥ 1 it skips the baseline so a re-run never wipes
data. All loading runs as the **owner** DSN you entered.

It then gives the constrained runtime roles generated LOGIN passwords and
writes the **three-role DSN shape** into `config.env` (the default since
2026-07-03 — see [`NATIVE_RLS_FLIP_RUNBOOK.md`](NATIVE_RLS_FLIP_RUNBOOK.md)):

- `DB_DSN` / `DB_DIRECT_DSN` → `setjoin_app` (tenant traffic, constrained by
  FORCE'd RLS),
- `DB_WORKER_DSN` → `setjoin_worker` (cross-tenant background jobs,
  `BYPASSRLS`),
- `DB_OWNER_DSN` (+ `DB_DIRECT_OWNER_DSN`) → the owner credential you entered
  (migrations / partition DDL only — `upgrade.sh` and re-runs of the installer
  use it; the running gateway never does).

**Escape hatch:** `--permissive-dsn` (or `PERMISSIVE_DSN=1`) keeps the old
single permissive DSN everywhere. **Rollback** (runbook §4.6): point `DB_DSN`
and `DB_DIRECT_DSN` in `config.env` back at the `DB_OWNER_DSN` value and
`systemctl restart setjoin setjoin-auth` — no migration to undo.

### 8. Write config + install the services

`config.env` (all shared settings + an explicit
`AUTHSERVER_URL=http://127.0.0.1:8443` + `LIVEKIT_API_KEY`/
`LIVEKIT_API_SECRET`/`LIVEKIT_URL`/`MEET_EGRESS_ENABLED`/`VALKEY_PASSWORD`),
`auth.env` (auth's loopback `LISTEN_ADDR` + empty `TLS_CERT`/`TLS_KEY` — the
gateway terminates TLS), `livekit.yaml` (the SFU's own config, rendered from
the checked-in `livekit.yaml.template` — `turn.enabled` is computed from
whether a cert pair already exists at
`/etc/setjoin/certs/{fullchain,privkey}.pem`, never hand-set; its `redis:`
block points at the loopback Valkey), `valkey.conf` (loopback-only,
password-protected, no persistence — `mailserver/deploy/scripts/lib-livekit.sh`'s
`provision_valkey_conf`), and `egress.yaml` (rendered from
`egress.yaml.template`; the same `VALKEY_PASSWORD` + `LIVEKIT_API_SECRET`
as above) are written to `/etc/setjoin/`. Binaries land in `/opt/setjoin/`
(including the pinned `livekit-server` binary downloaded in step 4), the
webmail bundle is copied alongside, and **all five** systemd units are
installed, enabled, and started in order: `setjoin-valkey.service` and
`setjoin-sfu.service` first, then `setjoin-egress.service`
(`Wants=setjoin-valkey.service`), then `setjoin-auth.service`, then
`setjoin.service` — the gateway proxies every `/auth/*` route to
authserverd and `/rtc` to the SFU, so the installer fails loud if
`http://127.0.0.1:7880/` (the SFU signal port), Valkey's `PING` on
`127.0.0.1:6390`, the `setjoin-egress` container's running status, or
`http://127.0.0.1:8443/health` doesn't answer.

### 9. Provision the first admin

The installer invokes `mailctl bootstrap-admin` locally with the owner database
credential. The password is read from standard input (or a root-readable 0600
secret file for unattended installation), never placed in a process argument
or sent to a public HTTP endpoint. `ensure_default_admin` serializes bootstrap
with a transaction advisory lock and atomically refuses once any user exists.
If you skip the installer password prompt, SSH to the server and run:

```bash
sudo -u setjoin /opt/setjoin/mailctl bootstrap-admin --email admin@example.com
```

The browser at `https://<host>/setup` only reports status and these local
instructions; it cannot create an administrator or accept restore credentials.

### 10. Health-check + verify

```bash
curl -k https://<host>/health           # installer does this; expect a 200 body
mailctl login https://<host>            # then: mailctl user create --email ... --password ...
```

Open `https://<host>/` and log in as the admin. Send a test message to confirm
the delivery path. The installer also confirms `http://127.0.0.1:7880/`
answers (the SFU signal port — a mis-keyed/dead SFU fails the install here,
not the first meeting), that Valkey answers `PING` on `127.0.0.1:6390`, that
the `setjoin-egress` container is running, and greps the gateway's `/health`
body for `"sfu"` and `"egress"` components, confirming the `LIVEKIT_*` /
`MEET_EGRESS_ENABLED` config was actually picked up.

For browser validation with a self-signed certificate, prefer trusting the
test CA or mapping the deployment hostname directly. If a temporary local
TLS/reverse-proxy bridge is unavoidable, it must preserve or rewrite `Host`,
`Origin`, and `Referer` to the same deployed hostname. Rewriting only `Host`
correctly produces CSRF 403 on state-changing requests because the browser's
loopback Origin is cross-site. Never disable or exempt CSRF to make a test
bridge pass; first prove the deployed-origin request reaches the same handler
with a non-live/dummy credential.

---

## Operations

```bash
setjoinctl status                       # every installed Setjoin unit
setjoinctl restart                      # dependency-safe stop/start order
setjoinctl stop                         # updater first, then public/core services
setjoinctl start                        # dependencies before auth/gateway/updater
journalctl -u setjoin -f                # gateway logs
journalctl -u setjoin-auth -f           # auth server logs (login/MFA/SSO)
journalctl -u setjoin-sfu -f            # Meet SFU logs (LiveKit)
journalctl -u setjoin-valkey -f         # Meet bus logs (Valkey — SFU<->Egress)
journalctl -u setjoin-egress -f         # Meet Egress logs (recording, in-container)
```

`setjoinctl` operates a compiled-in service allowlist; it accepts no unit or
path from the caller. If transactional execution is enabled, `stop`, `restart`,
and `uninstall` fail until the operator has verified that no upgrade is active
and supplies `--allow-updater-stop`. A reversible service uninstall is:

```bash
setjoinctl uninstall --confirm-preserve-data
```

This disables and removes only Setjoin's systemd unit registrations. It
deliberately preserves `/etc/setjoin`, `/etc/setjoin-updater`,
`/var/lib/setjoin`, `/var/lib/setjoin-updater`, `/opt/setjoin`, PostgreSQL, and
object storage. There is no automated purge-data option: export and verify a
recovery set before handling customer data as a separate, explicit operation.

This controller and the disposable exact-prefix rehearsal share the same
operational rule: preserve failed-upgrade evidence and customer data by
default, and delete only a compiled allowlist. Client-assisted recovery intake
is a separate OFF-gated workflow; see
[Client-assisted mail recovery](CLIENT_ASSISTED_MAIL_RECOVERY.md).

- **Config + secrets** live in `/etc/setjoin/config.env` (mode `0600`). **Back
  this up** — it holds `DB_ENCRYPTION_KEY`, the JWT/S3 secrets,
  `LIVEKIT_API_SECRET` (also mirrored in `/etc/setjoin/livekit.yaml`), and
  `VALKEY_PASSWORD` (also mirrored in `/etc/setjoin/valkey.conf` and
  `/etc/setjoin/egress.yaml`). The installer also creates the mode-`0600`
  `BACKUP_SIGNING_KEY_FILE` (normally `/etc/setjoin/backup-signing-key`). Preserve
  it with the recovery set: every backup manifest is signed with this key and a
  backup-enabled service refuses startup when the key is missing, linked, or has
  unsafe permissions.
- **User management:** `mailctl` (see `mailctl/AGENTS.md`) — `mailctl user
  create|list|delete`, `mailctl domain add`, etc.
- **Re-running the installer** is safe: it preserves config, secrets, TLS, and
  the database. Use `--force` only to deliberately re-prompt / rotate (it asks
  before touching a secret).

### Database disaster-recovery drill

`mailctl backup-db` must be exercised, not merely scheduled. It writes a
PostgreSQL custom-format dump to the configured backup bucket as the canonical
`db-dump.dump` plus a timestamped archival copy. For loopback SeaweedFS, pass
`--endpoint http://127.0.0.1:9000` explicitly; a bare endpoint may otherwise be
interpreted as HTTPS. Do not pass `--dsn` in the normal rehearsal: the command
must prove the installed owner-first resolver selects `DB_DIRECT_OWNER_DSN` or
`DB_OWNER_DSN` before the Native-RLS `setjoin_app` credentials in
`DB_DIRECT_DSN`/`DB_DSN`.

For each release rehearsal, run `pg_restore --list`, then use the full
`mailctl restore` path without `--dsn` against a newly created disposable
setup-mode target. Verify at least `max(schema_migrations.version)`, table
ownership, a known user count, stable representative IDs/content hashes, and
critical feature toggles. Drop only that disposable target after verification.
A full restore first restores blobs through the no-user gateway, then
atomically locks/re-checks `users=0`, replaces the preloaded `public` schema,
and replays the complete dump with its specialized ownership and standardized
runtime ACLs. Provision the standard Setjoin roles on the empty target before
restore. Do not
replace this with `pg_restore --clean` directly over the setup schema:
partition-inherited constraints cannot be dropped from their child tables.
Before starting the restored gateway/authserver, restore the source
deployment's offline `DB_ENCRYPTION_KEY` and `JWT_SECRET` from the protected
`config.env` backup. The database intentionally contains only encrypted
connector/configuration/signing-key ciphertext; newly generated target secrets
cannot decrypt it and both services must fail closed. Do not copy source DSNs,
hostname, TLS private keys, or endpoint-specific settings blindly.
The signed backup manifest proves internal integrity. If no independently held
trust pack authenticates the source, the restore still recovers data but applies
only reducer-classified safe configuration; encrypted, unknown, endpoint and
credential-bearing values are preserved in the restore quarantine for local-root
review and rotation. They are never silently activated.
A catalog-only check is insufficient: V149 exists because a Conditional Access
CHECK-constraint function previously failed only while data was being restored
under `pg_restore`'s empty caller search path.

## Recording sizing & concurrency (Meet B2)

Recording composites the room server-side through headless Chromium +
GStreamer — software encode, no GPU. Budget **2–4 CPU cores and ~1–2 GB RAM
per hour of recording** for a software VP8/VP9-class 1080p composite. On a
shared single-node box the practical concurrency cap is **1 simultaneous
recording**: `egress.yaml`'s `cpu_cost.room_composite_cpu_cost` (default `3`)
is checked against the `setjoin-egress.service` unit's `CPUQuota` (default
`400%` = 4 cores) — a second concurrent composite is refused by egress's own
admission control (surfaced to the user as a distinguishable "recording busy"
error, not a hang). **Raise both knobs together, and only with dedicated
cores** — `EGRESS_ROOM_COMPOSITE_CPU_COST` / `EGRESS_CPUQUOTA` at install
time (or hand-edit `egress.yaml` / the `setjoin-egress.service` unit and
`systemctl daemon-reload && systemctl restart setjoin-egress`).

**Separate-host recipe:** Egress and Valkey do not have to share the SFU's
box. Point a second host's `egress.yaml` `redis.address` (and nothing else)
at the primary host's Valkey over a private network (open `6390/tcp` between
the two hosts only — never publicly), and move `ws_url` to the SFU host's
address. The gateway, SFU, and Valkey stay on the primary node; only the
CPU-hungry Egress container moves.

## Federation (Pillar C1 DM federation, optional)

Answering yes to the installer's `FEDERATION_ENABLED` prompt (default no)
wires this box to be **able** to federate DMs with another setjoin org over
a mutually cert-authenticated s2s TLS stream. Unlike Meet's SFU/Valkey/
Egress trio, federation is not a sidecar — `federation.Service` runs
**inside** the `setjoin` gateway process itself, so there is no extra
systemd unit and `journalctl -u setjoin -f` already covers its logs.

What the installer does when enabled:

- Prompts for `FEDERATION_LOCAL_DOMAIN` (this org's s2s identity — defaults
  to the hostname you entered in step 4) and generates, in one step, an org
  CA (`/etc/setjoin/federation/ca.crt`/`ca.key`, 3650 days, self-signed) and
  an s2s leaf cert for that domain (`leaf.crt`/`leaf.key`, 825 days), unless
  you already supplied your own via the `FEDERATION_CERT`/`FEDERATION_KEY`
  environment variables — those are used as-is and nothing is generated.
- Writes `FEDERATION_LOCAL_DOMAIN`/`FEDERATION_LISTEN_ADDR` (default
  `:7443`)/`FEDERATION_CERT`/`FEDERATION_KEY` into `config.env` — all three
  of `_LOCAL_DOMAIN`/`_CERT`/`_KEY` being non-empty is `cmd/mailserverd`'s
  static gate to construct+start `federation.Service` at boot (absent env
  means no Service at all, never a half-started one).

**Exchanging anchors with a peer org:** hand the peer `ca.crt` (never
`ca.key` or `leaf.key`) — they paste its contents into their own admin
Federation console (`federation.manage` permission) as your
`federation_allowlist.peer_anchor`, and you do the same with theirs. Trust
is bilateral and default-off: nothing federates until **both** sides have
allow-listed each other **and** flipped `feature.federation` on (it ships
seeded OFF).

**Discovery:** peers find you via DNS SRV — publish
`_setjoin-im._tcp.<FEDERATION_LOCAL_DOMAIN>` pointing at this host on the
federation listen port (`7443`/tcp by default — `FEDERATION_LISTEN_ADDR`;
open it on your firewall for inbound s2s only, never expose it the way
`:443` is). This is the **only**
discovery mechanism today — there is no per-peer endpoint override for
air-gapped or no-DNS pairs yet; such a deployment needs a private DNS zone
(or an equivalent stub resolver) serving that SRV record for each peer
until one is built.

## When to graduate to HA

Move to the [3-node HA deployment](HA_OVERVIEW.md) when you cross ~100 users, or
need zero-downtime failover for PostgreSQL / blob storage / the gateway. The
data model is identical; HA adds streaming replication, Pgpool-II, and a
3-master SeaweedFS Raft cluster.
