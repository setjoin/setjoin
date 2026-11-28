<!-- Relocated verbatim from mailserver/DOX.md during #577 top-level layout promotion. -->
This is a task-selected reference, not an always-loaded rail. Root `AGENTS.md` and
`deploy/AGENTS.md` govern agent workflows. Deployment contracts below remain binding
for their scope; historical status is not permission to implement or enable flags.

# deploy — module DOX

Owns systemd unit/socket/path templates, single-node installer and upgrader scripts
(`deploy/scripts/`), lifecycle controller (`setjoinctl`), sidecar templates,
HAProxy/PgBouncer/Pgpool templates, and Grafana/Zabbix monitoring assets.
Server runtime and protocol behavioral contracts live in [`server/DOX.md`](../server/DOX.md).

## Ownership and installer contracts

- `deploy/` — systemd units (`setjoin-gateway.service` executing `setjoin-server`, `setjoin-auth.service` executing `setjoin-auth`, `setjoin-updater.service` executing `setjoin-updater`, optional `setjoin-asr-bot.service` executing Rust `asrbotd`, plus sidecars `setjoin-sfu.service`, `setjoin-valkey.service`, `setjoin-egress.service`, `setjoin-funasr.service`; legacy Go `mailserver.service.template` / `setjoin.service` was retired in `#142` / `ARCH-031`). Historical unit/sidecar notes below remain binding for sidecar templates and deployment scripts:
  - `setjoin-sfu.service` → `setjoin-sfu`, the Meet B1 LiveKit SFU sidecar, Task 14 — no `EnvironmentFile`, reads only its own `--config livekit.yaml`; **Meet B2 adds two more**: `setjoin-valkey.service` → `setjoin-valkey`, a loopback-only Valkey bus (`127.0.0.1:6390`, RESP-compatible, NOT Redis — LiveKit's go-redis client speaks the wire protocol but upstream only tests against Redis, so the live gate must prove the round-trip on Valkey specifically), no RDB/AOF persistence (bus only), config mode 0600; `setjoin-egress.service` → `setjoin-egress`, the pinned `livekit/egress` container (digest-pinned, podman-or-docker) with `cpu_cost.room_composite_cpu_cost` (default 3) against the unit's `CPUQuota` (default 400%) as the concurrency ceiling (Egress has no `max_concurrent` key — this is the real mechanism, and refusal from it IS the distinguishable `egressBusy` surface); **Meet B3 Task 16 adds a sixth and seventh unit, both OPTIONAL** (unlike the five above, which install unconditionally): `setjoin-asr-bot.service` → `setjoin-asr-bot`, the Rust captions room-bot (`server/bins/asrbot/`, `asrbotd` — a native binary, the `setjoin-sfu.service` genre: `EnvironmentFile=/etc/setjoin/asrbot.env`, never `config.env` — the bot holds no DB/S3 credential, D4; **B3 Task 18 pipeline-review finding 1 fix**: the bot's loopback control API — `/start`/`/stop`/`/status` — now requires a bearer `ASR_TOKEN` on every request, constant-time compared; loopback TCP alone carries no peer identity, so before this any local uid could drive the bot directly, bypassing the reducer's consent chip, DoS captions via `/stop`, or enumerate captioned rooms via `/status` — `/healthz` stays open, empty-body only; `ASR_TOKEN` is law-3'd like `LIVEKIT_API_SECRET`/`VALKEY_PASSWORD`, generated once by `install.sh` into both `asrbot.env` and `config.env`), `After=`/`Wants=setjoin-funasr.service setjoin-sfu.service`; `setjoin-funasr.service` → `setjoin-funasr`, the pinned upstream `funasr-runtime-sdk-online-cpu` C++ WebSocket ASR container (digest-pinned; **B3 Task 18 pipeline-review finding 2 fix**: NO LONGER host-networked — the old `--network=host` with no explicit `--port`/bind arg put an unauthenticated plaintext-WS server on every host interface at the run_server_2pass.sh default port 10095, not the 10096 `asrbot.env`/`install.sh`'s probe actually expected, a real port mismatch nothing enforced; now an explicit `--port 10095` plus a loopback-only published port, `-p 127.0.0.1:10096:10095`, so the container's own internal bind is irrelevant — FunASR only ever accepts inbound connections from asrbot, so unlike egress it never needed host networking; **finding 3 fix**: `StandardOutput=null` — `run_server_2pass.sh`'s underlying server commonly prints recognition results to stdout, and journald-persisting that would retain spoken caption transcripts on disk, defeating D4 ephemerality outside the bot process (stderr stays `journal`-routed for crash diagnostics); a real systemd deploy MUST still `journalctl -u setjoin-funasr | grep` for spoken text as a D4 verification gate before `feature.meet_captions` flips ON anywhere — the 2026-07-16 live gate CONFIRMED the container's raw stdout carries transcripts, so the null-routing is load-bearing, but the gate box had no systemd to exercise journald itself; **B3 live-gate fix (2026-07-16, run against the real pinned image)**: ExecStart now direct-`exec`s `funasr-wss-server-2pass` with every model dir named explicitly instead of `bash run_server_2pass.sh` — the upstream wrapper BACKGROUNDS the server and exits, so the old container's PID1 finished the moment the script returned, killing the just-started server and crash-looping the unit into `failed` at every real boot; the explicit `--lm-dir ''` disables upstream's optional ~960MB LM-rescoring default (see the template comment) — with `/var/lib/setjoin/funasr-models` mounted **read-only**, the `install_livekit_binary` trust posture extended to model weights: the container must never silently fetch its own trust root; the live gate proved the server loads all five models from that `:ro` dir and serves the full 2pass round-trip); both gated behind `install.sh`'s `MEET_CAPTIONS_ENABLED` prompt (default `false`) since this leg downloads a ~840MB pinned ONNX model + pulls a ~1GB pinned container image for a feature that, like recording, ships behind `feature.meet_captions` seeded OFF — **model pinning (Task 16 gap CLOSED by the 2026-07-16 live gate)**: `lib-livekit.sh`'s `install_funasr_models` pins ALL FIVE models the pinned image's own startup defaults name — online + vad + offline + punc + itn, every file SHA-256'd from ModelScope's own `repo/files` API and re-verified by download; upstream's optional LM is deliberately disabled in the unit rather than pinned (memory budget + proven-unneeded for round-trip quality)), the single-node installer + upgrader (`scripts/install.sh` / `scripts/upgrade.sh` — installer defaults to the constrained native-RLS three-DSN shape with a `--permissive-dsn` escape hatch, pins `AUTHSERVER_URL` explicitly, preflights pgtap, and provisions the SFU: `scripts/lib-livekit.sh`'s `install_livekit_binary` downloads + sha256-verifies the pinned `livekit-server` v1.13.5 release binary (hard-coded checksums, re-run-safe via a version-stamp file) and `render_livekit_yaml` substitutes `livekit.yaml.template` → `/etc/setjoin/livekit.yaml`, gating `turn.enabled` on whether a cert pair already exists at `/etc/setjoin/certs/{fullchain,privkey}.pem` — missing cert degrades to no-TURN, never no-SFU; `LIVEKIT_API_SECRET` is generated once and written to both `config.env` and `livekit.yaml` in the same install run; **B2 extends the one-run secret rule to `VALKEY_PASSWORD`**: generated once and written into `livekit.yaml`, `egress.yaml`, and `valkey.conf` in the SAME install run — no second secret universe; **the B3 Task 18 pipeline-review fix extends it again to `ASR_TOKEN`**: generated once (only when `MEET_CAPTIONS_ENABLED=true`) and written into both `config.env` and `asrbot.env` in the SAME install run; the post-install PING health probe (below) reads the Valkey password via `REDISCLI_AUTH` rather than `valkey-cli -a`, closing a `ps`/`/proc`-visible secret-leak finding (finding 4); upgrader applies schema DDL over the OWNER DSN, never the app DSN), HAProxy/PgBouncer/Pgpool templates, Grafana dashboards, Zabbix config. Runbook: `docs/guides/SINGLE_NODE_SETUP.md`; fresh-install gate: `scripts/deploy/ga-fresh-install-smoke.sh` (asserts a real `/auth/login` round-trip, not just `/ready`); the render logic's own check: `deploy/scripts/test-livekit-render.sh`.

Single-node Valkey packaging is distro-specific: Ubuntu 24.04+ provides both
`valkey-server` and `valkey-cli` through `apt install valkey-server`; the
RHEL/信创 package remains `valkey`. The installer preflight and the GA
fresh-install smoke must keep those operator hints and prerequisites aligned.

The single-node installer supports stock Ubuntu/PostgreSQL SCRAM loopback
authentication: when `DB_DIRECT_OWNER_DSN` contains an owner password it
exports that password only to its child `psql` calls. The fresh-install smoke
must exercise this password-bearing DSN path; do not mask it with a temporary
`pg_hba.conf` trust rule.

Both fresh installs and idempotent re-runs use the matching, just-built
`mailctl schema apply --yes` over the owner DSN before loading current reducers.
This order is mandatory for upgrades from an older schema: reducers may name
tables created by pending migrations. The installer builds and installs that
same `mailctl`; `scripts/guards/check-installer-migration-order.sh` guards the artifact
set and migration-before-reducer order.

SFU network-discovery settings (`RTC_PORT_START`, `RTC_PORT_END`, and
`USE_EXTERNAL_IP`) are persisted in `config.env`; an explicit environment
override changes them, while an ordinary re-run preserves them. Private/LAN
verification hosts use `USE_EXTERNAL_IP=false`; internet-facing NAT hosts keep
the `true` default or provide their explicit mapping.

`install.sh` owns its named config files and certificate/federation directories,
not every file under `/etc/setjoin`. Never restore a recursive `chown` of the
whole config directory: operator-managed sidecar credentials can require a
different narrow group and otherwise fail only after the sidecar restarts.

The installer installs `/usr/local/sbin/setjoinctl` from
`deploy/scripts/setjoin-lifecycle.sh` and uses it for dependency-ordered service
restart. The controller accepts no caller-supplied unit/path, stops the updater
before core services, starts dependencies before auth/gateway/updater, and
refuses an unconfirmed stop while transactional execution is enabled. Its
`uninstall --confirm-preserve-data` action removes only the exact Setjoin
systemd unit registrations; config, mail data, recovery sets, immutable release
trees, PostgreSQL, and object storage are always preserved. A data purge is a
separate unsupported operation. Keep `test-setjoin-lifecycle.sh` in the upgrade
contract gate whenever lifecycle behavior changes.

`deploy/scripts/test-upgrade-rollback.sh` exercises the legacy flat-layout
upgrade command with a failed schema migration. It verifies restoration of the
matching `*.prev` binaries (Go and the Rust `setjoin-gateway`, upgrade.sh's
optional fifth argument) and webmail plus service restart order. Immutable
installations use complete `current`/`previous` cohorts instead.

Rust front door (#264, ARCH-027 shape, ON by default): the catalog's
`setjoin-gateway` core unit (start after `setjoin`, stop before it) is
rendered by `render_gateway_unit` with its sibling `setjoin-gateway.socket`
(systemd-owned loopback `GATEWAY_LISTEN`, default `127.0.0.1:8090`), no
capabilities, and `ConditionPathExists` on the active release's binary so a
cohort adopted before the gateway existed stays inactive until a signed
release carries it. `gateway.env` (`render_gateway_env`, no secrets) points
`GATEWAY_UPSTREAM` at Go's loopback plain listener; config.env sets
`HTTP_MODE=proxy` and `TRUSTED_PROXY_IP=127.0.0.1`. The TLS terminator forwards
to the gateway; rollback points it back at Go's `:80`. Go keeps its TLS and
protocol listeners and `CAP_NET_BIND_SERVICE` until the listener swaps.
Signed releases must carry the `setjoin-gateway` artifact (`core_setjoin_gateway`,
required when staging, optional when parsing older installed manifests);
adoption captures it when present and quarantines `setjoin-gateway.prev`.
Proof: `deploy/scripts/test-install-front-door.sh` (in the upgrade contract gate).
`setjoinctl stop`/`uninstall` close companion sockets before their services;
`restart` leaves the socket listening so connections queue during replacement.

## Rust operator CLI and backup transfer (#355)

Release archives stage the Rust CLI at `server/mailctl` and the compatible
`mailctl/mailctl` artifact path. The installer consumes the canonical Rust path,
so an old Go binary in a source checkout cannot satisfy its prerequisite; source
builds use `cargo build --release --locked -p setjoin-mailctl`. Installed paths,
unit names and `.prev` rollback remain unchanged. The Go module catalog keeps
mailctl for oracle testing but no longer builds it as a customer artifact.
`package-server-release.sh` now requires nine inputs (Rust setjoin-auth added, #359b; see
`server/bins/updater/DOX.md`): architecture, Go binary directory,
Rust gateway, Rust setjoin-auth, Rust mailctl, Rust asrbotd (the captions bot, #356; staged as
`server/asrbotd` and installed to `bin/asrbotd` by the optional captions leg),
Rust updater, webmail build and output archive. All supplied ELF
machines are checked; the caller remains responsible for source provenance and
runtime floor qualification.

The installer preserves other `GO_WORKERS_OFF` names and adds `backup-engine`.
Configured backup effects now run in the Rust gateway; the Go launcher uses its
existing named worker switch. Signing keys, BACKUP_* configuration and worker /
LISTEN credential separation retain their existing meanings. To roll the worker
back, disable `RUST_BACKUP_ENGINE_ENABLED` and remove only `backup-engine` from
Go's disabled list, then restart both processes. Process-local Go workers remain
running. Detailed Rust contract: `server/crates/backup/DOX.md`.

## Native federation deployment (#347)

`render_gateway_unit` loads only the five dedicated allowlisted files
(`federation.env`, `storage.env`, `smtp.env`, `gateway.env`, and `tls.env`);
it never injects config.env or db-credentials.env into the front door.
`render_storage_env` projects S3/MinIO endpoint, bucket, and credentials into
0640 `storage.env` independently of SMTP enablement. Because `setjoin-updater`
upgrades the gateway separately from host unit/env rendering on immutable hosts,
first deploy the updated `setjoin-updater` and run
`upgrade.sh refresh-gateway-env` before activating a release that retires Go's
WORM legal-hold forward (`setjoin-gateway` also fails closed at startup if
`WORM_MODE` is enabled without any `S3_*`/`MINIO_*` settings loaded).
`render_federation_env` copies only DB_DSN, DB_DIRECT_DSN, DB_WORKER_DSN,
the four static FEDERATION_* settings, configured `LIVEKIT_API_KEY`/`LIVEKIT_API_SECRET`/`LIVEKIT_URL`
(projected directly from protected `config.env` via `yaml-config.py env-copy`
so LiveKit secrets never appear on process argv and native `/rtc` / `/api/rtc`
stay wired), and federation worker-switch entries.
The file is 0640 root:setjoin, under the root-controlled config directory.
Owner DSNs and unrelated secrets/switches stay out. gateway.env contains only
front-door settings and cannot override the federation worker switches.

With federation configured, the renderer adds `setjoin-federation.socket`,
names its FD `federation`, and attaches it through Wants/After. A bind failure
must leave HTTP available; an absent FD logs an error and leaves federation inert.
Installation enables it without a Rust routing flag and preserves other worker
switches while adding `federation-service,federation-residue-reap` to
`GO_WORKERS_OFF` and `federation-residue-reap` to `RUST_WORKERS_ON`.
The reaper runs even with peering unconfigured or the product toggle OFF.
`setjoinctl stop`/`uninstall` also close/remove this socket; restart retains it.

A flat `upgrade.sh` invocation with the new gateway (argument 5) also re-renders
its unit/socket/config surfaces and enables configured native federation/TLS before
restarting. It snapshots the gateway service and gateway/federation/HTTPS (plus any
legacy pre-#560 `setjoin-acme.socket` being retired on cutover) sockets,
config.env, gateway.env, federation.env, storage.env, smtp.env and tls.env (including file absence/modes), and
the federation/HTTPS/legacy-ACME sockets' active/enabled state below the root-only
`$INSTALL_DIR/federation-deploy.prev`. A render/start/readiness or migration
failure restores that snapshot alongside matching *.prev binaries: stop the
new federation socket before restarting an older gateway that cannot accept its
FD name. No runtime switch back to Go is added. Immutable installations continue
using signed Updates and its whole-release recovery workflow.

For a later manual flat rollback, stop setjoin-gateway, setjoin-federation.socket,
and setjoin-https.socket (plus legacy setjoin-acme.socket if reverting to a pre-#560 release);
disable the public sockets; restore matching *.prev binaries
(and webmail.prev when supplied). For each of setjoin-gateway.service,
setjoin-gateway.socket, setjoin-federation.socket, setjoin-https.socket, and any
snapshotted setjoin-acme.socket, replace the live file with
its copy under federation-deploy.prev/units, removing it if the snapshot has no
copy. Do the same for config.env, gateway.env, federation.env, storage.env, smtp.env and tls.env from
federation-deploy.prev/config, preserving modes/ownership with `cp -a`.
Run `systemctl daemon-reload`, re-enable/start the federation socket only if the
snapshot has socket-enabled/socket-active markers; restore HTTPS (and any snapshotted
legacy ACME socket) using their `<socket-name>-enabled` / `<socket-name>-active` markers.
Then restart the matching auth and gateway processes. Keep the private snapshot with the
binary backups.

Protocol/runtime oracle details:
[agreement](../server/crates/protocols/federation/DOX.md#native-activation-and-delivery-347).
Checks: `deploy/scripts/test-federation-socket.sh`, `test-federation-upgrade.sh`,
`test-upgrade-rollback.sh`, `test-setjoin-lifecycle.sh` and `test-install-front-door.sh`.

## Native HTTPS deployment (#413)

`configure_tls_front` strips retired Release N workers (`tls-ticket-keys`, `http-port80`)
from existing `config.env` files and transfers `http-tls,http-h2c,cert-monitor` when
`TLS_CERT` is configured and `TLS_EDGE_PROXY` is not truthy (`true`/`1`/`yes`). When
`TLS_EDGE_PROXY=true`, a same-host edge proxy such as Caddy/Angie owns `:443`, so
`http-tls`/`cert-monitor` and `setjoin-https.socket` are omitted (and any existing
`setjoin-https.socket` is stopped, disabled, and removed on refresh/upgrade) while
`TLS_CERT`/`TLS_KEY` remain in `tls.env` for SMTPS/IMAPS/LDAPS. Built-in ACME (`TLS_AUTOCERT_*` except `TLS_AUTOCERT_CACHE_DIR`,
`TLS_DNS_*`, `ACME_*`, `acme-renewal`, and `setjoin-acme.socket`) was retired in Release
N+1 (`#560`): `check_no_retired_acme_config` fails closed in `install.sh` and `upgrade.sh`,
and cutover stops, disables, and removes any legacy `setjoin-acme.socket` (restoring it on
rollback). Go's overseer `LISTEN_ADDR` becomes `127.0.0.1:0` before restart.
The Rust gateway accepts public TLS on `setjoin-https.socket` (FD `https`, port 443
or `GATEWAY_HTTPS_LISTEN`), without `CAP_NET_BIND_SERVICE`. The renderer attaches
optional federation sockets through Wants/After.
`tls.env` is a literal 0640 allowlist of `HOSTNAME`, `TLS_CERT`, and `TLS_KEY`; broad
`config.env` and owner credentials never enter the internet-facing gateway unit.
`storage.env` is a dedicated literal 0640 allowlist carrying only S3/MinIO
endpoint and credentials (resolved via pure-stdlib `deploy/scripts/yaml-config.py`,
covering the YAML subset for mappings, anchors/aliases/`<<` merges, standard tags,
duplicate-key rejection, and flow/block scalars alongside `systemd.exec(5)`
`EnvironmentFile` parsing, with Go's `s3.*` / `S3_*` / `MINIO_*` precedence;
`smtp.env` emits the identical resolved
`S3_*` lines when SMTP is enabled) independent of SMTP enablement (#289 legal
holds, blobs, attachments), and is rolled back alongside the deployment env files.
App/worker/LISTEN credentials and the transferred worker names stay in `federation.env`.

Managed settings (including `SETJOIN_CONFIG`, `HOSTNAME`,
`INTERNAL_DOMAINS`, `WORM_MODE`, `WORM_RETENTION_DAYS`, and explicit
`WORM_LEGAL_HOLD_ENABLED`) survive install config regeneration; explicit
operator environment values take precedence (`WORM_LEGAL_HOLD_ENABLED` follows Go's
env-only override semantics, and empty `WORM_MODE=` keeps WORM disabled; upgrading
all DB-backed immutable hosts requires installing the updated `setjoin-updater` and
running `upgrade.sh refresh-gateway-env` — or `upgrade.sh` on flat layouts — before
activation so `gateway.env` carries explicit `WORM_MODE=`/`WORM_MODE=<mode>`,
`setjoin-gateway.service` loads `storage.env`, and `federation.env` carries any
configured `LIVEKIT_*` settings (for native `/rtc` and `/api/rtc`); `setjoin-updater`
preflight checks WORM, storage, and `LIVEKIT_*` parity while systemd-activated
`setjoin-gateway` startup validates `WORM_MODE` and storage provenance (and
without `LIVEKIT_*` returns 404 on `/api/rtc` while `/rtc` falls through to
the catch-all SPA or 404). The TLS
import cache directory (`tls_import_cache_dir`, resolved from
`TLS_AUTOCERT_CACHE_DIR` or `SETJOIN_CONFIG` YAML `tls.autocert_cache_dir` via
`yaml-config.py`, used by `POST /admin/tls/import-cert`) is validated lexically and
canonically (`validate_tls_cache_target`: rejects control chars, quotes, backslashes,
`%` systemd specifiers, trailing-slash and intermediate component symlinks outside
OS-managed `/tmp` and `/var/run`, filesystem roots, `.`/`..` traversal, top-level
system directories, unrelated system/service paths outside dedicated
`setjoin`/`mailserver` or temp trees, and non-empty directories owned by another user
under root) before
filesystem mutation, provisioned (`0700`, `setjoin:setjoin` enforced on both new
and existing directories during root install/upgrade; `upgrade.sh` records prior
cache directory existence/mode/owner/`dev:ino` in `tls-cache.meta` and verifies
matching `dev:ino` before rollback mutation, while non-root upgrade rehearsals
skip only host `/var/cache/mailserver/autocert`), emitted solely into `gateway.env`
alongside resolved `WORM_*` and Go-matched trace identity (`HOSTNAME`/`INTERNAL_DOMAINS`)
settings, and granted a narrow `ReadWritePaths` in `setjoin-gateway.service`.
Static certificates remain read-only.

Install and flat upgrade require a real local TLS handshake plus the native
/_gateway/healthz response. The local probe accepts the installation's self-signed
leaf; it does not admit an HTTP-only response as TLS readiness. Lifecycle restart
retains sockets so connections queue; stop/uninstall closes/removes them.
Recovery reinstalls a complete matching release (binaries, units, socket set,
configuration and active/enabled state from federation-deploy.prev, as above).
No runtime switch back to Go is installed (owner decision 2026-11-04).
Checks: `deploy/scripts/test-tls-front-socket.sh`, `test-tls-front-upgrade.sh`,
`test-setjoin-lifecycle.sh`, `test-install-front-door.sh`, `test-install-provision-render.sh`
(the TLS front socket/upgrade scripts run under `scripts/guards/check-upgrade-contracts.sh`).
The root/systemd rehearsal `python3 scripts/deploy/test-tls-front-systemd.py <gateway>` renders the
actual hardened HTTPS unit, proves empty capabilities and queued TLS restart, and occupies
the optional federation port to prove its bind failure leaves HTTPS serving. All resources
use `gofree-tlsfront-*` names and are removed on exit; no database is used.
Transport/session/renewal details: [gateway contract](../server/bins/gateway/DOX.md#https-runtime-413).


## Native updater/recovery installation (#359)

The installer uses `server/setjoin-updater` and the unchanged
`setjoin-updater.service` unit name, adding the `run` subcommand. Early `check-swap`
admission and a final locked installation refuse any active/queued/unreconciled
update. Inactive Go journals are verified and archived as evidence, never converted.
The native installer preserves updater/recovery executables and the unit as `*.prev`;
its compatibility `setjoin-recovery` entrypoint execs native `recover`. Legacy flat
core/webmail rollback remains unchanged. Restore matching executables and units
together only with no update active, retaining the archived journal evidence.
The fixed Go Office-only companion remains owned by #300 and has no core-update
arguments. Full handover, release input and oracle contract:
[updater DOX](../server/bins/updater/DOX.md#installer-handover-and-release-inputs-359).
Checks: updater Cargo process targets, `test-updater-render.sh`, provisioning,
lifecycle and legacy rollback scripts, and `scripts/deploy/test-package-server-release.py`.

## Native SMTP deployment (#501 / #526)

Fresh installs and upgrades transfer SMTP by default after the enabled-pipeline
recordings (#526). The retired `SMTP_FRONT_ENABLED` opt-in is normalized to true,
including legacy false markers; explicit empty listener addresses remain respected.
The renderer transfers SMTP_INBOUND_ADDR
(:25), SMTP_INBOUND_TLS_ADDR (empty = off) and SMTP_SUBMISSION_ADDR (:587) to
`setjoin-smtp`/`setjoin-smtps`/`setjoin-submission.socket` (named FDs `smtp`/`smtps`/
`submission`). The gateway unit only `Wants=` them (no `Requires=`): an SMTP socket problem
never takes HTTPS down. The gateway loads a dedicated allow-listed `smtp.env`
(`render_smtp_env`: app/direct/worker DSNs, TLS paths, SMTP/S3/threat and inbound
ClamAV/CAPE/anti-phish settings, plus the link-protect key already derived from JWT_SECRET
at render time (`SMTP_LINK_PROTECT_KEY` = hex HMAC-SHA256 per Go `tokenKeyN`, `SMTP_LINK_PROTECT_VERSION`,
and `SMTP_LINK_PROTECT_KEY_PREVIOUS` only while the rotation overlap is open); the master `JWT_SECRET`, owner/updater DSNs and
private signing keys never reach it, and every re-render (including upgrade) rewrites the file so a stale `JWT_SECRET` is dropped; 0640 root:setjoin) before gateway.env. `configure_smtp_front` adds
`smtp`/`submission` to Go's GO_LISTENERS_OFF (Go checks `listenerEnabled` per listener);
gateway.env carries the union with imap, and Rust refuses to start an activated socket
whose name is not listed. Upgrade re-renders units/env, snapshots and restores sockets,
`smtp.env` (bytes, modes, absence) and active/enabled state; rollback closes the new sockets
before the previous gateway starts. No runtime way back to Go exists. Verification:
`deploy/scripts/test-smtp-sockets.sh`, `test-smtp-upgrade.sh` (six whole-script cases),
`scripts/deploy/test-smtp-systemd.py` (real rendered sockets, enabled Go recordings,
capability-empty service, restart and FTRL startup/live posture), and the existing
TLS/IMAP/federation/lifecycle/rollback scripts. The rehearsal uses its own private
resolv.conf mount and loopback DNS/S3/clamd peers; it changes no installed unit.

## Native IMAP deployment (#202)

When the installation has TLS_CERT/TLS_KEY, the renderer transfers configured
IMAP_ADDR (default :143) and IMAP_TLS_ADDR (default :993) to systemd's optional
`setjoin-imap.socket`/`setjoin-imaps.socket` (named FDs `imap`/`imaps`). Explicit
empty addresses omit that leg and survive reinstall config regeneration. The service has empty capabilities and reads
only the existing request/worker/direct credential allowlist plus protocol knobs.
`configure_imap_front` adds imap to Go's config.env GO_LISTENERS_OFF; gateway.env
contains GO_LISTENERS_OFF=imap. Activation requires the shared threat gate and
webhook dispatcher; no allow-all admission or runtime return-to-Go path exists.
Upgrade snapshots/restores these socket files and their enabled/active state;
restart retains the sockets, stop/uninstall closes them. Whole-release recovery
restores matching binaries, descriptor set and config. Verification:
`deploy/scripts/test-imap-sockets.sh`, existing TLS/front-door/upgrade/lifecycle
render tests and the native IMAP policy/effect replay in the Rust crate.
