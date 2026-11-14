<!-- Detailed DOX reference, moved from AGENTS.md on 2026-09-11. -->
This is a task-selected reference, not an always-loaded rail. Root and local
AGENTS.md govern agent workflows. Domain contracts below remain binding for their
scope; historical status is not permission to implement or enable flags.

# mailserver — module AGENTS.md (DOX rail)

`setjoin.com/mailserver` — the Gmail-quality on-premise mail server. Go gateway (thin, stateless protocol translator) + PL/pgSQL reducers (all business logic) + SvelteKit webmail SPA. Binary: `mailserverd`.

Read the root `AGENTS.md` first for project-wide rules. This doc adds the module-level rail; deeper detail lives in the three children below.

---

## 1. Purpose

The mailserver module is the primary product binary. It speaks SMTP/IMAP/JMAP/CalDAV/CardDAV/LDAP, stores everything in PostgreSQL, serves blobs through SeaweedFS (S3), and delivers the webmail SPA. The Go gateway is deliberately thin: it translates protocols, enforces auth, and calls reducers. All decisions (delivery, rules, quotas, spam, state tokens, pg_notify) happen inside PL/pgSQL.

---

## 2. Ownership

This doc owns:
- `cmd/mailserverd/` — entry point and startup sequence
- `internal/` — Go gateway packages, including cron task transfer gates (see child `internal/AGENTS.md`).
- `api/` — the integrator-facing OpenAPI 3.1 contract + serving (see child `api/AGENTS.md`)
- `sql/` — schema (dbschema migrations), reducers, tests (see child `sql/AGENTS.md`)
- `webmail/` — SvelteKit SPA (see child `webmail/AGENTS.md`)
- `deploy/` — systemd units (`mailserver.service` → installed as `setjoin`; `authserver.service` → `setjoin-auth`, loopback `127.0.0.1:8443`, shares `config.env` + an `auth.env` override file; `setjoin-sfu.service` → `setjoin-sfu`, the Meet B1 LiveKit SFU sidecar, Task 14 — no `EnvironmentFile`, reads only its own `--config livekit.yaml`; **Meet B2 adds two more**: `setjoin-valkey.service` → `setjoin-valkey`, a loopback-only Valkey bus (`127.0.0.1:6390`, RESP-compatible, NOT Redis — LiveKit's go-redis client speaks the wire protocol but upstream only tests against Redis, so the live gate must prove the round-trip on Valkey specifically), no RDB/AOF persistence (bus only), config mode 0600; `setjoin-egress.service` → `setjoin-egress`, the pinned `livekit/egress` container (digest-pinned, podman-or-docker) with `cpu_cost.room_composite_cpu_cost` (default 3) against the unit's `CPUQuota` (default 400%) as the concurrency ceiling (Egress has no `max_concurrent` key — this is the real mechanism, and refusal from it IS the distinguishable `egressBusy` surface); `mailserver.service` carries `Wants=`/`After=setjoin-sfu.service` alongside the existing auth ordering, same Wants-not-Requires rationale, extended to the two new units; **Meet B3 Task 16 adds a sixth and seventh unit, both OPTIONAL** (unlike the five above, which install unconditionally): `setjoin-asr-bot.service` → `setjoin-asr-bot`, the Go captions room-bot (`asrbot/`, `cmd/asrbotd` — a native binary, the `setjoin-sfu.service` genre: `EnvironmentFile=/etc/setjoin/asrbot.env`, never `config.env` — the bot holds no DB/S3 credential, D4; **B3 Task 18 pipeline-review finding 1 fix**: the bot's loopback control API — `/start`/`/stop`/`/status` — now requires a bearer `ASR_TOKEN` on every request, `crypto/subtle`-compared; loopback TCP alone carries no peer identity, so before this any local uid could drive the bot directly, bypassing the reducer's consent chip, DoS captions via `/stop`, or enumerate captioned rooms via `/status` — `/healthz` stays open, empty-body only; `ASR_TOKEN` is law-3'd like `LIVEKIT_API_SECRET`/`VALKEY_PASSWORD`, generated once by `install.sh` into both `asrbot.env` and `config.env` — **the gateway side is now wired** (pipeline-review follow-up closed): `internal/meet/config.go`'s `Config.ASRToken` (env `ASR_TOKEN`) threads through `NewCaptionsClient(baseURL, token string)` (`cmd/mailserverd/main.go`), and `internal/meet/captions.go`'s `httpCaptionsClient` sets `Authorization: Bearer <token>` on every `/start`/`/stop`/`/status` call (the shared `newRequest` builder both `doJSON` and `Status` route through) — including the `asr` health probe, which round-trips through `Status()`), `After=`/`Wants=setjoin-funasr.service setjoin-sfu.service`; `setjoin-funasr.service` → `setjoin-funasr`, the pinned upstream `funasr-runtime-sdk-online-cpu` C++ WebSocket ASR container (digest-pinned; **B3 Task 18 pipeline-review finding 2 fix**: NO LONGER host-networked — the old `--network=host` with no explicit `--port`/bind arg put an unauthenticated plaintext-WS server on every host interface at the run_server_2pass.sh default port 10095, not the 10096 `asrbot.env`/`install.sh`'s probe actually expected, a real port mismatch nothing enforced; now an explicit `--port 10095` plus a loopback-only published port, `-p 127.0.0.1:10096:10095`, so the container's own internal bind is irrelevant — FunASR only ever accepts inbound connections from asrbot, so unlike egress it never needed host networking; **finding 3 fix**: `StandardOutput=null` — `run_server_2pass.sh`'s underlying server commonly prints recognition results to stdout, and journald-persisting that would retain spoken caption transcripts on disk, defeating D4 ephemerality outside the bot process (stderr stays `journal`-routed for crash diagnostics); a real systemd deploy MUST still `journalctl -u setjoin-funasr | grep` for spoken text as a D4 verification gate before `feature.meet_captions` flips ON anywhere — the 2026-07-16 live gate CONFIRMED the container's raw stdout carries transcripts, so the null-routing is load-bearing, but the gate box had no systemd to exercise journald itself; **B3 live-gate fix (2026-07-16, run against the real pinned image)**: ExecStart now direct-`exec`s `funasr-wss-server-2pass` with every model dir named explicitly instead of `bash run_server_2pass.sh` — the upstream wrapper BACKGROUNDS the server and exits, so the old container's PID1 finished the moment the script returned, killing the just-started server and crash-looping the unit into `failed` at every real boot; the explicit `--lm-dir ''` disables upstream's optional ~960MB LM-rescoring default (see the template comment) — with `/var/lib/setjoin/funasr-models` mounted **read-only**, the `install_livekit_binary` trust posture extended to model weights: the container must never silently fetch its own trust root; the live gate proved the server loads all five models from that `:ro` dir and serves the full 2pass round-trip); both gated behind `install.sh`'s `MEET_CAPTIONS_ENABLED` prompt (default `false`) since this leg downloads a ~840MB pinned ONNX model + pulls a ~1GB pinned container image for a feature that, like recording, ships behind `feature.meet_captions` seeded OFF — **model pinning (Task 16 gap CLOSED by the 2026-07-16 live gate)**: `lib-livekit.sh`'s `install_funasr_models` pins ALL FIVE models the pinned image's own startup defaults name — online + vad + offline + punc + itn, every file SHA-256'd from ModelScope's own `repo/files` API and re-verified by download; upstream's optional LM is deliberately disabled in the unit rather than pinned (memory budget + proven-unneeded for round-trip quality) — see TODOS.md "Meet B3" item 1 for what the live gate proved vs what remains owed (the webmail F8 hidden-bot attestation P0, journald leg, GPU sizing)), the single-node installer + upgrader (`scripts/install.sh` / `scripts/upgrade.sh` — installer defaults to the constrained native-RLS three-DSN shape with a `--permissive-dsn` escape hatch, pins `AUTHSERVER_URL` explicitly, preflights pgtap, and provisions the SFU: `scripts/lib-livekit.sh`'s `install_livekit_binary` downloads + sha256-verifies the pinned `livekit-server` v1.13.5 release binary (hard-coded checksums, re-run-safe via a version-stamp file) and `render_livekit_yaml` substitutes `livekit.yaml.template` → `/etc/setjoin/livekit.yaml`, gating `turn.enabled` on whether a cert pair already exists at `/etc/setjoin/certs/{fullchain,privkey}.pem` — missing cert degrades to no-TURN, never no-SFU; `LIVEKIT_API_SECRET` is generated once and written to both `config.env` and `livekit.yaml` in the same install run; **B2 extends the one-run secret rule to `VALKEY_PASSWORD`**: generated once and written into `livekit.yaml`, `egress.yaml`, and `valkey.conf` in the SAME install run — no second secret universe; **the B3 Task 18 pipeline-review fix extends it again to `ASR_TOKEN`**: generated once (only when `MEET_CAPTIONS_ENABLED=true`) and written into both `config.env` and `asrbot.env` in the SAME install run; the post-install PING health probe (below) reads the Valkey password via `REDISCLI_AUTH` rather than `valkey-cli -a`, closing a `ps`/`/proc`-visible secret-leak finding (finding 4); upgrader applies schema DDL over the OWNER DSN, never the app DSN), HAProxy/PgBouncer/Pgpool templates, Grafana dashboards, Zabbix config. Runbook: `docs/guides/SINGLE_NODE_SETUP.md`; fresh-install gate: `scripts/ga-fresh-install-smoke.sh` (asserts a real `/auth/login` round-trip, not just `/ready`); the render logic's own check: `mailserver/deploy/scripts/test-livekit-render.sh` (B2 extends it with the Valkey/Egress unit + template render assertions; B3 Task 16 further extends it with the asr-bot/funasr unit + `asrbot.env` render assertions, incl. a structural StartLimit*-under-`[Unit]` check on both new units and a refusal check on a non-loopback `ASR_LISTEN` / an unpinned `FUNASR_IMAGE`).
- `go.mod` — module `setjoin.com/mailserver`

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
same `mailctl`; `scripts/check-installer-migration-order.sh` guards the artifact
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

Client-assisted recovery is an independent OFF-gated U5–U8 rail. V180 and
`internal/continuity` issue/present installation-, account-, timeline-, state-,
boot-, and digest-bound witnesses and receipts using a dedicated signing key.
V181 and `internal/mailrecovery` translate bounded incident/upload/quarantine
requests to reducers; Go never decides ingest authority. ClamAV is mandatory
and fails closed. Exact raw MIME/blob hashes, current user/delegate scope,
fresh admin authority, user consent, fork consent, state/audit/notify, and blob
refcounts are reducer/trigger-owned. The cleanup worker drains expired chunks
even while intake is OFF. See `docs/guides/CLIENT_ASSISTED_MAIL_RECOVERY.md`.

Drive node ACL and access governance is the V184–V193 gated rail. PL/pgSQL owns
closure, exact capabilities, grants/breaks, directory-group generations, epoch
fences, approvals, leases, invalidations, audit, and rollback refusal. Go remains
a bounded wire translator; native/web caches must consume the opaque invalidation
stream and quarantine revoked bytes. `feature.drive_node_acl_reads`,
`feature.drive_node_acl_writes`, `feature.drive_access_governance`, and
`feature.drive_emergency_access` are all seeded OFF. Integration and operator
contracts live in `docs/guides/DRIVE_ACL_INTEGRATION.md` and
`docs/guides/DRIVE_ACL_OPERATIONS.md`.
Grant and access-request creation require one canonical UUID
`Idempotency-Key` header exactly matching the body; cross-actor reuse is a typed
conflict. Revoke remains authorization-first, then returns a no-write replay only
to the same still-authorized revoker. Inheritance conflicts refresh access and
re-preview impact rather than bypassing the epoch fence.

Mail platform modernization V195–V208 is an OFF-gated rail. `internal/migration`
and IMAP translate immutable-source/checkpoint and membership-UID contracts.
IMAP pre-auth IDLE is refused (`NO [AUTHENTICATIONREQUIRED]`) before any
deadline-clearing path (med-shard3-012 SHIP): unauthenticated sockets stay under
the ordinary slowloris read deadline and cannot pin `tlsutil.LimitListener`
accept slots; authenticated long-lived IDLE accommodation is unchanged.
IMAP checkpoint writers emit canonical `uid`; readers accept the pre-V209
`lastUID` spelling, reject conflicting mixed payloads, and the checkpoint reducer
atomically projects committed UIDs into legacy `resume_cursor.uids`;
every resumable connector now implements the mandatory `SourceSession` seam:
the adapter owns source identity plus provider-native closed page/candidate
serialization, while the orchestrator applies and commits exactly one bounded
page before acknowledging the next read. IMAP uses UID ranges/UIDVALIDITY, EWS
durable scopes use stable folder IDs while the reducer atomically dual-projects
legacy display-name delta keys, and M365 retains per-category Graph links;
cancellation interrupts source reads and bounded-joins the producer, while
cross-page replay is reducer-operation-ID authority rather than Go heap state;
`internal/mailboxlifecycle` drains retained-mailbox effects and purge work;
`internal/mailwork` scans SLA state and drains local/signed-webhook plus exact
Task/Chat/Drive action effects;
JMAP exposes reducer-owned work, comments, calm preferences, cohort-safe metrics,
stable shared-draft sessions, collaborator catalogs, and full-access business-
calendar administration. `internal/mailwork` also dispatches authorization-first
daily resets and records real first responses. Admin and protocol gateways must not recreate
lifecycle, purge, source-rebind, notification, analytics, or draft-lease decisions.
See `retired-docs:verification/2026-08-10-mail-platform-modernization.md`.

Does NOT own:
- `authserver/` — standalone auth server (see `authserver/AGENTS.md`)
- `shared/` — cross-cutting packages consumed here but owned by `shared/AGENTS.md`
- `mailctl/` — admin CLI
- `clients/` — mobile/desktop apps

---

## 3. Local Contracts

### Startup order (mandatory — `cmd/mailserverd/main.go`)

1. `config.Load()` + encryption key validation
2. Network mode detection (China/Global/Airgap)
3. GeoIP DB download (fail-open)
4. Config atomic pointer + SIGHUP hot-reload goroutine
5. PgBouncer pool (`DB_DSN`) + database-schema-version guard: refuse to start if `MAX(schema_migrations.version)` is behind the version the binary ships. Expected version is **derived** from the embedded `V<NNN>__*.sql` in `sql/dbschema/` (`dbschema.ExpectedVersion()`) — no constant to bump. The loud error names the pending files + `mailctl schema apply`.
5a. Worker + owner pools (native-RLS W1b, INERT): `DB_WORKER_DSN` → `setjoin_worker` (BYPASSRLS) pool for cross-tenant carve-outs (the cron worker today), `DB_OWNER_DSN` → `setjoin_owner` pool for partition DDL. Both **default to `DB_DSN`** when unset — and when equal/unset they ALIAS the main pool (no second connection opened, no extra `defer Close`), so connection count is identical to today. Never `SET ROLE` on a shared pool.
6. Direct connection (`DB_DIRECT_DSN`) — LISTEN/NOTIFY only
7. MinIO/SeaweedFS client init
8. Monthly partition creation (`startup.EnsureMonthlyPartitions`, on the owner pool — new partitions are owner-owned; a thin `SELECT create_monthly_partitions(1)` — the catalog-derived reducer is the ONE owner of the month-partitioned table set, shared with the cron 25th task)
9. Stale multipart abort (`startup.AbortStaleMultiparts`)
10. WORM immutability startup check (`startup.InitWORM`)
11. Secret bootstrap (`startup.BootstrapSecrets`)
12. Feature toggle system (`toggle.New`) — must precede protocol servers
13. LISTEN/NOTIFY dispatcher + `toggle.BindNotifications` config_changed lifecycle. After every direct
    connection reconnect it first restores every LISTEN subscription, then
    reloads every registered authoritative cache before resuming notification
    service; PostgreSQL does not replay notifications missed during an outage.
    Any refresher failure closes the new connection and retries with backoff.
    Feature toggles enter their per-key conservative failure posture, and the
    authentication chain retains only signed bearer verification until a
    complete auth-method snapshot succeeds. Its process-lifetime
    `config_changed` handler is durable: an initial LISTEN failure retains the
    handler for reconnect replay, while request-scoped subscriptions keep the
    ordinary remove-on-failure contract. The shared binder performs the
    readiness-critical post-LISTEN reload and unregisters its notify/reconnect
    callbacks on cancellation. The gateway observer exposes two independent
    capacity-one signals and fixed context-bound goroutines for identity and
    legacy AD reconciliation: bursts coalesce per effect class while a slow AD
    reload cannot block normalized identity replacement. It does not consume or
    replace other `config_changed` subscribers.
14. Threat interceptor (`threat.New`)
15. Spam trainer goroutine
16. Auth chain (`auth.NewChain`) + threat wiring
17. Handlers constructed. Immediately after the AD/LDAP handlers and
    connector-secret validation, the normalized identity-source runtime
    reconciles active AD/LDAP workers only when `feature.identity_model_v2` is
    ON; remaining handlers follow. `config_changed` gives immediate generation
    replacement and a 30-second catalog poll reads the master toggle and source
    rows in one statement, closing lost-NOTIFY/cache windows and stopping every
    worker when the database master gate is OFF.
    Replacement cancels and joins the old generation; shutdown joins every
    worker.
18. Routes registered on `http.NewServeMux` — app JSON is registered with root-relative literals and served canonically under **`/api`** (the SPA block mounts the API mux via StripPrefix; pinned root surfaces per `scripts/api-pinned-prefixes.txt`; old-path non-GETs 308 to `/api/…` for one release)
19. HTTP/2 server (TLS via autocert or static cert; h2c in dev mode)
   In redirect mode, port 80 always targets the configured `HOSTNAME`; request-owned `Host` is never reflected into `Location`.
20. Protocol servers: SMTP inbound (`:25`), SMTP submission (`:587`), IMAP (`:143`/`:993`), LDAP GAL (`:389`/`:636`) — each gated by feature toggle
21. On SIGTERM, disable HTTP keep-alives and signal the overseer worker with
    SIGUSR2 before `http.Server.Shutdown`. Overseer releases inherited
    listeners only on its restart signal; omitting this step deadlocks
    listener teardown until `TimeoutStopSec`. A normal systemd restart must log
    `gateway stopped cleanly`; the outer 35-second bound is defense in depth,
    not the expected path.

`GO_WORKERS_OFF=name,…` suppresses exact, case-sensitive, whitespace-trimmed
worker names at startup and notification dispatch; empty/unknown entries are inert.
Names and original lifecycle policies are pinned in
`cmd/mailserverd/testdata/worker_launch_inventory.golden` and `worker_semantics.json`.
All asynchronous gateway workers, notification callbacks and self-starting helpers
are named. `startWorker` keeps helper startup synchronous (notably the webhook
first claim and AD/LDAP controllers); the identity runtime preserves its startup
error path and deferred join. `ad-sync`/`ldap-sync` also suppress background
config-change syncs so reload cannot restart transferred work. Request-owned
operations and mandatory shutdown still run. Non-HTTP protocol listeners keep
their existing whole-listener config/toggle gates (#238).

Cron's scheduler is `cron`; each task is independently switchable as
`cron:<AllTasks Name>` (for example `cron:scan-due-reminders`). `user-risk` is a
separate loop. Disabling a worker transfers its existing residue/drain obligation
to Rust; with the variable unset all original contexts, retries and joins remain.
`UPDATE_GOLDEN=1` regenerates the launch inventory from the real main.go after
reviewing launch changes; fixture overrides remain read-only.
`bash scripts/check-worker-launch-inventory.sh --self-test` proves new bypasses fail.

`pushjobs.NewWorker` is constructed once and then configured with the worker
pool, MinIO bucket, `noreply@<cfg.Hostname>`, `SetJoin`, and
`https://<cfg.Hostname>`. Its third Guest G1 leg drains
`guest_notification_intents` and reaps sent/stale rows unconditionally; the
guest feature toggle gates enqueue only, never residue drain. Each guest batch
uses a transaction-scoped advisory lock; the bounded mail phase keeps its
`outbound_queue` insert and intent stamp in that same transaction, preserving
atomicity through transaction-mode PgBouncer.

Guest G1 member invitations add `POST /api/me/guest-invites` to the authenticated
user surface. The handler requires both `feature.guest_accounts` and
`approval.guest_invite`, creates a `guest.invite` approval on the worker pool,
and performs the RLS-scoped visibility lookup before any worker-side decision.
On approval, decision + guest provisioning + SHA-256-only invite creation commit
in one worker transaction; the raw 256-bit token is emailed only after commit.

Guest G2a adds the admin management API behind an outer
`feature.guest_accounts` 404 gate, before audited `guests.view`/`guests.manage`
permission middleware. It exposes guest list/detail/lifecycle/profile assignment
and guest-profile CRUD, while `POST /api/admin/guests` creates new guests and
accepts an optional profile. Lifecycle writes
still route through the database-owned `guest_set_status` authority, which
independently requires persisted `guests.manage` before target lookup and keeps
host-domain reach in both the locked read and final mutation.

Guest G2b routes Chat, Drive, and Meet through a user-id entitlement checker
after each feature toggle's 404 gate. Mailbox-less guests therefore share the
same authoritative reducer as members; missing guest rows deny, missing member
rows preserve default allow, and capability lookup errors hide every app.

Guest G2c applies the assigned profile at every Chat grant choke. Memberships
snapshot explicit posting policy plus an immutable join-time history floor;
live profile edits update posting only. BZ220 rejects a read-only guest before
any send-side effect, while every member-facing reader applies the floor and
wall-clock join belt. The web console and constrained Chat shell consume only
server-derived entitlement and External/Removed/container fields.

Guest G2d is the release gate. Real independent sessions prove member-add and
disable serialize to either grant-then-delete or disable-then-BZ219, always
with zero membership after disable. The gate is composite: the admin lifecycle
tracer proves the full profile/entitlement/grant/post/lifecycle/re-invite arc,
and an independent Chat integration tracer observes a real `event: chat` SSE
frame. Because guests have no primary mailbox, EventSource
omits only their JMAP state subscriptions and initial StateChange; their
self-scoped revocation and app push channels remain live. The feature toggle
remains seeded OFF after this gate and is enabled only by deployment choice.

Guest G4 splits Drive preview from original-byte authority without exposing a
standalone Drive app. Chat-derived guests are viewers, meeting attendance keeps
its historical role, and only the exact office-PDF preview route is added to
the guest allowlist. Raw content calls the reducer-owned download gate before
version lookup; `allow_download=false` is constant-shaped BZ215. Preview and
raw reads both inherit live Chat attachment/history-floor revocation. Native
Drive-token minting remains denied. Guest viewers cannot upload attachments:
the chunk handler checks the reducer-owned editor requirement before storage,
and the Chat conversations capability hides composer upload/voice controls.

Guest G5 completes lifecycle ownership. `guest_set_status` is still the single
writer for admin disable/enable/extend and system due-expiry; disable/expiry
atomically align `guest_accounts` with `users.enabled`, revoke all sessions,
and snapshot the guest identity against every parent and breakout room belonging
to each ongoing meeting in which it participated. Meet token mint paths take
the guest lifecycle share lock, so no grant can race past that snapshot. The unconditional
`guestlifecycle.Worker` runs an hourly expiry sweep and a 5s durable SFU drain,
retrying even successful/absent removals through the stale-token horizon.
Guest status handlers and reducers acquire the V172 authority fence before any
guest/user row lock; `provision_account` takes the same fence before identity
resolution, so status changes, expiry, and guest reprovision serialize in the
universal advisory-to-row order rather than forming an ABBA deadlock.
Admin guest detail flags sponsor review and offers a same-scope explicit
sponsor/Chat-owner/Drive-owner transfer; attribution and compliance history are
never rewritten. Conditional Access also accepts targetless `guests` scope.

Guest credential recovery adds the explicit
`POST /api/admin/guests/{id}/reinvite` transition. In one worker transaction it
keeps the same identity, freezes sign-in at invited/disabled, revokes sessions,
records `action='reinvite'` SFU eviction intents, and replaces the pending
invite digest. Expired guests require a supplied future expiry; SSO-linked
guest rows fail closed rather than receiving a local-password fallback. The
post-commit fast drain runs before mail queueing, and all authenticated guest
Meet token paths remain fenced until the durable recovery intents complete.

Guest acceptance is limited to the exact unauthenticated `GET`/`POST
`/auth/guest-invite/accept` pair, the exact GET-only
`/auth/password-policy` bootstrap, and the bare-root, GET-only SPA prefix
`/guest-invite/`. The gateway registers all three authserver routes explicitly
so they cannot fall through to the SPA's HTTP-200 HTML response. The authserver
applies its enumeration guard and performs the
invite tombstone, guest activation, and user credential enablement atomically;
all other guest routes remain subject to `guestgate`. A 16-leg integration
tracer is the G1 hard gate across direct/member invites, disclosure, acceptance,
digest authorization, replay, revoke, and toggle-off behavior.

Violating this order causes startup failures (pool not ready, toggles not loaded before protocol init, etc.).

### Key files

| File | Role |
|---|---|
| `cmd/mailserverd/main.go` | Entry point; complete startup + route registration |
| `internal/config/config.go` | All gateway config fields + `koanf` tags |
| `config.yaml` / `config.env.sample` | Reference config |
| `internal/authproxy/proxy.go` | Reverse proxy — `/auth/*` plus an exact allowlist of root-level OIDC Provider/OAuth protocol endpoints → authserver |
| `internal/middleware/auth.go` | `RequireAuth`, `RequireAdmin`, `RequireRole`, `RequirePerm` |
| `sql/reducers/README.md` | Full reducer contract index |
| `sql/dbschema/` | Schema migration files (V000–V075+) |
| `go.mod` | Module `setjoin.com/mailserver`, Go 1.26.6 |

### Feature toggle gates

Protocol servers are gated by `feature_toggles` (loaded from DB at startup, updated live via `config_changed` NOTIFY):
The direct listener performs a full atomic reload after reconnect; consumers
that also hold long-lived authority must retain their own bounded database
reconciliation backstop.

| Toggle key | Controls |
|---|---|
| `feature.caldav` | CalDAV bridge (`/caldav/`) |
| `feature.carddav` | CardDAV bridge (`/carddav/`) |
| `feature.smtp_inbound` | SMTP MTA on `:25` |
| `feature.smtp_submission` | SMTP MSA on `:587` |
| `feature.imap` | IMAP4 on `:143` / `:993` |
| `feature.ldap_gal` | Read-only LDAP GAL on `:389` / `:636` |
| `feature.gal_carddav` | Read-only GAL CardDAV collection at `/carddav/gal/` (default ON) |
| `feature.dmarc_reporting` | Aggregate DMARC report receiver |
| `feature.tls_rpt` | TLS-RPT (RFC 8460) report receiver |
| `feature.assist` | AI compose assist + admin ops copilot (default off; provider not yet implemented) |
| `feature.offline_mail` | Native-shell offline mail cache (default OFF; seeded by `V029__offline_mail_toggle.sql`; gated by bridge presence + `caps.offline.allowed` before activating UI) |
| `feature.rust_inbox_list` | Answerer for the webmail inbox list (default OFF; #216, ARCH-026/027). Read only by the Rust front door, never by Go: ON, the gateway answers a verified single-tag `Email/query` with a READ ONLY scoped read; OFF, everything proxies here and `jmap_email_query` answers |
| `feature.rust_mark_read` | Writer for webmail mark-read (default OFF; #215, ARCH-026/027). Read only by the Rust front door (`server-rust/bins/gateway`), never by Go: ON, the gateway serves a verified `$seen`-only `Email/set`; OFF, everything proxies here and the reducer writes |
| `device_telemetry` | Privacy-first device telemetry endpoint |

### Auth priority chain (gateway layer)

JWT Bearer (priority 10) → Kerberos/SPNEGO (priority 20, blocked if user has TOTP) → Basic Auth (priority 30, disableable). All `/auth/*` routes and the explicitly registered OIDC Provider/OAuth protocol endpoints proxy to authserver. The root allowlist includes discovery/JWKS, `/authorize` plus `/authorize/callback`, exact `/oauth/token` and `/oauth/introspect`, `/userinfo`, `/end_session`, and `/revoke`; broad `/oauth/` and `/authorize/` gateway patterns are local 404 sinks, never proxies, so unknown protocol paths cannot expose a future internal authserver endpoint or fall through as SPA HTML 200. App passwords are first-class HTTP Basic credentials (per-app scoped token, no TOTP bypass).

**JWT dual-verify (ADR-005).** `JWTProvider.Validate` (`internal/auth/jwt.go`) verifies BOTH legacy **HS256** access tokens (shared `JWT_SECRET`, kid `authserver-hmac-1`/`mailserver-hmac-1`) AND first-party **ES256** access tokens (authserver JWKS). It dispatches on the header `alg`: `ES256` → the shared `jwtutil.ParseES256` primitive (which re-asserts ES256 + requires a kid → resolves the key SOLELY via the JWKS client; closes alg-confusion + jku/x5u injection), then the SAME iss/aud/exp checks as the HS256 path. The ES256 key source is `internal/auth/jwks.go` (`JWKSClient`): fetches the authserver JWKS from `AUTHSERVER_JWKS_URL` ONLY (no token-supplied URL is ever trusted), parses it (`go-jose` `jose.JSONWebKeySet`) into a kid→`*ecdsa.PublicKey` map, caches it (bounded TTL), refreshes on an unknown kid (rate-limited so bogus-kid floods can't hammer authserver), serves stale on fetch error, and fails closed with no cache (verification fails, never panics). Wired in `chain.go`: when `AUTHSERVER_JWKS_URL` is set the client is constructed and attached via `JWTProvider.SetES256Verifier` (startup log line either way); when unset, ES256 tokens are rejected (HS256-only mode). `JWT_SECRET` stays required (HS256 path + derived keys). This is the gateway half of the never-a-flag-day rollout: deploy gateway dual-verify first, then flip authserver issuance to ES256; HS256 acceptance is removed in a later release. **SM2 (Xinchuang `smx`/`hybrid` profile, kid `authserver-sm2-1`):** the third verify branch. SM2 is NOT distributed via the JWKS (only ES256 is) — it uses the symmetric-trust model, so `NewChain` loads the shared `SM2_PRIVATE_KEY_FILE` (the same PEM mounted to authserver, exactly as `JWT_SECRET` is shared for HS256) via `cryptokey.LoadSM2PrivateKey` and passes it to `NewJWTProvider` whenever `CryptoProfile == smx` (or `hybrid` with a key file). Without this the SMx gateway has `sm2Key==nil` and rejects EVERY token (authserver issues SM2-only under `smx`); load failure is fatal at chain construction (fail-closed).

### Database security (enforced)

Follows root AGENTS.md R1–R4. See `docs/standards/DATABASE_SECURITY.md`. Every reducer with `p_mailbox_id` must reference it and scope its user-data statements by the mailbox (the account slot is a `mailbox_id`, ARCH-003). **Per-user isolation (R4) is enforced at the application layer — `p_mailbox_id` propagation in reducers + ownership predicates in raw gateway queries — NOT by native PostgreSQL RLS** (zero policies exist; native RLS is *deferred*). The load-bearing CI controls are `scripts/check-account-scope.sh` (reducer layer: negative A–G + positive H) and `scripts/check-gateway-ownership.sh` (positive, over the raw gateway query surface). See `sql/AGENTS.md:42` and [ARCH-006](../docs/adr/ARCH-006-app-level-isolation-posture.md). Do not claim native RLS is enforced.

### Account-scope currency — the `shared/identity` seam (ARCH-003)

The account-slot argument every reducer receives is ALWAYS a **mailbox id** (the caller's PRIMARY mailbox), never a `users.id` — `users.id` and `mailboxes.id` are independent BIGSERIAL sequences and `mailboxes.user_id` is nullable, so confusing them matches the wrong row (or zero rows) and fails silently. The primary-mailbox lookup is single-sourced in **`shared/identity`**: never hand-write `SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary` in the gateway again.

- `identity.ResolvePrimaryMailbox(ctx, q, userID)` — the canonical primary-mailbox lookup (gateway-wide; ~46 former inline copies routed here). Returns `identity.ErrNoPrimaryMailbox` (wrapping `pgx.ErrNoRows`) when there is no primary.
- `identity.ValidateAccountID(ctx, q, reqMailboxID, userID)` — true iff `reqMailboxID` is the user's primary mailbox. JMAP `parseAccountID` (`internal/jmap/handler.go`) is the thin gateway wrapper around this: it returns the resolved `int64` + the JMAP `accountNotFound` error, and preserves the nil-pool unit-test fallback (compares against `userID`, no DB call). The `*pgxpool.Pool` satisfies `identity.Querier`.
- NOT routed (behavior-preserving, out of scope): in-statement `mailbox_id IN (SELECT … WHERE user_id=$N)` ownership subqueries (R3 — splitting would open a TOCTOU window), multi-column mailbox selects, the address-by-email lookup (`WHERE email=$1`), and the CalDAV primary-or-any `UNION ALL` fallback. The address-union predicate (`resolve_identity`) is Concern B and stays as the two guarded twins.
- The ADR-003 guard (`scripts/check-account-scope.sh`, wired into `scripts/test.sh`) keeps the currency rule un-writable in reducers.

---

## 4. Features / Capabilities

### 4.1 Protocol layer

**SMTP — inbound MTA (`:25`, `internal/smtp/inbound.go`)**
- Receive inbound SMTP with STARTTLS (RFC 5321 + RFC 3207)
- Implicit TLS on `:465` when `smtp.inbound_tls_addr` set
- Per-IP and per-user connection limits (`smtp.inbound_max_conns`, `smtp.per_user_max_conns`)
- Large-message spool-to-disk before pipeline processing
- Greylisting
- RBL/DNSBL checking
- SPF verification (`spf.go`)
- DKIM verification + ARC chain (`arc.go`)
- DMARC enforcement + aggregate report receiver (`dmarc_report.go`)
- Anti-spam scoring: per-user FTRL ML model (`antispam.go`, `spam/` package), plus the `shared/spam` deterministic-detector suite (arch review #A5) wired ADDITIVELY via `ml_detectors.go`'s `applyMLDetectorSignal` — sender-mismatch, forged-recipients, mixed-charset, fake-HTML — behind `feature.spam_ml_detectors` (DEFAULT OFF, V137); off, scoring is byte-for-byte unchanged. The rest of `shared/spam` (OSB tokenizer / multi-class FTRL / composite YAML rules / phishing-template hash / image hash / spamtrap) stays unwired — each needs infra (attachment-byte extraction, a template/hash feed, a trained model store, a rule config file) not yet built. See `internal/AGENTS.md` "Spam scoring" + `docs/design/mail/archive/spam-enhancement.md`.
- ClamAV antivirus (`clamav.go`)
- Milter protocol integration — external filter appliance (SpamAssassin, etc.)
- Attachment behavioral sandbox via CAPE (`sandbox.go`)
- Anti-phishing: display-name spoofing, lookalike domains, contact-trust checks (`antiphish*.go`)
- DLP policy enforcement inline on inbound (`pipeline_deliver_store.go`)
- Link protection — URL rewriting to `/link-protect` click handler (`link_protect.go`)
- Journal-on-delivery (BCC archive) via `journal_if_policy_matches` reducer
- Retention tagging at delivery via `tag_retention` reducer
- Vacation auto-reply + distribution group expansion in `deliver` reducer

**SMTP — submission MSA (`:587`, `internal/smtp/submission.go`)**
- AUTH PLAIN / LOGIN over STARTTLS (RFC 6409)
- Per-user send quota enforcement in `send` reducer
- DLP check, send-as delegation, auto-BCC, signature injection (all in `send` reducer)
- App-password authentication for mail clients (no TOTP bypass)
- DANE/MTA-STS outbound policy enforcement (`dane.go`, `mtasts.go`, `tls_policy.go`)
- DSN generation for bounces (async, in the `scheduled_action_dsn` reducer — the `dsn` scheduled-action handler; the synchronous Go `dsn.go` was retired in WAVE 9)
- TLS-RPT aggregate report submission (`tlsrpt.go`)
- Outbound DKIM signing (`pipeline_modify_dkim.go`)
- Spool-to-disk for large messages before queuing

**IMAP4rev2 (`:143`/`:993`, `internal/imap/`)**
- Full IMAP4rev2 (RFC 9051): LOGIN, SELECT, FETCH, STORE, SEARCH, APPEND, EXPUNGE, IDLE, UID commands
- STARTTLS on `:143`; implicit TLS on `:993` (default when the shared TLS certificate is configured). Pre-TLS capability includes `STARTTLS LOGINDISABLED`; both `LOGIN` and `AUTHENTICATE` fail with `PRIVACYREQUIRED` until the upgrade succeeds. Configuration validation rejects a non-loopback `IMAP_ADDR` unless both `TLS_CERT` and `TLS_KEY` are set; only an explicitly loopback-bound development listener may run without transport TLS.
- Per-user and total connection limits (`imap_limits.go`)
- Tag-based folder model: IMAP folders map to tags; `imap_uid_next` tracked per tag
- App-password authentication

**JMAP (RFC 8620/8621, `internal/jmap/`)**
- Full JMAP Core session (`/.well-known/jmap`, `/jmap`)
- HTTP and WebSocket requests share `JMAPHandler.ExecuteBatch`, the sole owner of non-empty `using`, 32-call and 2,000,000-byte per-call limits, ordered result references, `createdIds`, continuation, registry-derived entitlement/delegate invocation metadata, dispatch metrics, and method error ordering. HTTP retains RFC 7807 request problems; WebSocket projects the same typed failures as RFC 8887 `RequestError` with `requestId`. The transports retain their existing 10 MB/10 MiB body/frame bounds and own no execution loop.
- Email/get, Email/query, Email/changes, Email/set (create/update/destroy), Email/queryChanges
- Thread/get, Thread/changes, SearchSnippet/get (plain GIN + `ts_headline`, not ParadeDB/BM25 — see `sql/AGENTS.md` "Full-text search")
- Mailbox/get, Mailbox/query, Mailbox/changes, Mailbox/set, Mailbox/queryChanges
- EmailSubmission/set (send), EmailSubmission/get, EmailSubmission/query (scheduled send listing)
- Identity/get (from aliases + delegation), Identity/set
- QuickStep/get, QuickStep/set (create/update/destroy), QuickStep/apply (A2) — user-defined one-click triage macros (`internal/jmap/quicksteps.go` → `quick_step_*` reducers); mailbox id resolved from auth (R2), action allowlist + ownership enforced in the reducer
- CalendarEvent/get, /query, /changes, /set (set carries `valarm` reminder alerts), /import (bulk `.ics` file import → `calendar_import_ics` reducer, calendar-ownership checked; parser reuses `migration.SplitAndParseICS`, never the raw-INSERT path)
- Calendar/get, /changes, /set
- **A3 calendar parity** (`internal/jmap/calendar_a3.go`): Calendar/getShared, CalendarEvent/getShared (open another user's calendar; viewer = authenticated `user.UserID`, never a body field; `freebusy` grants redact title/location/description), Calendar/shareGet, Calendar/shareSet (calendar_acls grant/revoke; owner/admin-gated; levels freebusy/read/write/admin via V084), Calendar/delegateList, CalendarEvent/setOccurrence (this/following/series recurring edit), CalendarEvent/resourceList (bookable rooms), CalendarEvent/sendUpdate (SEQUENCE bump + iTIP REQUEST re-issue). CalendarEvent/rsvp gained `onBehalfOf` (delegate respond). CalendarEvent/set create books `role='resource'` attendees via `calendar_book_resource`.
- **Self-service booking pages** (feature #6; `feature.booking_pages`, DEFAULT OFF; V113 `booking_pages`/`booking_requests`; `sql/reducers/booking_pages.sql`; BZ134-BZ137). An owner publishes `/book/<slug>`; a booker picks a slot computed from the owner's REAL free/busy through the existing `calendar_busy_intervals` seam (busy-only, never event detail), submits (mandatory double opt-in — no calendar event exists until the emailed verify link is clicked), and the confirm step creates the event via `jmap_calendar_event_set_create` + sends an iTIP invite via `jmap.EnqueueInvite` (the same egress `CalendarEvent/set create` uses). This is setjoin's **first deliberate unauthenticated public app surface** — see §4.6 and `docs/adr/DES-007-public-booking-surface.md` for the full security posture (enumeration parity, rate limits, honeypot, hashed single-use tokens, the BYPASSRLS worker-pool carve-out). Owner CRUD: `GET/PUT/DELETE /api/booking/pages` (authed, `internal/booking.Handler`). Webmail: `/settings/booking` (owner config) + `/book/[slug]` + `/book/confirm` (public, standalone — no app shell).
- Contact/get, /query, /changes, /set; AddressBook/get, /changes, /set
- Task/get, /query, /changes, /set
- JMAP blob upload (`/jmap/upload/{accountId}`) and download (`/jmap/download/...`)
- WebSocket push and JMAP requests over `/jmap/ws` (JWT from HttpOnly cookie, no Authorization header); Request frames route through the same execution envelope as HTTP.
- Read receipt endpoint (`POST /auth/me/read-receipt`, body `{messageId, consent}`) — MDN RFC 3798. The **recipient** controls whether an MDN is ever sent via the per-user `read_receipt_policy` ∈ {ask (default), always, never} (V081); `send_read_receipt()` is the hard gate (`never` suppresses even with consent, `ask` needs consent). Set on the Privacy settings page
- Mailtips endpoint (`GET /auth/me/mailtips`) — compose-time warnings: large audience, external recipient, missing send-as, and **out-of-office (QoL #7)**. The OOO branch routes through the `recipients_ooo_status(p_mailbox_id, p_emails jsonb)` reducer (logic-where-the-data-is) — resolves each address via `resolve_identity` (external/unknown → absent, no directory-enumeration oracle) and returns **dates only** (`type:'ooo'`, `until` = end-date or null for indefinite), never the auto-reply body. Active-window logic verbatim from `deliver_group_vacation`.

**CalDAV (RFC 4791, `internal/caldav/`)**
- PROPFIND, REPORT, PUT, GET, DELETE on `/caldav/`
- iCalendar read/write with recurrence expansion (`ical.go`)
- iMIP parsing and delivery (`imip.go`)
- iTIP REQUEST/REPLY/CANCEL processing (`itip.go`) — a RECURRENCE-ID REQUEST/CANCEL applies to the recipient's local master via `jmap_calendar_event_set_occurrence('this', ...)` instead of the whole-series dedup/cancel (`retired-docs:superpowers/plans/archive/2026-07-08-recurring-event-occurrence-edit.md`). Round 6 (Astra HOLD): the series-CANCEL sweep is gated PER AFFECTED MAILBOX, not bound to the signer's domain — `cancelAffectedDomains` enumerates owner domains of every non-cancelled local copy sharing uid+organizer, each copy is cancelled only when its owner domain's `domainAcceptsCancelEvidence` policy accepts the authenticated evidence (S/MIME evidence must be covered by that domain's trust; DKIM/SPF evidence is not tenant-scoped; `SmimeTrustNone` accepts nothing), and the reducer is invoked once per accepted domain. External-organizer cancellations reach exactly the mailboxes whose policy trusts the evidence.
- Free/busy batch query (`freebusy_batch.go`)
- Calendar invite endpoint (`POST /calendar/free-busy`)
- Feature-toggle gated (`feature.caldav`)
- PROPFIND/REPORT property selection uses `internal/webdav.ResolveProperties`: requested and allprop catalogs are ordered, present values precede missing values in exact 200/404 propstats, typed nil is absent, and explicitly missing CalDAV values retain their namespace as empty XML elements. CalDAV owns only its typed request catalog/value installer.
- **Resource model: one CalDAV resource per uid.** A recurring master + its detached-occurrence override rows (`recurrence_override` set, same `uid`) render as ONE `.ics` resource: `listEvents`/`listEventsFiltered`/`getEventByUID` scope to the master row (`recurrence_override IS NULL`); `eventToICalWithOverrides` (`caldav.go`) renders the master plus one VEVENT per override inside a single `VCALENDAR`, each override tagged `RECURRENCE-ID` (`ical.go`'s `writeVEVENT`, split out of `eventToICal` for this). PUT parses the whole body via `ParseICalObjects` (Apple/Google send master + exception VEVENTs in one request; the single-object `parseICal` wrapper stays for every non-recurring caller) and reconciles exception VEVENTs/EXDATEs against existing override rows through `jmap_calendar_event_set_occurrence` — RFC 4791 PUT replaces the whole resource, so an exception dropped from the wire is dropped from the DB. EXDATE/RECURRENCE-ID parse both the bare UTC-Z form (Google) and `TZID=`/`VALUE=DATE` parameter forms (Apple), resolved to the same instant either way.

**CardDAV (RFC 6352, `internal/carddav/`)**
- PROPFIND, REPORT, PUT, GET, DELETE on `/carddav/`
- vCard 3.0/4.0 read/write (`vcard.go`)
- Feature-toggle gated (`feature.carddav`)
- PROPFIND/REPORT property selection uses the same `internal/webdav.ResolveProperties` authority and exact 200/404 grouping; CardDAV owns only its typed request catalog/value installer, including namespaced empty elements for explicitly missing properties.
- **GAL collection (`/carddav/gal/`, `gal.go`, read-only).** The org directory
  (webmail `/directory` + LDAP GAL's same audience) exposed as a third CardDAV
  addressbook, auto-appearing next to personal books in the home PROPFIND
  (Depth 1 on `/carddav/`) — no per-user opt-in. Members are
  `/carddav/gal/u{userID}.vcf`, `UID:setjoin-gal-u{userID}` (stable across
  renames), served straight off `directory_visible_users(p_mailbox_id)` — the
  SAME ADR-004 visibility seam webmail directory browsing and the LDAP GAL
  read from (one seam, three protocols; see `sql/AGENTS.md`). Guest P7 is
  enforced in that seam by excluding every `guest_accounts` discriminator row
  regardless of lifecycle state, so GAL/CardDAV never publishes guests. People only (no
  distribution groups / resource mailboxes as vCards). PROPFIND/GET/REPORT
  (addressbook-query with a parameterized `text-match` filter,
  addressbook-multiget, sync-collection via the `gal_changes` reducer) all
  work; PUT/DELETE (and the OPTIONS `Allow` list) are hard-rejected with a
  403 `DAV:cannot-modify-protected-property` — the directory is provisioned
  by admin/AD-sync, not by CardDAV clients, same stance as the LDAP GAL's
  `handleReadOnly`. Sync-collection token = `{maxUpdatedµs}-{visibleCount}`;
  a count mismatch (hard-delete, not just disable/hide) forces a full resync
  instead of ever serving a stale delta. Toggle `feature.gal_carddav`
  (default ON — parity with `feature.ldap_gal`; exposes nothing an
  authenticated user can't already browse at `/directory`), runtime-checked
  per request so an admin can flip it live; the whole bridge is still gated
  behind `feature.carddav` + `requireApp("contacts")`. `.well-known/carddav`
  and `.well-known/caldav` (RFC 6764, `main.go`'s `registerProtocolRoutes`)
  301-redirect to `/carddav/` / `/caldav/` so Apple/GNOME/DAVx5 auto-discover
  the server without a manual path — the GAL then rides the existing
  account's next collection-list poll.

**LDAP GAL (read-only, `internal/ldap/`)**
- RFC 4510 LDAP server on `:389`/`:636`; serves Global Address List (company directory)
- Paged search with `paging.go`, filter evaluation with `search.go`
- DN escaping via `dn.go`
- Every People base/subtree search and Compare resolves the bound user's primary mailbox through `identity.ResolvePrimaryMailbox` and reads `directory_visible_users(mailbox_id)`, the same ADR-004 authority as CardDAV/webmail. Hidden and Guest principals disappear uniformly; alias and UPN matching use the seam's full address set. Missing caller mailbox or query failure returns an LDAP operation failure, never a broader directory.
- Feature-toggle gated (`feature.ldap_gal`)
- Every data-returning handler (`handleSearch`/`handleCompare`) must assert a typed `BoundPrincipal` via `isBound(msg)` before touching the DB — `handleBind` (server.go) is the only place that stores it, after `auth.CheckPassword` succeeds. A client that never Binds (or fails to) gets `LDAPResultInsufficientAccessRights`, not a directory dump (A1 fix). `scripts/check-ldap-bound-state.sh` guards every `routes.Search()`/`routes.Compare()` registration in `server.go` against a reintroduced unguarded handler.

**SCIM 2.0 (RFC 7644, `internal/scim/`)**
- User and Group provisioning endpoints
- PATCH/PUT/DELETE for user lifecycle management
- Token validation via `scim_validate_token` reducer
- Every Group mutation carries the authenticated token's exact source
  generation. The reducer locks and rechecks `kind=scim,state=active,generation`
  in the mutation transaction; stale generations are BZ229 and inactive
  sources are BZ224.
- Optional; enabled via `SCIM_ENABLED=true`

### 4.2 Mail features

**Tag system (Phase 17)**
- Gmail-style multi-label model — `message_tags` junction table
- Exclusive groups: `location` {Inbox, Sent, Drafts, Trash, Spam}; `snooze` {Snoozed, Scheduled}
- Archive = remove location tag; All Mail = messages without Trash/Spam. The Archive **view** (A2) is the read side: `jmap_email_query`'s `inArchive` filter selects messages with no `location`-group tag
- State tokens: `jmap_email_state`, `jmap_mailbox_state`, `jmap_tag_state` (all bumped atomically in reducers via `notify_state_change`)
- NOTIFY channel: `tag:{mailbox_id}` → WebSocket fan-out

**Triage (A2 — V083)**
- **Quick Steps**: `quick_steps` table (per-mailbox named action macros) + `quick_step_{list,set,delete,apply}` reducers (`sql/reducers/quick_steps.sql`). A macro is an ordered array of a SUBSET of the rule-engine action vocabulary (move_to/categorize/flag/mark_read/forward_to) run through the shared `apply_action`. The allowlist (`quick_step_action_allowed`) is enforced at BOTH set and apply time — privileged rule actions (add_header/discard/delete) are rejected (`BZ043`), never silently passed through. Errors `BZ040`–`BZ043` (see `docs/reducer-error-codes.md`).
- **Flag for follow-up**: `messages.flag_due_at` / `flag_reminder_at` columns; set/cleared via `jmap_email_set_update` (`flagDueAt`/`flagReminderAt` patch keys; clearing `$flagged` nulls both), echoed by `jmap_email_get`. A2 only **stores** the instants — A6's `scan_due_reminders()` + `remind` handler fire the reminder (no parallel timer).
- **`jmap_email_get` property-projection contract (offline #1a):** when the client sends `properties: [...]` in an `Email/get` call, `jmap_email_get` projects only the requested columns. The offline sync engine requests exactly `METADATA_PROPS` (12 fields: `id`,`threadId`,`mailboxIds`,`keywords`,`receivedAt`,`hasAttachment`,`preview`,`subject`,`from`,`to`,`cc`,`bcc`) so sync fetches never over-fetch body content. Body content is fetched separately on open via an unrestricted `Email/get`. Callers must not add body properties to the sync projection.

**Message delivery**
- `deliver` reducer (`sql/reducers/deliver_group_vacation.sql`): alias resolution, group expansion, spam verdict, quota enforcement, vacation auto-reply, rule application, journal, retention tag
- **Focused/Other inbox split (V078)**: an Inbox message is Focused (no `Other` tag) or Other (carries the `Other` system tag — `exclusive_group=NULL`, `imap_expose=FALSE`, like `Muted`; absence = Focused). `deliver`'s Inbox arm calls `classify_focus` (deterministic, NOT ML — first match wins: per-sender override → contacts → internal sender → List-Id → first-time-external → else Focused); a TRUE verdict tags `Other`. `set_message_focus` moves a message + upserts a per-sender preference in `focus_sender_overrides` (per-user RLS). Read side: `jmap_email_query`'s `focus` filter (`'focused'`/`'other'`). Endpoint `POST /messages/{id}/focus` (`user/focus.go`, body `{focused}`). Webmail UI deferred.
- **Per-sender remote-image trust (WAVE-5 #5, V091)**: `user_image_allow(user_id, sender)` — EXACT-ADDRESS grain (not domain: a domain grain would trust every local-part at a shared big provider off one opt-in), FORCE RLS self policy copying V078 `focus_sender_overrides`'s shape. `internal/user/image_allow.go` (`GET/POST /settings/trusted-senders`, `DELETE /settings/trusted-senders/{sender}`), every statement via `dbscope.RunUserScoped` + an explicit `user_id=$1` predicate (R1–R3). Ungates the webmail's remote-image FETCH only — HTML always still passes DOMPurify sanitize.
- Soft-delete / Trash / permanent purge lifecycle (`jmap_email_set_destroy`, `jmap_email_purge`)
- Deleted-items recovery (`jmap_email_query_deleted`, `jmap_email_recover`)
- Auto-purge of soft-deleted messages >30 days (`purge_deleted_messages` cron)

**Outbound send**
- `send` reducer (`sql/reducers/send.sql`): authorization, send-as delegation, DLP check, local delivery, SMTP outbound queue, identity rules (signature injection, auto-BCC)
- Scheduled send (B2): `sendAt` field on EmailSubmission; `process_message_timers` cron wakes them; listed via `jmap_email_submission_get/query`
- Undo send (Stage 1.6): cancel within configurable delay window — `POST /messages/{id}/undo`; user configures delay at `PUT /settings/undo-send`; `user/undo_send.go`
- Message recall (after delivery): `POST /messages/{id}/recall`; 5-minute window; `internal/user/recall.go`, `sql/reducers/recall.sql`
- Message snooze (B1): `message_snooze` reducer applies Snoozed tag + `snooze_until`; `process_message_timers` cron wakes; `SnoozePicker.svelte` in webmail
- Tag-on-send (B3): add tag atomically during send via `send` reducer `p_tag_on_send` parameter

**Distribution groups + shared mailboxes**
- Distribution group expansion in `deliver` reducer
- Shared mailboxes via `mailbox_delegates` (not mailbox type)
- `deliver_group_vacation.sql` handles both

**Vacation auto-reply / Out-of-Office (A5)**
- Configured per mailbox; throttled (one reply per sender per day)
- Triggered in `deliver` reducer; respects RFC 3834
- **Separate internal vs external reply bodies** (Outlook OOO parity, V086): external senders get `body_external`, internal senders get the internal body; `external_audience` ∈ all/contacts/none gates whether external senders are replied to (`contacts` = only the owner's saved contacts)
- Self-service: `GET/PUT /user/automatic-replies` (`user/auto_reply.go`) → `get_vacation`/`set_vacation` reducers; mailbox derived from auth (R2). The settings PAGE is a later webmail step

**Out-of-office approval delegation / entrust (QoL #23, V105)**
- A date-range "entrust" distinct from the mail vacation reply: while active, an incoming **approval** request that resolves to the delegator is rerouted to the delegate. `approval_resolve_approver` calls `approval_active_delegate(user_id)` at resolution time (before the approver is snapshotted onto the request), so only requests created *during* the window are reassigned — already-created ones are untouched (DingTalk/Feishu semantics). Single-hop only (a delegate who is themselves OOO is not chained). Only the `user` kind is substituted; `role_group`/`skip` are untouched.
- `approval_delegations` (V105) deliberately has **NO RLS** (mirrors `vacation_settings`, not `approval_requests`): the resolution read runs on behalf of the *approver*, a different user than the requester, so FORCE RLS would hide the row — reads/writes are scoped by the `p_user_id` param instead (app-layer R1–R4 by propagation).
- Reducers: `approval_active_delegate` (resolver hook), `set_approval_delegation`/`get_approval_delegation` (user CRUD; BZ119 on invalid window / self / cross-domain delegate). Self-service: `GET/PUT /user/approval-delegation` (`user/approval_delegation.go`), delegator derived from auth (R2). Webmail: `src/routes/settings/approval-delegation/+page.svelte` (delegate picker reuses `directorySearch` + native `datetime-local` window).

**Send-as / delegation**
- Authorized via `mailbox_delegates` table; checked in `send` reducer (BZ003 on unauthorized)
- Send-as aliases: `jmap_identity_get` returns all user aliases as From identities

**User signatures**
- Multiple named signatures per user; applied by `send` reducer identity rules
- CRUD at `GET/PUT/DELETE /settings/signatures`; `user/signatures.go`

**Email annotations / external sender banner**
- External sender visual banner injected at read time; configurable threshold via `PUT /settings/external-sender`
- `EmailAnnotations.svelte`, `ExternalSenderBanner.svelte`

**RFC 8058 one-click unsubscribe**
- `POST /messages/{emailId}/unsubscribe`; `user/newsletter.go`, `NewsletterBundle.svelte`

**Raw .eml download**
- `GET /messages/{emailId}/download` — user self-service; `user/raw_email.go`

**Message recall (post-delivery)**
- `POST /messages/{id}/recall`; `user/recall.go` → `recall_message()` reducer (ARCH-002 — no raw cross-mailbox UPDATE in Go). Handler keeps the `isSender` + 5-min-window pre-checks as defense-in-depth, then routes the recall through the reducer (the structural gate). Recall is **unread-only + local-only + soft-to-Trash + visible stub** (the residual bound — Message-ID is forgeable; see `retired-docs:superpowers/plans/archive/2026-06-19-recall-harden.md`). The HTTP response is caller-safe `{status, recalled}` only (no cross-mailbox count / recipient list — that is a recipient-enumeration oracle); verdict→status: success→200, notFound→404, alreadyRecalled→409, disabled→404. `sql/reducers/recall.sql`.

**Sender allow/block lists**
- Per-user allow list (never-block) and block list at `GET/PUT /settings/senders`; `user/sender_list.go`

**View preferences + IMAP visibility**
- `GET/PUT /settings/view` — view density, thread grouping; `user/view_prefs.go`. Includes `offlineWindow` (default `"30d"`) — the offline sync retention window requested by the client. Validated against the enum `{7d,30d,90d,180d,365d,all}` by `validOfflineWindow` in `view_prefs.go` (mirrors `lib/offline/window.ts OFFLINE_WINDOWS`); read by the webmail's sync engine to compute the cache cutoff. Back-filled from the default map when the stored row predates the field.
- `GET/PUT /settings/imap` — IMAP folder visibility flags; `user/imap_settings.go`

**Migration (Phase 18)**
- Self-service user migration: IMAP, EWS (Exchange), Microsoft Graph / M365
- ICS calendar import, VCF contact import
- PST file import: `internal/pst/` — Microsoft Outlook PST parser
- Orchestrator: `internal/migration/orchestrator.go` dispatching on source_type
- Admin job control: list, cancel, retry, pause, resume; `admin/` + `user/migration.go`
- Admin bulk actions: `POST /admin/migration/test-connection` + `POST /admin/migration/start` (one job per target); `internal/migration/admin_api.go` (`migration.AdminAPI`), both `mail.pipeline`-gated
- Global source configs stored encrypted in `system_config` (EWS, M365)
- Admin-scoped: `PUT /admin/migration/source/{type}`, M365 OAuth consent flow
- **M365 admin-consent states (`V234` + reducers, med-shard2-023 SHIP)**: the consent lifecycle is reducer-authoritative — `m365_consent_state_mint` (one server-side single-use expiring state + same-actor spent/expired prune in one tx, DB-clock expiry), `m365_consent_state_consume` (guarded consumption commits before OAuth verification, so a competing callback can never double-consume; consumption deliberately survives verification failure), `m365_consent_complete` (final config+audit in one tx). The gateway (`internal/user` M365Connect) only orchestrates: random 32-byte token, calls mint inside `dbscope.RunUserScoped`; ownership (`actor_user_id`) is bound in every statement (R1/R3), never GUC-only. V234 is ENABLE+FORCE RLS with actor equality in `USING`/`WITH CHECK` (denial, not filtering). pgTAP covers replay/verify-failure; concurrent same-token exactly-one-winner is reducer-guaranteed.
- Operator docs + source×capability coverage matrix (mail/calendar/contacts/delta/rules, all 3 connectors + Zimbra): `docs/guides/M365_MIGRATION.md`. No native Zimbra connector — deliberate (ACCEPTED-RISK, `docs/audit/2026-07-04-ga-gap-list.md` G0-007): Zimbra migrates via the generic IMAP connector + `.ics`/`.vcf` upload, documented as a runbook in that guide. EWS's `SyncFolderItems`/`FetchDeltaItems` is built + tested but does **not** implement `DeltaLinker` — unlike M365, it is not orchestrator-wired for incremental resync (one-shot bulk pull only; M365 is the only connector with real delta resume via `orchestrator.go`'s `DeltaLinker` restore/persist).

**App passwords**
- Per-app scoped HTTP Basic credentials; no TOTP bypass; time-limited or permanent
- `GET/POST/DELETE /auth/me/app-passwords`; admin oversight at `/admin/users/{id}/app-passwords`
- `user/app_passwords.go`, `admin/admin_app_passwords.go`

**User webhooks**
- User-scoped outgoing webhooks with HMAC-SHA256 signing; self-service creation is always explicit `scope=self`
- `POST/GET/DELETE /auth/me/webhooks`; `user/user_webhooks.go`

**Org chart + directory**
- `GET /auth/me/org-chart` → recursive manager/reports chains; `user/org_chart.go`
- `DirectorySidebar.svelte`, `DirectoryMemberList.svelte`, `OrgChart.svelte`

**Security score**
- Per-user security posture score (MFA enrollment, passkeys, recent activity)
- `GET /user/security-score`; `user/security_score.go`

**Login history + device management**
- `GET /user/login-history`, `POST /user/login-history/{id}/report`
- `GET /user/devices`, `DELETE /user/devices/{fingerprint}/sessions`
- `user/login_history.go`, `user/devices.go`

**Notification preferences**
- Push, email, DND scheduling, per-device preferences
- `GET/PUT /user/notification-preferences`; `user/notification_prefs.go`
- Also carries the per-user `read_receipt_policy` (Track A privacy; `ask`/`always`/`never`). PUT validates the value and, when omitted, defaults to `ask` on insert but **preserves** the existing value on update (so saving unrelated notification prefs never resets the receipt choice) — this preserve-on-update contract only actually held for the global (NULL `device_fingerprint`) row after **V123** (`sql/dbschema/V123__notification_prefs_dedup.sql`) fixed a pre-existing bug: `user_notification_prefs`' `UNIQUE(user_id, device_fingerprint)` was a PLAIN unique constraint, and Postgres treats every NULL as distinct from every other NULL under a plain UNIQUE, so `ON CONFLICT (user_id, device_fingerprint) DO UPDATE` (SetPrefs' only write path) never actually conflicted for the global row — every save silently INSERTed a duplicate instead of updating one, and GetPrefs's `ORDER BY device_fingerprint NULLS FIRST` (no secondary sort key) then returned an arbitrary tie. V123 switches to `NULLS NOT DISTINCT` (PG15+, already used at V015/V041/V109) after a dedup DELETE for any deployment that already accumulated duplicates.
- **VIP senders (QoL #10a)**: `GET/PUT /user/vip-senders` on the same handler → `vip_sender_set`/`vip_senders_list` reducers (`sql/reducers/vip_senders.sql`), table `vip_senders` (V106, per-user FORCE RLS, `sql/dbschema/V106__vip_senders.sql`). Deliberately reuses `user_notification_prefs` + the existing Muted-tag mute-thread path rather than a new prefs table (H3). Webmail: star toggle in `SenderCard.svelte` (`$lib/stores/vipSenders.svelte.ts`), VIP filter chip in the inbox topbar (hidden until ≥1 VIP; composes a single `from:` search term — ponytail, no OR-of-senders in v1).

### 4.3 Security features

**SMTP inbound pipeline checks** (all in `internal/smtp/`)
- SPF (RFC 7208) — `spf.go`
- DKIM (RFC 6376) + ARC (RFC 8617) — `dkim.go`, `arc.go`
- DMARC (RFC 7489) + DMARC aggregate report receiver — `dmarc.go`, `dmarc_report.go`; feature-toggle gated (`feature.dmarc_reporting`)
- Greylisting
- RBL / Spamhaus DROP
- ClamAV antivirus — `clamav.go`
- Milter protocol support
- Attachment sandbox (CAPE behavioral analysis) — `sandbox.go`; fail-open by default
- Anti-phishing: display-name spoofing (`antiphish_display.go`), lookalike domain detection (`antiphish_lookalike.go`), contact trust checks (`antiphish_contact.go`), confusable Unicode characters (`confusables.go`)

**Outbound security**
- DKIM signing — `pipeline_modify_dkim.go`; per-domain keys managed via admin
- DANE/TLSA verification — `dane.go`
- MTA-STS policy enforcement — `mtasts.go`
- TLS-RPT report submission — `tlsrpt.go`; feature-toggle gated
- Outbound TLS policy per domain — `tls_policy.go`; admin at `GET/PUT /admin/outbound-tls-policy`

**Link protection**
- URL rewriting to signed `/link-protect` redirect; Google Safe Browsing + Spamhaus DBL scanners
- `internal/linkprotect/`; click audit log at `/admin/link-protect/audit`

**S/MIME**
- Per-user certificate upload, signing, verification
- `internal/smime/`, `admin/admin_smime.go`
- User CRUD at `/auth/me/smime/certs`
- Inbound verify (`feature.smime_verify`) chains against **per-recipient-domain** trust pools: bundled Mozilla roots ∪ deployment-wide anchors (`smime_trust_anchors.domain_id IS NULL`) ∪ the recipient domain's anchors — one tenant's imported root cannot grant trust in another. Built lazily + cached per domain in `InboundServer.smimeDomainPools` (RWMutex-guarded), cleared on the `smime_trust_changed` notify (admin trust-anchor CRUD emits it). Pool is never nil (fail-open → empty pool → untrusted, delivery proceeds). Round 6 (Astra HOLD): admin import persists ONE ROW PER CERTIFICATE of an uploaded PEM (each row its own single-cert PEM + fingerprint, via `smime.ParseAnchorChain`), and `smime.BuildTrustPool([]smime.AnchorPEM)` loads only certs whose DER fingerprint equals the authorizing row — a bundle can never smuggle unfingerprinted roots into a pool. `InboundServer.smimeAnchorTrustScope` resolves a validated chain's anchor into the tri-state `caldav.SmimeTrustScope` — unrestricted (bundled root via `smime.IsBundledRoot` or deployment-wide row), domain-scoped (tenant row's domains), or NONE (unknown/removed/unresolvable anchor or DB error — fail closed). Admin trust store: `admin/admin_trust_anchors.go`, `sql/dbschema/V015__smime_trust_anchors.sql`.

**WORM / S3 Object Lock (compliance)**
- Governance or compliance mode; configurable retention days (default 2557 / 7 years)
- `startup.InitWORM`; retention registry wired into blob handler
- `sql/dbschema/` (WORM schema integrated in initial schema)

**DLP (Data Loss Prevention)**
- Pattern library managed at `/admin/dlp/patterns`; applied inline on `send` reducer
- admin DLP config; `admin/admin_dlp.go`
- Consolidation migration: `V075__dlp_consolidate.sql`

**Threat interceptor (shared)**
- `shared/threat/interceptor.go` — 8-step pipeline: feed-block → IP-rules → geo-block → lockout → spray-detect → CAPTCHA → tarpit → rate-limit
- Wired into gateway at startup; also used by authserver
- Policy engine + conditional access: device trust, IP risk scoring, conditional access policies

**Conditional access policies (CA-F substrate — V025; CA-0a engine + write path)**
- Admin CRUD at `/admin/conditional-access/policies`; `admin/admin_conditional_access.go`. Create and Update each wrap `ca_policy_upsert` plus optional `set_session_control` in one transaction, so BZ098/BZ080 cannot commit a partial policy mutation.
- Break-glass read/write: `GET /admin/conditional-access/break-glass` (resolves set to display data) + `PUT /admin/conditional-access/break-glass` (calls `ca_break_glass_set` reducer); `ConditionalAccessHandler.GetBreakGlass`/`SetBreakGlass`. Gated: `access.policy_read`/`access.policy_write`. V222 serializes this write with policy and admin-authority mutations; deferred database validation rejects a commit that would remove the last enabled, permanent, non-JIT escape admin.
- Resolve-principals: `GET /admin/conditional-access/resolve-principals?users=…&groups=…` — batch id→display for exclude picker; `ConditionalAccessHandler.ResolvePrincipals`. Gated: `access.policy_read`.
- All CA routes now use `access.policy_read` (read) / `access.policy_write` (write) (adopted from CA-F §F5; replaced prior `requireAuthPerm`/`requireIdentityWrite`).
- **CA-F substrate (`V025__ca_foundation.sql`)**: `user_group_members` table (+ RLS FORCE); `user_devices.device_id` FK→`devices.id` (SET NULL; canonical device model F3); `oauth_tokens.family_id` (refresh-family UUID, inert until CA-3); `access.policy_read`/`access.policy_write` seeds in `admin_permissions`; `ca_fail_mode` seed in `system_config` (`"closed"` default); `ca_validate_policy_document(p_conditions jsonb, p_grants jsonb) RETURNS boolean` SQL allow-list CHECK helper (F6 mirror of `shared/threat/policyschema.go`).
- **`ca_notify_policy_change(p_reason TEXT)`** reducer (`reducers/ca_notify_policy_change.sql`): the single choke point that announces any CA policy mutation. Calls `app_notify('conditional_access', …)`. Error BZ079 on empty reason. All admin CA write paths call this reducer; both servers subscribe to the resulting NOTIFY.
- **`ca_break_glass_set(p_actor, p_ip, p_ids[])→VOID`** reducer: writes `system_config.ca_break_glass_user_ids`, appends `admin_audit_log` row, calls `PERFORM ca_notify_policy_change('break_glass_set')`. Requires non-empty array (22000). See `mailserver/sql/AGENTS.md` for details.
- **`conditional_access` NOTIFY channel**: the single fixed channel both mailserver and authserver LISTEN on. Mailserver: `listener.Subscribe(ctx, "conditional_access", …)` calls `policyEngine.InvalidateCache()` + `policyStore.LoadBreakGlass` + `policyEngine.SetBreakGlass` (CA-0a Task 9). Authserver: same pattern in the LISTEN goroutine. `InvalidateCache()` flushes BOTH the policy-set cache and the F8 per-principal decision cache; `SetBreakGlass` refreshes the break-glass snapshot so changes propagate within the engine's TTL window.
- **`session_revoke` NOTIFY channel** (CA-3a): fixed global channel; gateway LISTENs once at startup and applies each `{user_id, scope, not_before, expires_at, jti?, family_id?}` payload to both `SessionDenylist` (indexed future request/handshake rejection) and the process-wide `ProtocolSessionRegistry` (immediate closure of established IMAP/SMTP/WS/SSE transports). Paired access/refresh tokens carry the same family; WS/SSE's client signal uses exact all/JTI/family semantics rather than a user-wide fallback. Missing-`iat` push tokens are refused. The 30 s reconcile repairs missed notifications; refreshes serialize and merge concurrent `Apply`, and both caches compact keys and prune expired enforcement. `revoke_user_sessions` is the sole producer: all scope is the complete user boundary and compacts to one watermark, family scope also revokes matching OAuth anchors, and JTI scope removes its persisted web session. V172 requires expiry and adds targeted indexes; audit evidence remains separate. Expired rows are pruned daily. Possession gate (V273): the same boundary also deletes the first-factor gate's artifacts — all scope deletes every `mfa_reauth_step_ups`/`webauthn_ceremonies` row for the user; family/JTI scopes delete the rows whose `refresh_family_id`/`session_jti` match (narrow predicate — no widening).
- **`sessions` table population (web-session-revoke Tier 1)**: authserver's `issueTokensWithFactors` now INSERTs one row per web login (id = the access token's jti); before this the table was only ever written by tests. `GET /user/sessions` (`internal/user/sessions.go` `SessionsHandler.List`) surfaces these alongside OAuth/IMAP families. `sessions_auth_method_check` (V001 baseline + V066 + V094) must stay a superset of every value authserver's `authMethodFromFactors` can emit.
- **Break-glass startup load (CA-0a Task 9)**: at startup (after `policyEngine.CheckFailModePosture()`), both mailserver and authserver call `policyStore.LoadBreakGlass(ctx)` and `policyEngine.SetBreakGlass(bg)` so the engine honours the break-glass set immediately on boot.
- **IMAP/SMTP post-auth gate (CA-F F1)**: after a successful LOGIN/AUTHENTICATE (IMAP) or AUTH PLAIN (SMTP submission), `threat.ThreatInterceptor.EvaluatePostAuth(ctx, &meta)` runs a user-scoped CA evaluation with resolved UserID/GroupIDs. A `threat.ActionReject` result disconnects the session. Wired at the IMAP LOGIN+AUTHENTICATE completion points and the SMTP PLAIN/LOGIN completion points.
- **`scripts/check-migration-allocation.sh`**: CI guard (wired into `scripts/test.sh`) — confirms V025 is the true next-free migration and BZ079 is unused before CA-F allocation. Self-tested by `check-migration-allocation-selftest.sh`.
- **CA-0b sign-in log (`V027__ca_signin_log.sql`, CA-F §6 structured-decision-log)**: the `ca_signin_log` table is append-only telemetry (BZ083 on UPDATE or unauthorized DELETE — see [`docs/reducer-error-codes.md#BZ083`](../docs/reducer-error-codes.md#BZ083)). Each row records: `user_id`, `source_ip`, `protocol`, `client_type`, `device_fp`, `country`, `matched_policy_id`, `decision`, `report_only`, `evaluated` (jsonb — ordered per-policy outcome trace: `applied`/`would_block`/`would_step_up`/`would_notify`/`skipped`/`excluded`), `correlation_id` (opaque `CA-<hex>` reference minted on enforcing or report-only evaluations), `occurred_at`. No hash-chain; retention pruned by the `prune-ca-signin-log` cron (see below). **CA-F §6 satisfied**: `ca_signin_log` records all resolved attributes (trust_tier, ip_band/score, geo_tier, auth_method/acr via `evaluated` jsonb + `protocol`/`client_type`), matched `policy_id`, decision, principal, source_ip, ts, report_only flag, and correlation_id — the structured decision log the CA-F §6/CONDITIONAL_ACCESS_BREAK_GLASS deferred TODO required.
- **`ca_signin_log_append(p_row jsonb)→VOID`** reducer (`reducers/ca_signin_log_append.sql`): the single write seam for telemetry rows; called by `shared/threat/recorder.go` (`pgxSignInRecorder`). Best-effort — a write failure is logged and never blocks the sign-in.
- **`ca_signin_log_prune(p_retain_days int)→VOID`** reducer (`reducers/ca_signin_log_prune.sql`): deletes rows older than `p_retain_days` days. Must run on the `DB_WORKER_DSN` (`setjoin_worker`, BYPASSRLS) pool — `setjoin_app` cannot DELETE from `ca_signin_log` (BZ083). Wired as the `prune-ca-signin-log` cron task (`internal/cron/tasks.go`, daily at 03:45, retention from `system_config.ca_signin_log_retain_days`, default 30 days).
- **`GET /admin/conditional-access/signin-log`** endpoint (`ConditionalAccessHandler.SignInLog`): returns recent `ca_signin_log` rows filtered by `user_id` OR `correlation_id` query param (one required). Gated: `access.policy_read`. Direct SELECT on `ca_signin_log` — no reducer (read-only telemetry query). Limit 200 rows; ordered by `occurred_at DESC`. **⚠ IMAP/SMTP caveat (CA-F F1 pending)**: `ca_signin_log` records evaluations at the **web-login seam only** (HTTP auth chain + IMAP/SMTP post-auth gate via `threat.ThreatInterceptor`). IMAP and SMTP logins produce rows with `user_id=NULL` until CA-F §F1 (post-auth identity injection) lands — the `EvaluatePostAuth` pass today resolves group memberships but the `ca_signin_log` recorder does not yet receive the resolved `UserID` from that path. A `user_id`-filtered trace returns empty for IMAP/SMTP protocol logins until CA-F §F1 ships. Verify report-only policies over web login; IMAP/SMTP trace requires the `correlation_id` lookup path.
- **Named locations (CA-1 D1)** (`admin/admin_named_locations.go`, `NamedLocationsHandler`): CRUD for `named_locations` rows (IP ranges + country codes). Routes: `GET /admin/conditional-access/named-locations` (list; `?include_deleted=1` for tombstoned), `POST` (create), `PUT /{id}` (update), `DELETE /{id}` (soft-delete via `ca_named_location_set(p_deleted=true)`), `POST /{id}/restore` (clear `deleted_at` + audit log + notify). Reducers: `ca_named_location_set`. Gated: read (`access.policy_read`) / write (`access.policy_write`).
- **Auth strengths (CA-1 D1)** (`admin/admin_auth_strengths.go`, `AuthStrengthsHandler`): CRUD for `auth_strengths` rows (authenticator-combination requirements). Routes: `GET /admin/conditional-access/auth-strengths` (list built-in + custom), `POST` (create custom), `PUT /{id}` (update custom), `DELETE /{id}` (custom only; built-in → 400 via reducer EXCEPTION). Reducers: `ca_auth_strength_set`. Gated: read / write. Built-in delete guard: reducer raises plain EXCEPTION (`cannot delete built-in auth strength`) → `caAuthStrengthErrorStatus` maps to 400.
- **What-If simulator (CA-1 D6)** (`admin/admin_ca_simulate.go`, `CASimulateHandler`): `POST /admin/conditional-access/simulate`. Accepts a hypothetical `PolicyEvalContext` (user_id, ip, client_type, country, device_fp, auth_method, protocol, user_agent; `from_signin:<id>` seeds from a `ca_signin_log` row). Loads a **fresh uncached** policy/location/strength snapshot, calls `engine.SimulateWithPolicies` (added to `shared/threat/policy.go`), and returns `{matched_policy, decision, grants[], evaluated[{policy_id,name,priority,scope,outcome,first_failed}]}`. `first_failed` names the failing condition key (`"client_type"`, `"country_in"`, etc.) or `"scope:<type>"` for a scope miss. NO-MATCH → `matched_policy:null, decision:"applied"` (calm path). Read-only — no enforcement, no `ca_signin_log` append. Gated: `access.policy_read`. Engine extension: `SimulateEntry`, `SimulateResult`, `PolicyEngine.SimulateWithPolicies` added to `shared/threat/policy.go` (calls `matchAllVerbose` for first_failed annotation).
- **Doctor health check (CA-1 G1)** (`admin/admin_ca_doctor.go`, `CADoctorHandler`): `GET /admin/conditional-access/doctor`. Aggregates 4 read-only checks into a health score + per-gap next-actions: `feature_on` (feature_toggles), `break_glass_configured` (system_config), `has_report_only_policy` (conditional_access_policies), `no_coverage_gaps` (ca_coverage_report()). Also surfaces policy hygiene (`stale_report_only` = report_only policies older than 30 days) and `time_to_first_policy_sec` (interval from first `ca_policy_upsert` to first `ca_policy_promote` in admin_audit_log). Returns `{score, total, checks:[{name, passed, next_action}], hygiene:{stale_report_only:[...]}, time_to_first_policy_sec}`. Passed checks omit `next_action`. Read-only — no audit / no notify. Gated: `requireCAPolicyRead`. Exit non-zero via `caDoctorCmd` when score < total.

**Device lockdown (CA-2 — 终端安全)** — `feature.device_lockdown` (DEFAULT OFF via the toggle registry; fail-closed)
- **`DeviceLockdownGate`** (`internal/middleware/device_trust_gate.go`) — strict HTTP gate: blocks unenrolled/unbound devices at 403 BZ095 when lockdown is ON. Build-gate (Decision-9): refuses to enforce unless `ca_break_glass_user_ids` is non-empty in `system_config`. Layered AFTER `DeviceTrustGate` on the authenticated chain in `main.go`. See `mailserver/internal/AGENTS.md` middleware entry.
- **IMAP/SMTP enforcement**: `ConnectionMeta.DeviceBound=false` / `DeviceID=0` set for IMAP and SMTP connections (legacy protocols cannot carry X-Device-* headers); `EvaluatePostAuth` blocks them when a `client_type:legacy` policy is enforcing. `user_imap_settings.imap_enabled` (V033) is a per-user IMAP kill switch (default `true`).
- **Admin device endpoints** (`admin/admin_device_lockdown.go`): `GET /admin/devices/queue` (approval queue), `GET /admin/devices?user_id=` (by-user list), `POST /admin/devices/{id}/enroll|approve|revoke` (lifecycle via `device_enroll_transition` reducer; BZ095 → 409). `mam.read` / `mam.write`.
- **Webmail device-approval console** (`src/routes/admin/device-lockdown/+page.svelte`): DeviceEnrollBadge state map, two-tab queue/by-user layout, revoke-confirm dialog. End-user lockout screen shown when the bridge cannot produce a device proof under lockdown (DeviceNotApprovedBanner / lockout route).
- **`effective_capabilities` block**: `device_lockdown` boolean emitted in the `features` block of the JMAP session capabilities (default `false`); the SPA reads it to decide whether to show the lockout screen / request deviceProof from the `window.setjoinNative` bridge.
- **Schema**: V033 (`devices` enrollment columns, `device_enroll_events`, `user_imap_settings.imap_enabled`, toggle seed, `device-lockdown` ca_template). V034 (`ca_validate_policy_document` updated for `device_bound` / `require_compliant_device`). Reducer: `device_enroll_transition` (BZ095). Tests: `device_lockdown_schema.pg`, `device_enroll_transition.pg`, `ca_template_instantiate.pg` (17/17).

**Mobile Device Management (MDM / MAM)**
- Device check-in, policy engine, compliance evaluation, remote wipe
- `internal/mdm/`: `engine.go`, `mam_policy.go`, `conditional_access.go`, `device_identity.go`, `policy_push.go`
- Admin UI at `/admin/mam`. Admin mutations emit a `device_policy` `pg_notify` (`mdm.NotifyPolicyChange`); the gateway LISTENs and logs it for observability, but does **not** yet push it to WebSocket clients — the JMAP WS path is mailbox-keyed (`tag:{mailbox_id}` → StateChange) and `device_policy` is a global/per-device broadcast with no StateChange mapping or deviceID→connection routing. Clients pick up changes on their next MAM check-in (`internal/mdm/checkin.go`). Real-time WS push is unwired (would need new push plumbing). See the NOTE on `mdm.PolicyChangeNotification`.
- Schema: `V029__mdm_schema.sql`, `V060__mam_policy_engine.sql`

**ACME / TLS certificate management**
- Let's Encrypt autocert via TLS-ALPN-01, HTTP-01, or DNS-01 (lego multi-provider)
- Stable TLSA SPKI hash via key reuse or 2×TLSA rolling rollout
- Admin import of static certs; TLS status/config at `/admin/tls/`
- `internal/acme/`, `internal/tlsutil/`

**GeoIP blocking**
- DB-IP Lite auto-downloaded at startup; `internal/geoip/`
- Country block list via `GEO_BLOCK_COUNTRIES` env or conditional access policy

**Auth log**
- Full auth event log at `/admin/auth-log`; `admin/admin_auth_log.go`

### 4.4 Compliance features

**Journaling (BCC archive)**
- Policy-based journaling: match by direction (inbound/outbound/all), domain, user
- `journal_if_policy_matches` reducer + `drain_journal_queue` cron
- `sql/reducers/journal.sql`

**Retention management**
- Per-domain and global retention policies; litigation hold exemption
- `tag_retention` at delivery; `enforce_retention` cron hard-deletes expired messages
- Admin CRUD at `/admin/retention/policies`; `admin/admin_retention.go`
- MRM templates for named policy sets; `admin/admin_templates.go`

**eDiscovery**
- KQL (Keyword Query Language) parser: `internal/kql/`
- `POST /admin/ediscovery/search` — search across mailboxes; export selected; legal hold
- Case management: `/admin/ediscovery/cases` CRUD
- `admin/admin_ediscovery.go`, `admin/admin_ediscovery_cases.go`

**Content Search & Purge**
- Admin hard-delete across mailboxes: `POST /admin/content-search/delete`
- `content_purge_messages` reducer logs single audit entry; skips litigation-held messages
- `admin/admin_content_search.go`, `sql/reducers/content_purge.sql`

**Audit log**
- Append-only `admin_audit_log` table (trigger blocks UPDATE/DELETE)
- CSV export; cryptographic chain verification (`GET /admin/audit/verify`)
- `admin/admin_audit.go`; schema: `V050__admin_audit_log.sql`
- Audit policy singleton (`audit_policy` table, `V038__audit_policy.sql`): `GET/PUT /admin/audit/policy` — level (`lean`/`full`) + reason-required areas; PUT gated `audit.export`, always requires non-empty reason, self-audits with before/after core entry. Handler: `admin/audit_policy.go`.

**WORM immutability** — see Security features above.

**Xinchuang (国产) compliance**
- `internal/xinchuang/db/` — PostgreSQL adapter, error map, NOTIFY bridge
- Supports domestic Chinese platform requirements

### 4.5 Admin capabilities

**Users + mailboxes**
- Full CRUD: `/admin/users`, `/admin/mailboxes`; CSV import
- Alias management; quota per user; password reset
- Folder management per mailbox (create, update, delete)
- Import/export per mailbox (`.eml` / ICS / VCF)
- `admin/admin_users.go`, `admin/admin_mailboxes.go`, `admin/admin_import_export.go`

**Domains**
- Domain CRUD at `/admin/domains`; per-domain settings (greylisting, DLP, retention)
- `admin/admin_domains.go`

**Departments**
- Hierarchical department tree; user assignment; org chart backing store
- `/admin/departments`; `admin/admin_departments.go`

**Rules engine**
- Admin transport rules + per-user rules; OR grouping; stop-processing flag
- Rule templates with visibility control; test endpoint
- `/admin/rules`, `/admin/rule-templates`; `user/rules.go`
- End-user own-rule CRUD at `/settings/rules*` (`user/user_rules.go`, non-transport, own-mailbox-scoped)
- **Apply rule retroactively (QoL #5)**: `POST /settings/rules/{id}/apply {window: 90d|1y|all}` → 202 + action id; `GET /settings/rules/apply/{actionId}` polls progress. Async via a `rules_retro` scheduled_action (`rules_apply_retroactive` enqueuer → `scheduled_action_rules_retro` handler, dispatched by the 1-min `dispatch-scheduled-actions` cron). The handler batches the mailbox's messages in the window through `apply_rules(p_organize_only=>TRUE, p_rule_id)` — **organize-only suppresses send-time actions (forward_to/redirect/bcc/append_footer/add_header) so no historical mail is re-sent** — caps at 5000 with a `truncated` flag, R1-scoped throughout. `apply_rules`/`apply_action` gained `p_organize_only` + (apply_rules) `p_rule_id` params, defaulted so the delivery/send call sites are unchanged.

**DNS wizard**
- Generate and verify SPF/DKIM/DMARC/MX/TLSA DNS records
- `GET /admin/dns/records`, `GET /admin/dns/verify`; `admin/admin_dns.go`

**DMARC dashboard**
- Live feed + failure details + trend; `admin/admin_dmarc.go`

**Spam classifier dashboard**
- Per-user Bayesian model management; reset/disable/enable
- `GET /admin/spam`; `admin/admin_spam.go`

**Outbound queue dashboard**
- List, force-retry, bounce; `/admin/queue`; `admin/admin_queue.go`

**Quarantine**
- Admin: list, preview, release, reject; `/admin/quarantine`. **Preview returns RAW stored `body_html`** (no server-side sanitize/mutation — forensic fidelity). The webmail client sanitizes (DOMPurify) + sandboxes + CSP-locks the render; the prior false-safety string-replace blocklist in `admin_quarantine.go` was deleted (2026-06-19; see CONTEXT.md "Layered containment for untrusted HTML").
- User self-service: list count, release, reject; `/quarantine`; `user/quarantine.go`
- User spam/phishing report: `POST /report`; `user/report.go`

**SMTP pipeline config**

**Anti-phishing config**
- Domain-level protection; `GET/PUT /admin/anti-phish`; `admin/admin_antiphish.go`

**Message trace**
- Per-message delivery trace events (SMTP inbound, rules, delivery, errors)
- `GET /admin/trace`, export CSV; `admin/admin_trace.go`

**Alerts**
- Health-check-driven alerts; acknowledge, unsuppress, configure thresholds
- `/admin/alerts`; `admin/admin_alerts.go`

**Reports**
- Summary reports (message volume, spam, quota); `admin/admin_reports.go`

**Live monitor**
- Real-time protocol connection stats; `GET /admin/monitor/live`; `admin/admin_monitor.go`

**Branding**
- Logo upload, color, org name; stored in S3 blob store
- `GET/POST /admin/branding`; `admin/admin_branding.go`

**AD sync**
- LDAPS sync of Active Directory identities; paged search; `uSNChanged` delta cursor
- Config, test, sync-now, log, health, conflict resolution, field policy
- `admin/admin_ad.go`; `internal/ad/`
- Normalized sources honor the catalog's exact host/port, `ldaps|starttls|none`
  transport, base DN, user filter, and `objectGUID|msDS-ConsistencyGuid`
  immutable anchor. The legacy singleton/domain-discovery constructor remains
  only for the compatibility path.

**LDAP sync**
- Generic LDAP identity sync; `internal/ldapsync/`
- `admin/admin_ldap.go`; same admin API shape as AD sync
- Normalized sources honor the exact endpoint/TLS mode, base DN, user filter,
  and operator-approved immutable subject; no DN/email fallback is permitted.

**Auth methods**
- List and update per-method config (Basic, Kerberos, etc.)
- `GET/PUT /admin/auth/methods`; `admin/admin_auth.go`

**Identity + RBAC**
- SAML/OIDC group-to-role mappings; `admin/admin_identity.go`
- Role CRUD + member assignment; `admin/admin_roles.go`. Mutating endpoints enforce **P2 hardening** (spec `2026-06-21-rbac-role-editor-design.md` §9): **grant-only-what-you-hold** (CreateRole/UpdateRole reject any permission the acting admin does not hold via `claims.HasPermission`; AssignMember fetches the role's permissions and rejects if the actor lacks any → 403) and **mutation-scope-confinement** (only when `middleware.DomainScopeFromContext > 0`: a scoped admin may create/edit/delete only roles whose `domain_scope` equals their scope — out-of-scope roles are 404, never leaked — and may assign only in-scope target users to roles whose effective `COALESCE(domain_override, domain_scope)` equals their scope). UpdateRole, DeleteRole, and AssignMember acquire the V172 `admin_authority_fence` immediately after opening their transaction and before any role/principal/scope `FOR UPDATE`, preserving advisory→row order with assignment/group triggers. The legacy `IsAdmin`/super-admin bridge holds all perms and is unscoped, so both authorization rules are inert for it.

**Email Address Policies** (`internal/admin/admin_email_address_policy.go`, `internal/eapjobs/worker.go`)
- Conditional policy engine: condition→template→priority; CJK pinyin via `cjk_to_ascii`
- REST CRUD + preview + match-count + bulk-apply enqueue + reorder: `GET/POST /admin/email-address-policies`, `PUT/DELETE /admin/email-address-policies/{id}`, `/reorder`, `/{id}/preview`, `/match-count`, `/apply`, `/apply/{jobId}`
- Async apply worker (`eapjobs.NewWorker`): drains `eap_apply_jobs` (status=`queued`) by calling `email_address_policy_apply_bulk`; started as a goroutine in `cmd/mailserverd/main.go`; uses the `DB_WORKER_DSN` (worker pool)
- Gated by `feature.email_address_policy` toggle (DEFAULT OFF); per-recipient opt-out via `users.address_policy_enabled`

**Feature toggles**
- Live enable/disable of feature flags stored in `feature_toggles` DB table
- `GET /admin/features`, `PUT /admin/features/{key}`; changes propagated via `config_changed` NOTIFY. Each list row additively projects the shared operator semantics (`changeMode`, `disableBehavior`, non-null `dependencies`, `confirmationRequired`) without changing the behavior registry digest or generated SQL. Unknown/unannotated keys project no warning semantics. Webmail and mailctl consume this server-owned metadata rather than maintaining key-name heuristics.
- **Exception — `dengbao.sod_mode` (等保三级 SoD):** the generic `PUT /admin/features/{key}` **refuses** this key (4xx). It is flipped only via the dedicated gated route `PUT /admin/dengbao/sod-mode` (`admin.SodModeHandler`, gated on `security.write` not a role), which runs `admin_sod_precheck()` + the toggle UPDATE in **one transaction** — any precheck violation rolls back and returns 409 (toggle stays OFF); a clean precheck commits + writes an `admin_audit_log` row. Turning OFF is unconditional + audited. (Historical note: the legacy `is_admin`→`AllPermissions` bridge and the SSO `users.admin_role` write path the SoD gate once tightened are both GONE — the RBAC cut-over deleted the bridge and `V017` dropped `users.admin_role`; authorization is now pure permission-set membership, and SSO group→role writes target governed `admin_role_assignments`.) Toggle key constant: `toggle.FeatureDengbaoSodMode` / `admin.SodModeToggleKey` (DEFAULT OFF).

**Config management**
- Key/value `system_config` table; get/set/export/import
- SIGHUP or `POST /admin/reload` for hot reload

**Storage (SeaweedFS)**
- Status, DR scan (integrity check), reconcile, blob-level storage migration
- `/admin/storage/`; `admin/admin_storage.go`, `admin/admin_storage_migrate.go`

**Backup + disaster recovery** (the ARCH-007 collapse had dropped the `backup_runs` table, leaving this dormant; rebuilt 2026-06-21)
- **Blob backup to S3/OSS/B2.** A `backup_runs` row — admin `POST /admin/system/backup` or a scheduled insert — fires `trg_backup_runs_notify` → the worker CAS-claims it (single-flight; a startup drain reprocesses stranded `pending` rows), snapshots live blobs, idempotently copies them (HeadObject **size**-skip + post-write size check), emits the manifest set (`manifests/incr-<ts>.json`, `config-<ts>.json`, the `backup-manifest-<ts>.json` index + the `backup-manifest.json` latest pointer written LAST as the commit point), mirrors to the optional cross-region replica (async, best-effort), then applies **real GFS tiered retention** (the `7d4w12m` counts are tier depths — retain the newest run per the most-recent `daily` distinct days, `weekly` distinct ISO-weeks, `monthly` distinct months; prune only runs in no retained bucket, so old monthly snapshots survive — prunes index objects, never blobs; per pruned run the secondary incr/config objects delete FIRST and the self-contained `backup-manifest-<ts>.json` index LAST, and the run's remaining deletes abort at the first failure: the `backup_runs` row is removed only after every object delete of that run succeeded (D-MAILSERVER-INTERNAL-BACKUP-F-003), so a failed pass keeps row + surviving objects for the next-pass retry). Restore treats that embedded manifest as integrity evidence only: it automatically applies reducer-classified safe configuration and quarantines every operator-approved/protected/unknown row; no public boolean can promote an embedded-only backup to a trusted source.
- **OSS driver transport posture** (storage-s3-plaintext-downgrade SHIP): empty `Endpoint` with explicit `Secure=false` is rejected before client construction (the region-derived default endpoint is always TLS); nil/true keep TLS — same contract as the backup-S3 constructor, enforced in direct construction and `NewDriver`. Loopback-HTTP compatibility and both scheme-conflict rejections unchanged. Migration `setStatus` detached writes are timeout-bounded (10s) and never silently ignored (errors log migration ID + intended status for reconciliation).
- **Restore.** `mailctl restore` drives the gateway setup-mode `POST /setup/{preflight,restore}` for config + blob restore (`internal/restore`, SHA-256-verified, hash-validated, single-flight). The full DB dump/restore (`pg_dump`/`pg_restore`) is operator-run via `mailctl backup-db`/`restore` with operator creds — the gateway's `setjoin_app` role is RLS-constrained, so it cannot dump every row. A full restore does blob-restore-through-the-gateway FIRST (while the system is empty, past the no-users guard) then `pg_restore`.
- **Encrypted-at-rest mail = two non-blob backup dependencies (SP1).** S/MIME recipient-encrypted mail (SP1) stores ONLY ciphertext in the blob and NULLs the body columns. Recovering it needs two secrets that live **outside** the blob store the Engine snapshots: (1) `user_smime_certs.private_key_enc` — per-user keys encrypted via `pgp_sym_encrypt` (`admin/admin_smime.go`), captured ONLY by the `pg_dump` (NOT the blob snapshot); and (2) `DB_ENCRYPTION_KEY` (= the `app.encryption_key` GUC set per-connection in `internal/db/pool.go`), captured by NO backup artifact at all — it must be stored separately in the operator secret store. Lose the key ⇒ every `private_key_enc` is undecryptable ⇒ every encrypted-at-rest body is permanently unrecoverable. The DR runbook MUST restore `DB_ENCRYPTION_KEY` before starting `mailserverd`. Full detail + the planned P5 post-restore zero-decryptable-rows assertion: `retired-docs:superpowers/plans/archive/2026-06-21-backup-restore-dr.md` §"S/MIME keystore + encryption key — permanent-loss risk".
- Design: `docs/design/archive/storage-ha-backup-restore.md`, `docs/design/mail/archive/mailctl-restore-lock-replication.md`. Plan: `retired-docs:superpowers/plans/archive/2026-06-21-backup-restore-dr.md`.
- `internal/backup/engine.go`, `internal/restore/engine.go`
- Admin: `POST /admin/system/backup`, list, download, delete
- WORM Object Lock on backup bucket: governance or compliance mode; configurable retention days

**HA Deploy wizard (Phase 37)**
- SeaweedFS HA deployment planner; scale-up/scale-down; systemd unit generation
- `GET/POST/DELETE /admin/deploy/`; `admin/admin_deploy.go`, `internal/deploy/`

**System + upgrade**
- The legacy `POST /admin/system/upgrade/{check,apply,rollback}` compatibility routes fail closed with typed RFC 7807 `410 Gone` before parsing input or touching the filesystem/database. `GET /admin/system/upgrade/status` remains read-only. No web or CLI path accepts a caller binary/path mutation.
- U0/V178 provides signed Community/Enterprise release and intent authority. U1 adds the root-owned no-listener observer, isolated updater credential, journal, and recovery guide. U2 adds immutable staging/adoption, fixed migration/systemd/rollback adapters, and `/usr/libexec/setjoin-recovery`. U3/V179 binds the current database timeline, HMACed application recovery set, exact intent recovery UUID/digest, and separate isolated restore proof; `shared/recoveryset` is the portable verifier. U4 exposes only bounded reducer-authoritative `/admin/system/upgrades*` routes for console/preview/challenge/intent/cancel/diagnostics/recovery evidence. V183+ release manifests additionally bind feature-registry digest/mode/rollback compatibility; updater preflight checks it before host mutation and rechecks post-commit/rollback. The daemon loads its fixed compiled mutation catalog only when root execution config, database execution gate, and verified recovery evidence all agree. Disposable-Ubuntu recovery/switch/rollback and the bilingual browser state matrix pass; production rollout flags remain OFF.
- The old path-based auto-update and separate maintenance-window routes remain authenticated compatibility shells only: every method returns typed RFC 7807 `410 Gone` before parsing or persistence and points operators to `/admin/updates/server`. No caller-controlled path can reach updater execution.
- `/admin/system/upgrade/`, `/admin/system/auto-update`, `/admin/system/maintenance-window`; `admin/admin_upgrade.go`, `admin/admin_autoupdate.go`

**Webhooks**
- Admin-scoped outgoing webhooks + HMAC-SHA256 signing; event catalog; delivery log. Admin creation may explicitly select `self` or `organization`; all pre-V211 rows default to `self` and intended organization subscriptions must be recreated explicitly.
- `/admin/webhooks`; `admin/admin_webhooks.go`; `internal/webhook/`
- `feature.webhook_publication_outbox` is DEFAULT OFF and gates only new durable enrollment. The unconditional WorkerPool drain converges committed residue. Delivery rows are atomically leased through the worker credential only when the fixed executor has capacity; active/retry policy and total attempts are rechecked at claim, and settlement is lease-owner fenced. Migrated groups include `user.created|updated|deleted`, `migration.completed|failed`, and committed `mail.received|mail.sent`. Mail facts are enrolled by worker-only protocol reducers with database-derived user/mailbox subjects; payload remains exact SMTP-envelope `{from,to}`, one stable event per recipient. Held/denied/system/local-fanout/group-recursion paths do not invent facts; scheduled and approved sends publish only when they actually commit. OFF compatibility dispatches only after commit through `DispatchForMailbox`. HTTP is at-least-once and receivers deduplicate by stable CloudEvent `id`. Operator contract: `docs/guides/WEBHOOK_DELIVERY.md`.

**Air-gap update feed**
- Admin uploads binary bundle; clients download locally (no internet required)
- `POST /admin/updates/airgap/upload`, `GET /updates/appcast`; `internal/updates/`

**Client version control**
- Track device update status; push update to specific devices
- `/admin/updates/`; `admin/admin_updates.go`

**Telemetry**
- Privacy-first device telemetry; no PII stored; admin opt-in via `device_telemetry` toggle
- `POST /telemetry`; `internal/telemetry/`

**Client download page**
- Desktop client distribution with version cache; `GET /downloads`; `internal/downloads/`

### 4.6 Discovery + well-known + the public booking surface

- `GET /.well-known/setjoin` — SetJoin client discovery (crypto profile, MAM, login field)
- `GET /api/discover` — SRV/MX/.well-known auto-discovery for client setup
- `GET /.well-known/jmap` — JMAP session discovery (auth required)
- `GET /.well-known/autoconfig/mail/config-v1.1.xml` — Thunderbird (and compatible clients') autoconfig, unauthenticated (`internal/wellknown/autoconfig.go`). `r.Host` (port stripped, lowercased) must match an `is_local=TRUE` row in `domains`, else plain `http.NotFound` (the consumer is an XML client, not JSON — no RFC7807 problem body). Renders Mozilla's config-v1.1 XML: IMAP prefers implicit TLS (993/SSL) when `IMAPTLSAddr` is configured else STARTTLS (143); SMTP submission prefers implicit TLS (465/SSL) when a TLS submission listener is configured else STARTTLS (587) — today there is no dedicated 465 submission listener in `config.go`, so it always advertises 587/STARTTLS until one is added. This `.well-known` path works zero-DNS on the primary vhost; the `autoconfig.<domain>` subdomain convention some clients also probe is an optional manual DNS/SAN step, not auto-provisioned. MS Autodiscover is out of scope.
- **`/api/public/booking/*` — the FIRST unauthenticated public app surface** (feature #6, `feature.booking_pages`, DEFAULT OFF; `internal/booking.PublicHandler`; mounted in `registerPublicRoutes` outside `requireAuth`, exactly like the routes above): `GET /{slug}` (page meta) · `GET /{slug}/slots` · `POST /{slug}/book` · `POST /confirm` · `POST /cancel`. Toggle-off and an unknown/disabled slug are byte-identical 404s (enumeration parity — no oracle for "does this org even have booking enabled"). Two dedicated `HybridRateLimiter`s (read 60/min, write 5/15min); the global `middleware.SecurityHeaders` CSP still applies (proven for this surface by a dedicated test, not assumed). Full threat model + the recommended reverse-proxy/vhost exposure pattern: `docs/adr/DES-007-public-booking-surface.md`.

### 4.7 First-boot setup

- `GET /` → 302 to `/setup` when no users exist (`needsSetup()` checks `SELECT COUNT(*) FROM users`)
- Public HTTP exposes only read-only `GET /setup/status`. The former public mutation routes are absent from the router and OpenAPI contract. The setup SPA is status/instructions only and never accepts bootstrap or restore secrets.
- `mailctl bootstrap-admin` connects through the local owner database credential. `ensure_default_admin` takes the transaction-scoped bootstrap advisory lock and atomically refuses creation when any user already exists.
- **Local restore control** (`cmd/mailserverd/setup_control.go`, `admin/admin_setup.go`, consuming `internal/restore.Engine`): `mailctl restore` dials the filesystem-permissioned Unix socket (`SETJOIN_CONTROL_SOCKET`, default `/run/setjoin/control.sock`; directory 0750, socket 0600). The socket alone mounts `POST /setup/preflight` and `POST /setup/restore`; the public TCP listener never does. Restore remains synchronous, re-checks the no-users rail, uses the reducer-authoritative single-flight job, and finalizes job state with a bounded request-independent context so a disconnected operator cannot strand the lease. Signed recovery trust, stored source profiles/secret references, and quarantine-on-untrusted-restore remain owned by the active security-boundary plan.
- `admin/admin_setup.go`; local control listener at `cmd/mailserverd/setup_control.go`; read-only setup SPA at `webmail/src/routes/setup/`

### 4.8 Webmail SPA (thin map — detail in `webmail/AGENTS.md`)

The production SPA responder is `cmd/mailserverd/static_responder.go`, shared
directly by production and table tests. At startup it validates the build-bound
representation manifest and refuses a mismatched/tampered artifact. It serves
Brotli, then gzip, then identity with representation-correct strong ETags and
`Vary: Accept-Encoding`; Range stays identity. Hashed `_app/immutable` assets
are one-year immutable, while HTML, the service worker, and mutable manifests
revalidate. Path containment and the pinned API/SPA fallback boundary remain
fail closed. Performance verification enters through
`bash scripts/verify-webmail-performance.sh`; details are owned by the webmail
DOX and `docs/guides/WEBMAIL_PERFORMANCE_VERIFICATION.md`.

| Area | Routes | Key components |
|---|---|---|
| Inbox + mail | `/inbox`, `/quarantine` | `ComposeModal.svelte`, `ShadowDomEmail.svelte`, `EmailAnnotations.svelte`, `UndoToast.svelte`, `SnoozePicker.svelte`, `NewsletterBundle.svelte` |
| Calendar | `/calendar` | `CalendarApp.svelte` (+ `lib/components/calendar/`: `RecurrenceEditor.svelte`, `RoomFinder.svelte`, `ShareCalendarDialog.svelte`); RRULE compose/parse helper `lib/calendar/rrule.ts`. A3 wired: recurrence editor, occurrence-vs-series prompt, open-shared-calendar, share dialog, room finder, send-update, delegate respond, in-editor scheduling assistant |
| Contacts | `/contacts` | `DirectorySidebar.svelte`, `DirectoryMemberList.svelte` |
| Tasks | (integrated) | — |
| Directory | `/directory` | `OrgChart.svelte` |
| Settings | `/settings/**` | Language, TOTP, signatures, notifications, appearance, security score, login history, migration |
| Admin — mail | `/admin/(mail)/**` | users, mailboxes, domains, departments, rules, templates, quarantine, queue, reports, retention, DMARC, DNS, TLS, SMTP pipeline, spam, trace, migration, storage |
| Admin — identity | `/admin/(identity)/**` | auth methods, conditional access, identity / group mappings |
| Admin — system | `/admin/(system)/**` | features, alerts, deploy, system, updates, webhooks, logs, audit, eDiscovery, content-search, MAM, welcome email |
| UI library | `src/lib/components/ui/` | 28 primitives: Avatar, Badge, Button, Card, Checkbox, DateTimePicker, Dialog, EmptyState, IconButton, Input, Menu, Pagination, Progress, Radio, Resizer, Tooltip, + utilities |

---

## 5. Work Guidance

- All rules from root AGENTS.md apply here (lint, DB security, PL/pgSQL conventions).
- When adding a Go package under `internal/`, update `internal/DOX.md` Package index; update hot rails only when ownership or routing changes.
- When adding a reducer, update `sql/reducers/README.md` and the relevant pgTAP tests. Add a forward migration only for schema or seed changes; reducer-body updates are not migrations.
- When adding a gateway route, it belongs in `main.go` with the smallest sufficient middleware wrapper. Keep `main.go` as the single source of truth for gateway mounts — do not scatter registration into package inits. Since c8, registrations are grouped into six registrar methods on `gatewayDeps` (`register{Public,JMAP,AuthProxy,Protocol,User,Admin}Routes`). Drive, Chat, Meet, and SCIM own package-private `registerRoutes(router)` child registrars used by both production construction and package-local evidence emitters. `scripts/check-route-inventory.sh` replays all five owners, records all 32 gateway condition masks, merges outer middleware/visibility onto child operations, and drives the OpenAPI guards. The legacy total gateway golden remains byte-pinned by `cmd/mailserverd/route_inventory_test.go` + `testdata/route_inventory.golden` (`UPDATE_GOLDEN=1` only after deliberate changes; pool identity remains `check-rls-coverage.sh`'s invariant).
- Feature-gated protocols must check `featureToggles.IsEnabled(...)` before binding the port (not just before handling requests).
- Config changes are hot-reloaded via SIGHUP or `POST /admin/reload` — do not read env vars at request time; read from `cfgPtr.Load()`.
- The expected database-schema version is **derived** from the embedded `V<NNN>__*.sql` files in `sql/dbschema/` (`dbschema.ExpectedVersion()` = the highest), shared by the gateway's refuse-to-start guard, the admin `SchemaVersionStatus` endpoint, and `mailctl schema`. Adding a `V<NNN>__*.sql` bumps it automatically — there is **no constant to increment** (the old twin `expectedVersion = 1` literals are gone). Each migration must `INSERT` its own `schema_migrations` row (guarded by `sql/dbschema/dbschema_test.go`).

---

## 6. Verification

```bash
# Build
cd mailserver && go build -o mailserverd ./cmd/mailserverd

# Unit tests
cd mailserver && go test ./...

# Lint (must be clean before commit)
cd mailserver && golangci-lint run ./...

# Reducer tests (requires test DB)
pg_prove -d mailserver_test mailserver/sql/tests/*.pg

# Webmail type-check (must be 0 errors, 0 warnings)
cd mailserver/webmail && npm run check

# Webmail unit tests
cd mailserver/webmail && npm test

# Full suite
bash scripts/test.sh

# E2E protocol tests
bash scripts/e2e.sh          # all
bash scripts/e2e.sh imap
bash scripts/e2e.sh smtp
bash scripts/e2e.sh ldap
```

The IMAP E2E lane starts two loopback-only disposable servers: Alpine Dovecot
for plaintext protocol compatibility and the digest-pinned Apache James demo
for verified STARTTLS. Both consume the same three-message/flag fixture and
must pass connection, full fetch, cursor resume and bad-credential cases. The
test-only loopback dial injection does not relax the production migration SSRF
policy.

---

## 7. Child DOX Index

- `internal/AGENTS.md` — all Go gateway packages under `mailserver/internal/`; per-package purpose, key files, interfaces, and invariants. Own children: `internal/chat/AGENTS.md` (Chat/IM Pillars A1+A2+A3+A3.5+A4a+A4b — core messaging, attachments-on-Drive, QoL wave, mobile push, records lifecycle, eDiscovery oversight) and `internal/meet/AGENTS.md` (Meet Pillars B1+B2 — LiveKit-SFU conferencing, reducer-authorized tokens, guest lobby, host-initiated Egress recording → Drive). `internal/drive/` has no separate child doc; it is documented directly in `internal/AGENTS.md`'s package table.
- `api/AGENTS.md` — the integrator-facing OpenAPI 3.1 contract (hand-authored core slice), its serving, and the route↔spec coverage guard.
- `sql/AGENTS.md` — PL/pgSQL reducers, schema migrations, pgTAP tests, reducer dev loop, error code registry.
- `webmail/AGENTS.md` — SvelteKit SPA: routes, components, stores, design system tokens, Svelte 5 runes conventions.

## Rust operator CLI and backup transfer (#355)

Release archives stage the Rust CLI at `server-rust/mailctl` and the compatible
`mailctl/mailctl` artifact path. The installer consumes the canonical Rust path,
so an old Go binary in a source checkout cannot satisfy its prerequisite; source
builds use `cargo build --release --locked -p setjoin-mailctl`. Installed paths,
unit names and `.prev` rollback remain unchanged. The Go module catalog keeps
mailctl for oracle testing but no longer builds it as a customer artifact.
`package-server-release.sh` now requires nine inputs (Rust setjoin-auth added, #359b; see
`server-rust/bins/updater/DOX.md`): architecture, Go binary directory,
Rust gateway, Rust setjoin-auth, Rust mailctl, Rust asrbotd (the captions bot, #356; staged as
`server-rust/asrbotd` and installed to `bin/asrbotd` by the optional captions leg),
webmail build and output archive. All supplied ELF
machines are checked; the caller remains responsible for source provenance and
runtime floor qualification.

The installer preserves other `GO_WORKERS_OFF` names and adds `backup-engine`.
Configured backup effects now run in the Rust gateway; the Go launcher uses its
existing named worker switch. Signing keys, BACKUP_* configuration and worker /
LISTEN credential separation retain their existing meanings. To roll the worker
back, disable `RUST_BACKUP_ENGINE_ENABLED` and remove only `backup-engine` from
Go's disabled list, then restart both processes. Process-local Go workers remain
running. Detailed Rust contract: `server-rust/crates/backup/DOX.md`.

## Native federation deployment (#347)

`render_gateway_unit` loads only gateway.env and a dedicated federation.env;
it never injects config.env or db-credentials.env into the front door.
`render_federation_env` copies only DB_DSN, DB_DIRECT_DSN, DB_WORKER_DSN,
the four static FEDERATION_* settings and federation worker-switch entries.
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
restarting Go. It snapshots the gateway service and gateway/federation/HTTPS/ACME sockets,
config.env, gateway.env, federation.env and tls.env (including file absence/modes), and
the federation/HTTPS/ACME sockets' active/enabled state below the root-only
`$INSTALL_DIR/federation-deploy.prev`. A render/start/readiness or migration
failure restores that snapshot alongside matching *.prev binaries: stop the
new federation socket before restarting an older gateway that cannot accept its
FD name. No runtime switch back to Go is added. Immutable installations continue
using signed Updates and its whole-release recovery workflow.

For a later manual flat rollback, stop setjoin-gateway, setjoin-federation.socket,
setjoin-https.socket, setjoin-acme.socket and setjoin; disable the three public sockets;
restore matching *.prev binaries
(and webmail.prev when supplied). For each of setjoin-gateway.service,
setjoin-gateway.socket, setjoin-federation.socket, setjoin-https.socket and
setjoin-acme.socket, replace the live file with
its copy under federation-deploy.prev/units, removing it if the snapshot has no
copy. Do the same for config.env, gateway.env, federation.env and tls.env from
federation-deploy.prev/config, preserving modes/ownership with `cp -a`.
Run `systemctl daemon-reload`, re-enable/start the federation socket only if the
snapshot has socket-enabled/socket-active markers; restore HTTPS/ACME using their
`<socket-name>-enabled` / `<socket-name>-active` markers. Then restart the matching
auth, Go and gateway processes. Keep the private snapshot with the binary backups.

Protocol/runtime oracle details:
[agreement](../server-rust/crates/protocols/federation/DOX.md#native-activation-and-delivery-347).
Checks: `deploy/scripts/test-federation-socket.sh`, `test-federation-upgrade.sh`,
`test-upgrade-rollback.sh`, `test-setjoin-lifecycle.sh` and `test-install-front-door.sh`.

## Native HTTPS deployment (#413)

`configure_tls_front` transfers `http-tls,http-h2c,cert-monitor,tls-ticket-keys` when
TLS_CERT or TLS_AUTOCERT_DOMAINS is configured. Go's overseer LISTEN_ADDR becomes
127.0.0.1:0 before restart: it binds even when Go's serving workers are disabled.
The Rust gateway accepts public TLS on `setjoin-https.socket` (FD `https`, port 443
or GATEWAY_HTTPS_LISTEN), without CAP_NET_BIND_SERVICE. The renderer attaches
optional federation/ACME sockets through Wants/After, never Requires on Go services.
`tls.env` is a literal 0640 allowlist of TLS paths/provider credentials; broad
config.env and owner credentials never enter the internet-facing gateway unit.
App/worker/LISTEN credentials and the transferred worker names stay in federation.env.

Managed TLS-ALPN-01 (default) and DNS-01 move `acme-renewal` with the TLS listener.
HTTP-01 also transfers `http-port80` and renders `setjoin-acme.socket` (FD `acme`)
only for HTTP_MODE=redirect (including unset). Go :80 proxy/serve remains owned by
Platform #305. Managed settings survive install config regeneration; explicit
operator environment values take precedence. ACME cache/account-key parents gain
narrow ReadWritePaths in the hardened service. Static certificates remain read-only.

Install and flat upgrade require a real local TLS handshake plus the native
/_gateway/healthz response. The local probe accepts the installation's self-signed
leaf; it does not admit an HTTP-only response as TLS readiness. Lifecycle restart
retains sockets so connections queue; stop/uninstall closes/removes them.
Recovery reinstalls a complete matching release (binaries, units, socket set,
configuration and active/enabled state from federation-deploy.prev, as above).
No runtime switch back to Go is installed (owner decision 2026-11-04).
Checks: `deploy/scripts/test-tls-front-socket.sh`, `test-tls-front-upgrade.sh`,
`test-setjoin-lifecycle.sh`, `test-install-front-door.sh`, `test-install-provision-render.sh`.
The root/systemd rehearsal `python3 scripts/test-tls-front-systemd.py <gateway>` renders the
actual hardened HTTPS unit, proves empty capabilities and queued TLS restart, and occupies
the optional federation port to prove its bind failure leaves HTTPS serving. All resources
use `gofree-tlsfront-*` names and are removed on exit; no database is used.
Transport/session/renewal details: [gateway contract](../server-rust/bins/gateway/DOX.md#https-runtime-413).


## Native updater/recovery installation (#359)

The installer uses `server-rust/setjoin-updater` and the unchanged
`setjoin-updater.service` unit name, adding the `run` subcommand. Early `check-swap`
admission and a final locked installation refuse any active/queued/unreconciled
update. Inactive Go journals are verified and archived as evidence, never converted.
The native installer preserves updater/recovery executables and the unit as `*.prev`;
its compatibility `setjoin-recovery` entrypoint execs native `recover`. Legacy flat
core/webmail rollback remains unchanged. Restore matching executables and units
together only with no update active, retaining the archived journal evidence.
The fixed Go Office-only companion remains owned by #300 and has no core-update
arguments. Full handover, release input and oracle contract:
[updater DOX](../server-rust/bins/updater/DOX.md#installer-handover-and-release-inputs-359).
Checks: updater Cargo process targets, `test-updater-render.sh`, provisioning,
lifecycle and legacy rollback scripts, and `scripts/test-package-server-release.py`.

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
`scripts/test-smtp-systemd.py` (real rendered sockets, enabled Go recordings,
capability-empty service, restart and FTRL startup/live posture), and the existing
TLS/IMAP/federation/lifecycle/rollback scripts. The rehearsal uses its own private
resolv.conf mount and loopback DNS/S3/clamd peers; it changes no installed unit.

## Native IMAP deployment (#420)

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
