# Platform (F08, #299)

`setjoin-platform` depends only on foundation crates (`authz`, `contracts`, `db`, `pg`,
`schema`) and no other family crate. The gateway adapter `bins/gateway/src/platform.rs`
translates HTTP; business authority stays in reducers. The actor and mailbox come from the
sealed auth context; path ids and bodies name targets and never grant authority. Later
Platform slices (webhooks #302, config/reload #414, TLS #413 and the rest) add modules here
and arms to the adapter's action table; they reuse `authority`, `console_denied`, `scope`,
`envelope`, `command` and the Go-JSON helpers in `lib.rs`.

## Slice map (all 121 F08 inventory entries, exactly one slice each)

Guard: `inventory_guard::platform_slice_ownership_is_exhaustive_and_disjoint`.

| Slice | Routes | State |
| --- | --- | --- |
| `system-features` (#299, this crate) | 27: `/admin/system/{version,schema-version,status,health,backup*,config*,welcome-email*,jit-defaults}`, `/admin/health`, `/admin/features*`, `/admin/dengbao/sod-mode`, `/admin/auth/methods*` | groups below |
| `updates-deploy` (#300; security fixes: [updates-security.DOX.md](updates-security.DOX.md)) | 35: `/admin/system/upgrade*`, `/admin/system/upgrades*`, `/admin/system/recovery/*`, auto-update, maintenance window, `/admin/updates/*`, `/updates/*`, `/admin/deploy/*` | ON: all 35 registrations (#300, #455) |
| `jobs-storage` (#301) | 14: `/admin/jobs/*`, `/admin/storage/*` | 14 ON; storage execution (#459) is documented in [storage.DOX.md](storage.DOX.md) |
| `webhooks` (#302) | 6: `/admin/webhooks*` | ON (`src/webhooks.rs`, `webhook_secret.rs`) |
| `terms-remaining` (#303, `bins/gateway/src/platform_terms.rs`) | 29: terms, domains, branding, federation peers, DNS, alerts, apps, monitor, reports, `/setup/status`, `/terms/*` | 26 ON by group (below); 1 forwarded to Go; 2 ON as rust-auth (#363) |
| `configuration` (#414, `bins/gateway/src/platform.rs`) | 1: `POST /admin/reload` | ON; [gateway configuration contract](../../../bins/gateway/DOX.md#gateway-configuration-414) |
| `secevents` (#304) | none: worker-only slice | n/a |
| `acme-control` (#305) | 9: the ACME :80 listener and the unix setup control socket (3 ON, see below); the 6 federation test-harness routes stay OFF | 3 ON |

F08 admin routes mount at `/api` (pinned in Go: `/setup`, `/updates`, `/terms`, `/.well-known`
stay at the root); `inventory.rs` mounts family 8's `/admin/` entries accordingly.

## Slice `system-features` groups

| Group | Routes | State |
| --- | --- | --- |
| `system` (`src/system.rs`) | version, schema-version, status, health, backup POST/list/download/delete (8) | ON |
| `config` (`src/config.rs`) | list, get, put, export, import (5) | ON |
| `features` (`src/features.rs`), `sod-mode` (`src/sod.rs`), `health` (`src/health.rs`) | `/admin/features*` (4), `/admin/dengbao/sod-mode` (2), `/admin/health` (#443) | ON |
| `welcome-email`, `jit-defaults`, `auth-methods` (`src/{welcome,jit,auth_methods}.rs`) | 3 + 2 + 2 (#443) | ON |

### Group `system`

- Gates mirror Go: every read and the two 501 stubs `requireSystemPerm` (any of
  `system.config|system.upgrade|backup.read|mail.offline_policy`), enqueue and delete
  `requireBackupWrite`. A refusal writes Go's durable `console.denied` row and answers the
  bare 403; none of these permissions is org-wide-only, so a domain-scoped admin is served.
- `status` and `health` report the Rust process itself (pid, uptime, alive tokio tasks as
  `goroutines`, resident MiB as `memory_mb`, local-time `started_at`). The oracle checks their
  shape and masks their values; Go's own numbers are never comparable.
- `schema-version` reads `MAX(version)` of `schema_migrations` (0 on SQLSTATE 42P01) and
  compares with the compiled `setjoin_schema::MIGRATIONS`; a body over 2 KiB is sent chunked
  as net/http does.
- Backup enqueue is Go's whole transaction (one `INSERT` whose trigger notifies the worker),
  so it is one receipted statement. The list renders Go's nullable counts and `time.Time`
  strings; download and delete answer Go's bare 501.

### Group `config`

- Reads need `requireSystemPerm`; put and import need `system.config`. Secret rows (the
  `encrypted` column, a `_enc` suffix, `assist.api_key`) answer `[ENCRYPTED]` on every path.
  List and get re-render the stored value as Go does after decoding into `any` (float64
  numbers with Go's exponent thresholds, sorted object keys); export writes the value
  verbatim, compacted.
- Put is Go's whole transaction (one `INSERT .. ON CONFLICT`; the table trigger raises
  `config_changed`): one receipted statement. Only the 18 writable keys are accepted;
  `apps_caps_strict` additionally needs a boolean-like value. A missing `value` binds NULL and
  is Go's 500.
- Import streams like Go's `json.Decoder` over a 4 MiB `MaxBytesReader` and applies items one
  transaction each, so earlier items persist when a later one fails. A disallowed key is a 403
  with Go's `%q` quoting; a description pgx cannot encode (anything but string or null) skips
  the item, probed against Go's pgx. An unknown commit outcome answers 503 (Go has none).
- Go quirk kept: a `value` beyond float64 range inside a stored document decodes to `null`
  (Go ignores the decode error); nested overflow is not mirrored.

## Slice `terms-remaining` groups

| Group | Routes | State |
| --- | --- | --- |
| `terms` (`src/terms.rs`) | `/admin/terms-of-use` list, create, update, delete (4) | ON |
| `domains` (`src/domains.rs`) | `/admin/domains` list, get, create, update, delete (5) | ON |
| `alerts` (`src/alerts.rs`) | `/admin/alerts`, `ack`, `unsuppress`, `config` get/put (5) | ON |
| `monitor` (`src/monitor.rs`) | `/admin/monitor/live`, `/admin/reports/summary` (2) | ON |
| `apps` (`src/apps.rs`) | `/admin/apps`, `operations`, `recover` (3) | ON |
| `federation` (`src/federation.rs`) | `/admin/federation/peers` list, upsert, delete (3) | ON |
| `dns` (`src/dns.rs`) | `/admin/dns/records`, `/admin/dns/verify` (2) | ON |
| `branding` (`src/branding.rs`) | `/admin/branding` get, post (2) | ON |
| rust-auth (#363) | gateway `/terms/pending`, `/terms/accept` (2) | ON (`rust-auth`) |
| forwarded to Go | `GET /setup/status` (1) | OFF (Go) |

Forwarded routes and their owners: gateway `/terms/pending` and `/terms/accept` (Go's
`authProxy`) now forward to rust-auth (#363; `authLimit` and the outer CSRF gate still apply;
DPoP-bound sessions still forward whole until #352; test `bins/auth/tests/terms_gateway.rs`);
`GET /setup/status` answers 200 only while the users table is empty, so the oracle can record just its 404
case and the route stays Go's.
All groups live behind one intercept, `bins/gateway/src/platform_terms.rs`, whose action table
adds a row per route and whose group handlers sit in `platform_terms/<group>.rs`.

### Group `terms`

- Gates mirror `RequirePermAudited`: reads need `access.policy_read`, writes
  `access.policy_write`; a refusal writes the durable `console.denied` row and answers the
  bare 403. The oracle adapter is its own intercept (`PlatformTermsRoute`).
- Create, update and delete are Go's whole transaction (row write plus core audit row), so
  each is one reducer call (`rust_platform_tou_create|update|delete`, pgTAP
  `rust_platform_tou.pg`). A database error (duplicate name/version/lang, an `int4`
  overflowing `version`, a NUL byte) is Go's 500 `request failed`; a missing id is 404
  `terms_of_use not found` with nothing written.
- Bodies decode like `json.Decoder.Decode` (case-folded keys, `null` keeps the zero value,
  only integer versions, first value only, 1 MiB cap). `created_at` renders as Postgres'
  `created_at::text`. The oracle pins the next generated id at 9200 and seeds 9101+.

### Groups added by #443 (all 27 system-features routes are ON)

- Gates mirror Go: `/admin/health` any Mail-console permission, features and welcome reads the
  System console, feature/welcome writes `system.config`, sod-mode `security.write`, jit-defaults
  `roles.manage`, auth-methods list the Auth console and update `identity.write`. Feature writes
  and SoD PUT also carry `RequireReason` (areas `system`, `security`): a missing header writes
  `sensitive_action.reason_missing` and answers the bare 400.
- Features: `registry_data.rs` is the compiled `shared/toggle` registry generated from the newest
  `testdata/registry-v*.json`; `features::tests::registry_matches_newest_snapshot` fails when it
  drifts (it also checks the digest). Operator semantics are a small table in `features.rs`
  (covered by the `flist_*` goldens). `gatewayEffective/Source` follow Go's `Resolve` over the
  database rows plus the four configuration pins (`KERBEROS_ENABLED`, `AD_SYNC_ENABLED`,
  `DNSSEC_ENABLED` default true, `TLS_AUTOCERT_ROLLOUT`), read from the environment only (not
  from Go's YAML file). Writes call the V183 reducers; BZ261/262/263 map to Go's problems.
- Health: verdict cache (5 s), token bucket and one-evaluation lock are process local. The
  ok-to-error `system.health_alert` goes through the optional `health::Alerts` observer that the
  gateway wires to the shared dispatcher (#457; one transition tracker shared with the public
  `/health`, `bins/gateway/tests/health_alerts_recorded.rs`). Probes (`sfu`, `egress`, `asr`) run when the LiveKit environment
  configures them; their error text is Rust's own. A `health_history` row with NULL `details`
  makes Go answer `internal error` (kept).
- SoD and welcome test-send are mirrored by reducers (`mailserver/sql/DOX.md`). Frozen Go's test
  send always answers 500 under RLS; the goldens record that.
- Auth-methods update relies on the table trigger's `config_changed` for chains to reload (Go
  reloads its own chain synchronously).

## Slice `webhooks` (#302)

Go's `admin.WebhooksHandler`. Reads gate on `requireSystemPerm`, create/delete/rotate on
`requireSystemConfig` (a refusal writes `console.denied` and answers the bare 403). List and
deliveries have no ownership filter in Go (any permitted admin sees every subscription and
any subscription's delivery log); delete and rotate are creator-only (`id AND user_id` in the
same WHERE, so another admin's subscription is a 404). Responses use Go's struct order and
`omitempty` rules (`userId`, `responseCode`, `latencyMs`; `errorMessage` only when non-NULL);
`eventTypes` decodes like `json.Unmarshal` into `[]string` (non-string elements become `""`,
anything but an array `null`). Create validates in Go's order and decodes with
case-folded keys; the url is not validated (Go does not).

- **Secrets** (`webhook_secret.rs`): `SecretCodec` seals the generated 32-byte hex secret as an
  EK01 column envelope (`config-secret::seal_column`, master = `JWT_SECRET` raw bytes, key id
  `v1`); an unknown key id or empty master fails closed. The plaintext is returned once.
  `load_subscription_secret` is Go's loader including the lazy re-seal of legacy plaintext rows
  (both cells, one pinned UPDATE). `sign` is the `v1,t=,sig=` HMAC header (secret >= 32 bytes).
- **Rotate** keeps Go's outcomes with one fewer transaction: read the secret cells under the
  actor, open and re-seal the previous value in Rust, then ONE `UPDATE` pinned to id, user and
  the three cells read; a concurrent rotation matches nothing and the loop re-reads (5 tries,
  then 500), so rotations still serialize. A reducer cannot do this (the master key never
  enters SQL), so no new reducer and no bypass follow-up.
- Delivery (dispatcher, executor, `webhook-publications`, `webhook-retry`) lives in the
  gateway: `bins/gateway/DOX.md` "Webhook delivery".
- Oracle: `tests/platform_webhooks.rs` (`platform_webhooks_oracle/`), goldens
  `webhooks-<action>-<case>.json`; every stored envelope is opened and classified
  (`<returned>`, `<seed:old>`, ...) so Go-sealed rows are opened by Rust.
  Go quirks mirrored: a body that is not an object decodes to a 400 `url and eventTypes
  required`; a url with markup renders `\u003c`-escaped.

## Oracle

`tests/platform_oracle/mod.rs` is the shared harness: personas are governed role groups, the
Go oracle runs behind the front door in record mode, goldens live in
`tests/conformance/platform/goldens/`, faults are real triggers (no-audit, no-notify,
double-bump) or planted rows (no-tenant-filter). Catalog entries are regenerated from the
test files by the notes' `plat1/catalog.py` and `plat1b/catalog.py`; group 1b's per-action
requests, seeds and recorded tables live in `tests/platform_oracle/b.rs`. Goldens replay byte
for byte after masking run-specific values, except the reviewed Go map-derived storage
topology ordering in `storage-order-review.json` (#459); that comparator only sorts the
listed arrays and retains the raw Go response.

## Slice `updates-deploy` (#300)

Own adapter `bins/gateway/src/platform_updates.rs` (a separate intercept, so this slice and
`system-features` own disjoint arms), `platform_upgrades.rs` for the upgrade console, and
oracle cases through `tests/platform_oracle/updates.rs` (a table of requests, personas, seeds
and the effect table; `{{timeline}}` and `{{now+Nh}}` body tokens; run-time timestamps,
installation ids and preview digests are scrubbed). Gates: `requireSystemPerm`,
`requireSystemConfig` (`SYSTEM_CONFIG`), `requireSystemUpgrade` (`SYSTEM_UPGRADE`); none is
org-wide-only, so a domain-scoped admin passes the gate and the reducers refuse it. Exception (#539): the jobs-storage scan/reconcile/migrate/cancel routes also need an organization-wide `system.config` grant (see storage.DOX.md).

| Group | Routes | State |
| --- | --- | --- |
| `retired` (`platform_retired`) | auto-update and maintenance-window GET/PUT, upgrade check/apply/rollback: Go's typed 410 (7) | ON |
| `updates` (`src/updates.rs`, `platform_updates`) | upgrade history, `/admin/updates/{summary,devices,push}` (4) | ON |
| `upgrades` (`src/upgrades.rs`, `platform_upgrades`) | console, recovery-context, intent read/diagnostics/cancel/request, preview, challenge issue and complete, recovery-set, restore-proof (11) | ON |
| recovery incidents (7), deploy wizard (3), appcast, airgap upload, `/updates/{slug}/{filename}` (#455) | 13 | ON |

- `retired`: the 410 problem carries Go's type, title, `instance` (the path without `/api`),
  remediation and `Content-Language` from `Accept-Language`.
- `updates`: upgrade history remains org-wide. Device summary/list reads honor a
  domain-scoped caller's reach under the owner-approved #456/#512 security fix. The two
  scoped replay cases retain hash-pinned Go baselines and exact reviewed expectations in
  `tests/conformance/platform/divergences.json`; the shared `common::golden_doc` loader
  validates the approval and baseline digest. Frozen Go exposed every device. Go ignores `rows.Scan` errors and pgx
  stops a result set at the first one, so a NULL column ends a list with a partly filled
  entry; `devices` scans `last_seen` into a string, which pgx refuses for every value, so it
  never lists more than the first row (empty string `last_seen`) and `devices` is `null`
  when empty. Push: the `notification_queue` insert fails (no such table) and only
  `pg_notify('update_available', <count>)` lands, one receipted statement; Go answers 204
  either way. Body cap is 16 MiB here (Go has none).
- `upgrades`: every route calls one `upgrade_*` reducer with the verified actor (never a
  request field) and writes its JSONB verbatim, no trailing newline; SQL NULL is an empty 200
  body. Writes are one receipted statement. Updater codes BZ242-BZ251 classify like
  `reducererr.WriteClassified`; any other fault is the fixed 500. `requireReason` reads
  `audit_policy.reason_required_areas` for `system` and writes the durable
  `sensitive_action.reason_missing` row before its 400. The body decoder mirrors
  `decodeUpgradeJSON` (64 KiB, one object, case-folded strict fields, RFC 3339 times,
  Go `uuid.Parse` forms). `preview` success is recorded with a seeded release; challenge and
  intent success need the preview digest of a live run and are recorded only as the reducer's
  refusals (no signed catalog is seeded). `challenges/complete` ports Go's
  `VerifyFreshAAL2` over the verified token (`acr` aal2, `jti`, `iat` within 5 min, `mfa`
  marker, two known factors, at most 16 distinct `amr`) and the SHA-256 session and factor
  bindings, so it needs no new token plumbing.

## Slice `jobs-storage` (#301)

Gateway adapter `bins/gateway/src/platform_jobs.rs`; crate modules `jobs.rs` and
`storage.rs`. Gates mirror Go: `requireMailPerm` (`MAIL_CONSOLE`, any of five) for the
queue reads and the storage reads, `requireQueueWrite` for the journal retry,
`requireRolesManage` for bulk-role detail and retry. A refusal writes Go's
`console.denied` row and answers the bare 403; handler errors are Go's `WriteProblem`
(instance is the stripped path, `Content-Language` from the request).

- `jobs`: summary and list call the F3 reducers (`get_queue_summary`, `list_queue`) on the
  worker executor (cross-tenant by design). List items are the reducer's jsonb text,
  compacted and HTML-escaped as `json.Marshal` renders a `RawMessage`; `limit` and
  `offset` follow `ParseLimitOffset(50, 200)`. Journal retry is one receipted
  `repend_dead_journal_row` call (0 rows is 404). Bulk-role detail writes `row_to_json`
  bytes verbatim. Bulk-role retry is Go's `UPDATE .. WHERE id AND status='error'` plus the
  `bulk_role_job_retry` audit row; Go commits them separately and ignores an audit failure,
  here both are one statement (one transaction).
- `storage` reads render `map[string]any` (sorted keys, int64 counts); scan `details` is
  decoded and re-marshalled (float64 numbers, non-object element `null`, anything but an
  array `null`); a NULL `started_at` makes migration status 404 (Go cannot scan it).
- Storage status, DR start/reconcile and migration start/cancel are owned by the process
  runtime (#459); lifecycle, transports and oracles: [storage.DOX.md](storage.DOX.md).

## Slice `acme-control` (#305)

Auxiliary listeners the gateway never mounts publicly (`listener` `acme` and `control` in the
inventory, ON as `local-rust`; their oracle is the Go-recorded goldens named in each entry's
`oracle_goldens`, checked by `scripts/check-gofree-oracle-adequacy.py` like the captions bot).

- **ACME :80** (`bins/gateway/src/acme.rs`): the activated descriptor named `acme` answers a
  pending HTTP-01 token with its key authorization (`text/plain`) and redirects everything else
  (`301`, Go's `http.Redirect` body). Needs `GO_WORKERS_OFF=http-port80`. Only `HTTP_MODE=redirect`
  behaviour is ported: Go's proxy/serve modes serve the app on :80 and keep Go's listener.
- **`acme-renewal` worker**: `RUST_WORKERS_ON=acme-renewal` + `GO_WORKERS_OFF=acme-renewal` +
  the :80 descriptor; http-01 only (see [setjoin-acme](../../acme/DOX.md)). Configuration is read
  from the environment names koanf derives (`TLS_AUTOCERT_DOMAINS`, `_EMAIL`, `_CACHE_DIR`,
  `_KEY_FILE`, `TLS_AUTOCERT_CHALLENGE`, `HOSTNAME`); Go's config file is not readable.
- **Setup control socket** (`bins/gateway/src/setup_control.rs`, restore engine in
  `setjoin-backup::restore`): `RUST_WORKERS_ON=setup-control` + `GO_WORKERS_OFF=setup-control`
  (a name this ticket added to Go's `main.go`). Socket 0600 (born 0700), directory 0750, refuses a
  relative path, a non-socket path and an active socket; `X-Setup-Token` compared constant-time,
  empty token answers 503; preflight/restore refuse once any user exists. Rollback: remove both
  names; Go binds the same `SETJOIN_CONTROL_SOCKET` again.
- **Kill switch**: drop the three names from `RUST_WORKERS_ON` and `GO_WORKERS_OFF`
  (`acme-renewal`, `http-port80`, `setup-control`) and the descriptor from the socket unit.

## Terms-remaining groups (#303)

Shared: gates are Go's per-route middleware, resolved live by `authority()` (`MAIL_CONSOLE`,
`DOMAINS_WRITE`, `LOGS_CONSOLE` (`audit.read`, org-wide only: a domain-scoped admin is refused
with the durable `console.denied` row), `SECURITY_WRITE`, `APPS_VIEW`, `APPS_MANAGE`,
`FEDERATION_MANAGE`, `MAIL_PIPELINE`). No new reducer: every write is Go's single statement or
one existing reducer, run as a receipted command with the verified actor.

- `domains`: Go writes through the pool with no audit; a domain-scoped principal is checked in
  the handler and again in the write's WHERE (R3). Names are trimmed and lower-cased, then
  `validate.ValidateDomain`; SQLSTATE 23505 is the only create error with its own answer (409).
  `Get` scans four text columns into `string`, so a NULL there is Go's 500.
- `alerts`: reads are `audit.read`; `config` is one `jsonb_each` upsert standing for Go's pgx
  batch (one implicit transaction); values are re-marshalled like `json.Marshal` of a decoded
  `any`. `?` patterns keep Go's unescaped `_` wildcard.
- `monitor`: live counters run on the worker credential (`messages` is RLS) and ignore errors
  as Go does (zero, `null` lists); `traced_at` does not exist, so threats stay zero.
- `apps`: one reducer call per route; reads need `apps.view|apps.manage`, writes
  `apps.manage` plus the `apps` required-reason policy. Bodies are strict (unknown field,
  trailing value, 64 KiB cap), the raw `request` member is passed to the reducer verbatim.
- `federation`: reads on the worker credential (the table is deny-all RLS), writes are the
  existing `federation_peer_set` and `federation_peer_delete` reducers; the real X.509 parse
  (`x509-parser`, Go's `pem.Decode` first-block rule) and the `FEDERATION_LOCAL_DOMAIN` refusal
  stay in the adapter. The list writes its `federation_peers_list` audit row best effort.
- `dns`: verification asks `dns::Resolver` (hickory; `/etc/resolv.conf` in production, one
  fixed server in tests) and renders Go's `lookup <name> on <server>: <reason>` text.
  Go's DKIM reads query a column that does not exist, so selectors are never listed.
- `branding`: multipart read as `ParseMultipartForm(2 MiB)` (query values come first; a bad
  query escape fails the form), logo to `branding/logo` in object storage, config upserts
  whose errors are ignored: the value must itself be JSON, so a bare name is silently unsaved.

Oracle (the `dns` cases need root for the fake zone server on 127.0.0.77:53): `tests/platform_oracle/<group>.rs` hold the case tables, `terms.rs::run` is the shared
runner (placeholders `{a_domain}`..., run-specific ids/dates/uuids masked, fake zone server
for DNS, fake S3 capture for branding).

## Security fix (#456, owner-approved 2026-11-05)
`updates::summary` and `updates::devices` take `reach` (the caller's user id when it is domain scoped, else 0) and count only devices of users it reaches (`admin_can_reach_perm` with `SYSTEM_CONSOLE`); Go listed every tenant's devices. Mutant `updates-devices-unscoped`; test `secfix6.rs::update_devices_are_confined_to_the_callers_reach`. Upgrade intents are system objects, not tenant data, and stay readable by any `system.upgrade` holder.

## Recovery administration (#455)

`bins/gateway/src/platform_recovery_admin.rs` extends the existing updates-deploy adapter.
The worker credential executes the existing recovery reducers; the verified token supplies
its actor. Storage/continuity readiness comes from the same F16 startup configuration;
`feature.client_recovery_ingest` also gates the handler. Permission middleware runs first.
The incident list preserves Go's limit, cursor and status validation, raw JSONB bytes, and
BZ003's historic send-as problem detail. Its five HTTP oracle cases live in
`tests/platform_recovery_admin.rs` through the existing Platform harness (success, invalid
limit, scoped denial, populated filtering and status mutant). These adapters are native and qualified by the individually selectable
`platform_qualification` HTTP floors. All 35 updates-deploy registrations are ON.

The native read adapter also serves continuity signals and incident artifacts using their
worker-only reducers. The read oracle has ten tests, including the three floor cases and
status mutants for every read, missing incidents, and Go's compact/URN/wrapped UUID aliases
plus nil rejection. Identifier parsing is shared through `contracts::ids::go_uuid`; no
family crate supplies this helper. All updates-deploy requests use native Rust adapters.


Approval and closure are native writes through the same adapter. Go's reason-policy
middleware runs before readiness; the handler then decodes one strict 1 MiB JSON object,
validates the path/reason and calls one existing worker reducer through `upgrades::write`.
The actor comes only from verified auth; a commit with unknown outcome uses the shared
non-success response. Closure recordings include the active upload's abortion, the
incident row, core audit and `mail_recovery_incident_changed`; repeated calls preserve
Go's replay result and unchanged effects. The harness observes extra tables separately
and normalizes user and mailbox identities using distinct currencies. The HTTP oracle checks the committed rows, audit and notifications for each write.

Incident opening uses `mail_recovery_incident_open` with canonical mailbox
scope and evidence, bounded expiry and the existing fresh two-factor AAL2 check. SHA-256
binds the verified user, token id, issued time and canonical incident UUID using Go's
recovery protocol string. Fourteen immutable Go cases cover scope/evidence failures,
strong-auth refusal, approval, UUID canonicalization and replay. The harness verifies the
stored binding and exact expiry against the sent bearer/body before masking dynamic data.
Recovery HTTP cases also cover request and authority edge conditions.

Artifact acceptance uses `mail_recovery_artifact_ingest`: a strict resolution
and exact reason precede one receipted reducer call with the verified actor. Eleven Go
cases include cross-domain refusal, malware/approval eligibility, fork consent and replay.
Snapshots cover quarantine, ledger, messages, tags, tag membership, attachments, content
blobs, mailbox state and JMAP journal, plus audit and both notification channels. The
harness verifies newly generated message/audit references before normalizing them;
preexisting fixture identities derive from BEFORE rows, and tied membership rows sort
canonically. Frozen recordings remain immutable. Quota baseline is the fixture's two
accounted ten-byte messages, matching Go's startup refresh.

Recovery readiness now includes a process-local feature snapshot. Startup subscribes on
`DB_DIRECT_DSN` before loading; each `config_changed` hint and reconnect reloads the
worker's authoritative row (notification payloads never supply values). A failed reload
closes admission; connection loss retains the last snapshot until reconciliation, as Go.
The listener stops on adapter shutdown or last-owner drop and runs alongside Go's local
cache until Go deletion. Recovery HTTP tests include disabled intake,
silent notification loss, invalid cursor/status and a 4 KiB chunked list response (the
shared JMAP response helper already owns Go's 2 KiB framing threshold).

## Airgap updates (#455)

`airgap::Store` owns the local `/var/lib/setjoin/updates` index. Startup reads the trimmed
`OFFLINE_UPDATE_TRUST_ROOTS` path (default `/etc/setjoin/offline-update-roots.json`), using
foundation `release-format` for purpose-separated Ed25519 verification. Missing roots
leave an empty readable store; malformed roots disable the store. Sidecars enter the
servable map only after signed metadata matches every persisted target field. Authenticated
expired sidecars still raise the per-slug rollback floor. Consumption checks expiry again.
The public appcast uses Go struct field order and HTML escaping; HEAD is Go's plain 405.
`tests/platform_airgap.rs` records/replays a real independent ring-signed sidecar and byte
fixture, scoped/public access and invalid method, plus a status mutant and unchanged disk
snapshots. All three airgap routes are ON after their recorded qualification passes.

The native public file adapter resolves only the currently admitted slug/filename and
rechecks signed expiry. It preserves Go's download headers, conditional requests and
single/multipart byte ranges, streaming at most 64 KiB per frame. Gateway transport
helpers supply the existing Go validator/date/range grammar; dropping the body closes
the file. The five-test airgap suite includes nine file recordings (public scoped access,
missing target, range/error, 304, HEAD, expired and tampered sidecars) and both status
mutants. A separate HEAD recording checks the original Content-Length=19; the older
invalid-method fixture retains its immutable normalized length.

The native upload adapter requires live `system.upgrade` (Go permits a scoped holder),
reads at most 100 MiB of multipart data through multer, and preserves query-value
precedence, first file/value selection and Go's validation order. The store stages a
0600 file, syncs it, proves size/hash and the offline signature, then holds its write lock
while checking the per-slug version floor, 20 GiB quota and 10% filesystem reserve
(safe rustix). Atomic rename publishes bytes and a synced 0640 sidecar; replaced filenames
are removed and the newest three targets per platform retained. The in-memory floor
survives pruning; restart rebuilds only from surviving sidecars, mirroring Go's known
persistence defect. Sidecar-publication failure removes the new destination, matching Go.
Seven HTTP tests pass over all three airgap routes, including twelve upload recordings,
per-route status mutants, disk snapshots, signature/hash/rollback/refusal cases and a
fresh frozen-Go verification run. No archive extraction or database mutation is involved.

## Deploy wizard (#455)

`deploy::Wizard` restores `deployment_steps` through the worker credential at process
startup and owns a process-local status snapshot. `system.upgrade` gates the HTTP read;
Go permits scoped holders and ignores its query input. Restored running steps render as
failed; any nonempty persisted output/error is replaced with Go's withheld-detail note.
Restore does not mutate the stored rows or recover node credentials/start time. The
five frozen-Go status cases cover restoration, empty state, scope, ignored invalid query
and permission denial, plus the native status mutant.


The native start/cancel adapter owns an asynchronous run beyond the HTTP response.
Reset cancels and drains for ten seconds; unconfirmed remote termination fences future
runs for the lifetime of the process. Dropping/shutting down the adapter cancels its run.
The status projection never emits inline credentials. The existing one-statement worker
upsert carries the verified actor; Go's `ok` status violates the table CHECK and is
intentionally ignored, so successful progress remains process-local. No schema changes.

`deploy/ssh.rs` uses russh with an exact pinned OpenSSH public key or host certificate.
Certificate algorithms are offered before bare keys, and failover known_hosts carries the
same canonical configured pin. RSA private signing
uses OpenSSL; ssh-key's RSA feature supplies public decoding/verification only. Seven
stages use the frozen command strings and the three verbatim deployment assets in
`deploy/assets/`. The credentials callback re-reads the original operator configuration
layers for each SeaweedFS configuration step without publishing a config reload.
`tests/platform_oracle/deploy.rs` owns three SSH peers, checks the authenticated key,
records commands without executing them, and can hold a command for cancellation/fence
observations. Go recordings include full success, malformed key/nodes, scope and denial,
and cancel during an active command, idle cancel, ignored body and fenced restart.
All three deployment routes are ON. The 46-case `platform_qualification` target names
success, scoped/cross-tenant and invalid-input floors for all thirteen #455 routes, plus
repeated mutators. Replays use no Go upstream and assert the F08 proxy counter is zero.
Each route also has a changed-status mutant; recovery open/close/accept plant real
notification suppression and prove that the immutable effect oracle rejects it.

Deployment JSON consumes Go's first value and preserves existing struct fields when a
repeated `nodes` array omits them or supplies null. The duplicate-array recording checks
both the public node projection and the resulting SSH commands and failed-step row.
SSH output and failed-step/log strings retain raw bytes through structural redaction,
exact-secret replacement and Go's 4096-byte retention limit. Status JSON uses Go's
per-invalid-byte `\ufffd` escapes; the one-statement upsert binds bytes and validates them
with PostgreSQL `convert_from(..., 'UTF8')`, preserving Go's rejection of invalid text.
The RSA peer case authenticates only the public half of the checked-in 2048-bit
`tests/conformance/platform/ssh/client-rsa.pem` test key, generated with OpenSSL. It runs
all seven stages through Go and Rust; production RSA private operations stay in OpenSSL.
Recovery transaction faults use the real PostgreSQL wire: each of open, approve, close
and accept loses COMMIT before transmission and after PostgreSQL commits. HTTP remains
503 with the operation ID; a fresh receipt lookup resolves the outcome without replay.
Committed row/audit/notification effects match the Go success recording exactly; aborted
transactions retain the seed and publish no audit or notifications. Every proxy is joined
or aborted on cleanup.
Late statement failures are injected immediately before each reducer's final success
return, after its writes/audit/notify. All four routes must return500 and leave the seed,
audit, notification streams and durable receipts unchanged. The harness restores and
byte-checks the exact original function definition on cleanup; production SQL is unchanged.
Airgap fixtures accept `GOFREE_AIRGAP_FIXTURE_ROOT` as their temporary parent on shared
hosts. Both Go and Rust use the same real filesystem; every fixture has an owned nonce
path, resource-ledger entry and Drop cleanup. Product paths, quota/free-space checks and
immutable expectations remain the same.
The legacy recovery-set and restore-proof UUIDs are authored fixture inputs and stay
exact in effects, audit and notifications; the generated-UUID mask excludes only those
two fixed values. A changed relationship therefore still fails the recorded oracle.
Recovery-context replay validates the actual HTTP `schemaVersion` against the live
`schema_migrations` maximum before projecting that environment value in comparison views.
The projection applies symmetrically to immutable old recordings and Go verification;
request/recovery-set schema fields stay exact. A real HTTP response mutant changes the
version and must fail the independent DB binding before normalization.

Storage execution additions (#459): [storage contract](storage.DOX.md).
