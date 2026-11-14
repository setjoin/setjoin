# setjoin-gateway — DOX (moved verbatim from server-rust/AGENTS.md, #385)

Parent: [server-rust/AGENTS.md](../../AGENTS.md). Rust front door (#255, [ARCH-027](../../../docs/adr/ARCH-027-rust-front-door-gateway.md)).

Rust front door (#255). Dispatches by `bins/gateway/route-inventory.json`
to local Rust, `setjoin-auth`, Go mailserver or Go authserver. OFF entries
select Go; ON entries select their Rust adapter. The inventory includes
family F01–F22, slice, method/path, listener, upstream, state and Go source
provenance; auxiliary listeners are listed but never publicly mounted.
Reverse-proxies unported requests unchanged
(streamed bodies, WebSocket tunnel, unbuffered SSE); strips client
`Forwarded`/`X-Forwarded-*`/`X-Real-IP` and sets its own by the
`shared/clientip` rules (library default none; the executable starts with Go's
loopback defaults and refreshes `system_config`, as described below). No
business logic: `src/routes.rs` installs local adapters only after parity;
a route that cannot handle a whole request forwards it to Go. Env:
`src/main.rs`. Socket activation: [DOX.md](../../DOX.md#socket-activation).
See [route budgets](../../DOX.md#rate-limits-and-threat).
`src/workers.rs` provides the cron scheduler: families explicitly register
their own task callbacks by frozen Go task name, schedule and timeout; no
cron task transfers merely by being present in the catalog, and the
executable starts only tasks named `RUST_WORKERS_ON=cron:<task>` (see
[cron handover](../../DOX.md#cron-handover-per-task-locks)). Checks every second,
catches up missed cron minutes, and cancels and joins work on lock loss or
shutdown.
`RUST_WORKERS_ON=session-denylist-refresh` starts the Rust refresh/cache
and direct listener in the gateway for the shared protocol-session registry. HTTP runtime
admission (#405) always has a process-local cache; it reuses this explicitly configured
cache or starts its own copy when the flag is unset. Its cross-tenant reads use `DB_WORKER_DSN` (fallback `DB_DSN`), and LISTEN
requires `DB_DIRECT_DSN`. HTTP CAE refuses a cold cache locally and positive revocations
are authoritative even with CAE OFF. Adapter-only tests retain the older cold-cache seam;
production routes also retain their existing per-request DB check.
Its separate protocol registry retains revocations until expiry, as Go does.
Per #260's clarification, keep Go's refresh running until Go is deleted:
each process refreshes its own cache and live protocol-session registry.
The HTTP listener accepts HTTP/1.1 (including upgrades) and HTTP/2 prior knowledge
(h2c, #413) through the same dispatch and client identity seam. HTTP shutdown
stops acceptance and drains active requests for up to 30 s.
Native TLS and the live certificate/ticket consumers are wired in #413;
see [HTTPS runtime](#https-runtime-413) and the [transport contract](../../crates/tls/DOX.md).
`GATEWAY_ENABLED` defaults true; false bypasses Rust
adapters, probes and limiting, forwarding all traffic to Go mailserver.
`--version` prints the Cargo package version without starting the server.
`GATEWAY_AUTH_UPSTREAM` is required while enabled for unported auth shapes.
Qualified `/auth/*` entries reach the Rust identity process; unported and
unknown/invalid method requests keep the same proxy identity/streaming rules.
Exclusive authserver paths outside `/auth/` also dispatch directly;
overlapping public paths (health, discovery, admin reload) keep gateway
ownership. Auth's real `/auth/` registrations override proxy stubs.
`GATEWAY_RUST_AUTH_UPSTREAM` configures the Rust identity process. Qualified
auth routes fail closed with 503 when that upstream is absent. Proxy tests
assert native refresh/version dispatch and no Go-counter contribution;
unported SAML (#341) preserves the separate Go-auth transport check. Native RP
login/callback/link and its mixed namespace are ON (#340); the gateway GET-link
alias retains the auth server's POST-only405. Optional
`GATEWAY_ROUTE_INVENTORY` loads reviewed JSON instead of the bundled file;
the executable rejects ON entries absent or OFF in the bundled inventory,
but accepts turning a bundled ON entry OFF for rollback.
`GET /_gateway/metrics` exports Prometheus
`setjoin_gateway_proxied_to_go_total` and
`setjoin_gateway_proxied_to_go_by_family_total{family="F01"…"F22"}`
(F00 unclassified): count attempted Go forwards, including failed dials
and adapter declines, once at the proxy boundary. Rust replies and
probes/scrapes add nothing. Counters reset on process restart; with the
kill switch OFF the scrape path also forwards to Go.
With `GATEWAY_UPSTREAM` unset, locally served requests work and any Go
mailserver fallback gets 502, enabling Go-free replay.

JMAP (`src/jmap/`, #215/#216/#315): `POST /jmap` serves the qualified Email
commands natively regardless of `feature.rust_mark_read` and
`feature.rust_inbox_list`. Those retired pilot flags never select the command
implementation or a Go fallback. Mark-read and inbox-list retain their qualified
specialized adapters; general update/destroy and query shapes use the JMAP1
adapters. Every command uses `authorize_request` once after global CSRF: security gates,
ES256/JWKS, guest/session checks and mailbox scope still apply. Security reads
are bounded; a stalled admission read gets one precheck bound. Deferred shapes
retain whole-request forwarding before writes; encrypted `Email/get` awaits
the S/MIME decrypt-on-read helper (#328). See the JMAP1 details below and
[family contract](../../crates/domains/jmap/DOX.md).

F05 (#292): every registration is an `/admin` console route, so the inventory matcher mounts the
family at `/api` like F01; the mailboxes slice is served by `src/mailboxes.rs` (contract:
[Mailboxes DOX](../../crates/domains/mailboxes/DOX.md)). Import/export (#425) and all migration
shapes (#446) are native; [Microsoft provider contract](../../crates/domains/mailboxes/MICROSOFT.md)
and [provider oracle](../../tests/conformance/migration/README.md).
F05 worker slice (#295): [worker contract](../../crates/domains/mailboxes/DOX.md#worker-slice-295).
`mail-work` and `mailbox-lifecycle` require named Go-off handover; their webhook events
go through the shared dispatcher (#457).

F07 (#310): the `/admin` consoles of the family (`/admin/mdm/*`, `/admin/devices*`) mount at `/api`; the
`mdm` slice is served by `src/devices.rs` (contract: [Devices DOX](../../crates/domains/devices/DOX.md)).
The MAM slice (#311) also defaults ON through this adapter after its recorded oracle. Offline (#312) uses `src/offline.rs`; all its JSON registrations, including the user `/offline/*` paths, mount at `/api`. All 36 F07 routes default ON after recorded qualification; both global and per-route rollback restore Go and its counters. The MDM observer runs by default with the process, preserving Go's refused subscription and no shared effects.

## Drain workers (#408)

`RUST_WORKERS_ON=notify-intent-drain` and `RUST_WORKERS_ON=push-intent-drain`
(`src/notify_drain.rs`, `src/push_drain.rs`) take Go's two foundation queue
drains. Each refuses to start unless `GO_WORKERS_OFF` lists the same name, uses
only `DB_WORKER_DSN` (fallback `DB_DSN`; the queues are cross-tenant) and drains
until `GO_WORKERS_OFF` is lifted. They are not process-local: leave neither Go
copy on beside the Rust one.

`RUST_WORKERS_ON=security-event-delivery` (#304, `src/secevents.rs`) takes Go's
`secevents.Worker` the same way (refuses without `GO_WORKERS_OFF=security-event-delivery`,
worker credential only: the outbox is FORCE-RLS deny-all). Go builds it with a **nil
sink** (no production sink is admitted), which is fully inert, and so does the
executable: no connection, claim, sweep or retention. The full drain is ported
behind the `Sink` trait (claim, generation-fenced settlements, backoff, 5-attempt
cap, exhausted sweep, `security_event_outbox_prune()` reducer, 200-row batch, 90 s
deadline) and oracle-tested with an injected test sink (`tests/secevents_recorded.rs`,
Go overlay `secevents_tick_test.go.txt`); a later ticket that admits a producer passes
its sink to `SecurityEventDelivery::new`.

`RUST_WORKERS_ON=tls-rpt-report` (#323, `src/tls_rpt.rs`) takes Go's `smtp.TLSRPTWorker`
(refuses without `GO_WORKERS_OFF=tls-rpt-report`; it POSTs reports and deletes the sent
sessions, so two copies would double both). Worker credential; first pass after 10 minutes,
then every 24 h, only while `feature.tls_rpt` is ON (default; read once at start like Go's
launch gate). Per (domain, report URI) pair for yesterday's UTC date: `https://` URIs POST
`json.MarshalIndent` bytes (`application/tlsrpt+json`, SSRF-guarded client, no redirects) and
delete that domain/date's rows on ANY answer; a failed POST, `mailto:`, empty or other schemes
keep the rows. The organisation name is `HOSTNAME` (Go's `cfg.Hostname`; a config-file value
is not readable here). The `tls_rpt_sessions` table exists only in the archived 035 migration,
so on a current schema both Go and Rust find no table and do nothing. Oracle:
`tests/tls_rpt_recorded.rs` (`tick()` seam; Go overlays `tls_rpt_tick_test.go.txt` +
`tls_rpt_source.go.txt` replace the inline client), `tests/tls_rpt_startup.rs`.

`smime-trust-listener` (#328/#526, `src/smime_trust.rs`) observes
`smime_trust_changed` in each process owning a trust cache. Native inbound SMTP
starts it automatically; `RUST_WORKERS_ON=smime-trust-listener` also starts it
without SMTP. Go retains its own process-local subscription until Go is deleted;
no `GO_WORKERS_OFF` transfer is required. Native SMTP and this listener share the
same `setjoin-certificates::trust::TrustCache` (F06 keeps its public re-export).
Needs only `DB_DIRECT_DSN` (LISTEN), reads and writes nothing; unlike Go it also
clears on every (re)connect (divergence record). `smtp_inbound_trust` proves actual
SMTP badges follow that shared invalidation cache. Oracle: `tests/smime_trust_recorded.rs` (Go overlay `smime_trust_tick_test.go.txt` runs
Go's real listener wiring and `smimeRootsForDomain`: seed, observe, change the table, observe
the stale cache, one notification, observe), `tests/smime_trust_startup.rs`.
Owner-approved security fix 2026-11-05 (#465): no cached pool while the LISTEN
connection is down, cache cleared on reconnect (`tests/smime_trust_reconnect.rs`; mutants
`smime-no-reconnect-reload`, `smime-cache-while-deaf` via `scripts/test-smtp-secfix-mutants.py`).

- **notify**: Go's statement verbatim (1 s, batch 500, `FOR UPDATE SKIP LOCKED`,
  full batches repeat inside one tick, one no-op `DELETE` per idle tick, always
  on). With `feature.notify_decouple` ON this is the only NOTIFY emitter, so the
  LISTEN clients under webhooks, SSE and WS depend on it.
- **push**: 3 s tick, three legs plus reaps in Go's order: mail (claim lease,
  `push_should_notify`, payload, devices, dispatch, done/retry/failed), chat
  (coalesce, per-member `chat_push_should_notify`, always done after fan-out),
  guest digest (per-guest transaction spanning the object-store write and the
  `outbound_queue` insert). Payload JSON is built with Go's key order and
  HTML-escaping; the digest `%q` is a `strconv.Quote` port. Device tokens decrypt
  in SQL, so `DB_ENCRYPTION_KEY`/`AUDIT_HMAC_KEY` set the session GUCs
  (`WorkerDatabase::connect_session`). Provider transports and capability-URL
  scrubbing stay in `crates/push`; the executable refuses without an object store.
  `HOSTNAME` (default `localhost`) feeds the digest sender and webmail URL; the
  gateway resolves the same YAML/environment value before worker wiring (#414).
- The guest digest keeps Go's multi-statement transaction in the worker: it spans
  an S3 write, so no reducer can own it (ARCH-028 exception, parity with Go).
- Known gaps: a non-ASCII digest subject longer than one encoded word is not
  split like Go's `mime.QEncoding`; DB error text in `push_intents.last_error`
  differs from pgx's wording.

Oracle: `tests/{notify,push}_drain_recorded.rs` run frozen Go's real `Worker.Run`
for one tick (recording-only overlays in `tests/conformance/drain/`, container
via `drain_oracle::GoTick`) over a seeded DB, then replay the Rust `tick()`
against the goldens: rows, `pg_notify` payloads, every request seen by the
owned Python push peer (reused from `bins/mailctl/tests`: APNs HTTP/2 with
client certificate, decrypted Web Push, RS256 OAuth, FCM/HMS via CONNECT) and
the stored digest MIME. Record: `GOFREE_RECORD_DRAIN=all GOFREE_GO_SOURCE=<sha>`.
`*_startup.rs` cover the refusal, the worker credential (restricted request
DSN) and decoupled events reaching a LISTEN client through Rust.

## Webhook delivery (#302)

`src/webhook.rs`: one `Dispatcher` per process (Go's `webhook.Dispatcher`): fixed executor
(8 tasks, queue 8, 16 admission tokens; started lazily by the first submit or claim), per
subscription circuit breaker (10 failures, 2 min), SSRF-safe client (public addresses only at
dial time, no proxy, no redirects), signing secret opened per delivery. `dispatch*` is the
legacy best-effort fan-out (user-lifecycle routes call `dispatch_for_user` after the commit);
`enqueue_durable`, `deliver_pending_event` and `retry_pending` drive `webhook_delivery_claim`
and `webhook_delivery_complete`. Claims take turns, each bounded at 5 s for connect plus claim and
5 s for its COMMIT; a claim is committed only after its rows are decoded, so a timed-out claim rolls
back instead of leasing rows nothing sends, and a COMMIT whose outcome is unknown is dispatched anyway
(at-least-once). Go has no claim timeout. Workers: `RUST_WORKERS_ON=webhook-retry` (claim at start,
then every 60 s) and `=webhook-publications` (drain at start, then every 5 s, prune every 12 h);
each refuses to start unless `GO_WORKERS_OFF` lists the same name, uses the worker credential
and is not process-local. Callers (#457): mail-work and mailbox-lifecycle (`enqueue_durable`), the
migration runner's terminal events (`dispatch_for_mailbox`/`dispatch_for_user`), IMAP
`auth.login`/`auth.login_failed` (`imap_runtime::AuthEvents`, `dispatch`) and `system.health_alert`
(`health_alerts.rs`, one transition tracker for `/health` and `/admin/health`) all use the
process's one `Dispatcher`; no Rust path drops or forwards a webhook event to Go. Caveat: Go's
handlers that still dispatch (SMTP) drop events once Go's `webhook-retry` is off, because Go's
executor only starts with that worker; flip it only when their callers are Rust or accept the loss.
Producer oracles share `tests/common/webhook_receiver.rs` (fake receiver, masked ids/times) and Go's
real Dispatcher through the `webhook_unguarded_export.go.txt` overlay file (`GoTick::run_with`):
`mail_workers_recorded.rs`, `migration_terminal_recorded.rs`, `imap_auth_webhooks_recorded.rs`,
`health_alerts_recorded.rs`. Oracle: `tests/webhook_workers_recorded.rs` (Go one-tick overlays in
`tests/conformance/drain/webhook_*_tick_test.go.txt`, in-process fake receivers, signatures
verified under the seeded secrets), `tests/webhook_dispatch.rs`, `tests/webhook_workers_startup.rs`.
Record: `GOFREE_RECORD_DRAIN=all GOFREE_GO_SOURCE=<sha>`.

## Meet leftovers (#410)

- **`/rtc`, `/rtc/`** (`src/rtc.rs`, F13, ON): Go's `httputil.ReverseProxy` to the fixed
  `127.0.0.1:7880` SFU signal port, never behind `requireAuth` (LiveKit checks its own
  token). Mirrors prefix strip over the decoded path (re-escaped), `SetXForwarded`, hop-by-hop
  removal, upgrade tunnel (first side to end closes both), Go's transport gzip (`Accept-Encoding:
  gzip` added and the answer decoded when the client sent neither it nor `Range`), empty 502 on
  failure, `ServeMux` 307 for unclean paths, and Go's middleware envelope (security headers,
  `Cache-Control: no-store` except on a hijacked 101, `X-Request-ID`). Declines to Go when LiveKit
  is not configured (Go registers no handler then: SPA fallback) and when the request carries a
  JWT credential the verified-member precheck rejects (Go's guest belt). Kill switch: inventory
  OFF or `GATEWAY_ENABLED=false`. The address is a constructor argument (tests only); production
  never reads it from the environment. `/meet`, `/meet/` catch-alls stay on Go with the generic
  ones (#416).
- **`meet-reconcile`** (`src/meet_worker.rs`): `RUST_WORKERS_ON=meet-reconcile` with
  `GO_WORKERS_OFF=meet-reconcile` (startup refuses otherwise); worker credential, 60 s tick.
  Legs and gates are Go's (`mailserver/internal/meet/worker*.go`): unconditional drains
  (recording reconcile, ingest, staging reaper, semantic sweep and exports, Drive-History,
  lease expiry) then, when `feature.meet` and LiveKit are on, lobby expiry, `ListRooms`,
  `DeleteRoom` retries, breakout presence, lost-webhook GC, captions. The semantic export
  composer is nil in Go, so claimed exports complete failed with Go's reason. The breakout
  absence grace map is process-local. Oracle: `tests/meet_worker_recorded.rs` (frozen Go with
  only this worker on, first tick 60 s after launch, so each recording takes ~75 s).
- **`dmarc-report`** (`src/dmarc_report.rs`, #324): `RUST_WORKERS_ON=dmarc-report` with
  `GO_WORKERS_OFF=dmarc-report` (startup refuses otherwise) and only while
  `feature.dmarc_reporting` is on (read once at start, absent row = on). Worker credential;
  first pass 5 min after start, then 24 h after each finished pass. Go's `sendReports`: per
  `(report_uri, domain)` older than 1 h it queues an inline-raw report email in
  `outbound_queue` and deletes that domain's `dmarc_reports`. Mirrors Go's raw-XML-labelled-gzip
  attachment. Oracle: `tests/dmarc_report_recorded.rs` (Go's unexported `sendReports` via the
  `dmarc_report_tick_test.go.txt` overlay) and `tests/dmarc_report_startup.rs`.

Verification after integration changes: replay `rtc_recorded`, `rtc_dispatch`,
`meet_worker_recorded`, `meet_worker_startup`, then `inventory_guard` serially
with `REQUIRE_DB=1` and `--test-threads=1`. Reload the assigned disposable database
from this worktree before each target; clear `GOFREE_RECORD_GO_BINARY` so replay
cannot overwrite the frozen-Go goldens. `rtc_dispatch` needs loopback port 7880;
replay peers in `rtc_recorded` use ephemeral ports. Preserve both the `/rtc`
exception to `/api` mounting in `inventory.rs` and the other families' worker
registration/shutdown wiring when resolving integration conflicts.

## Drive workers (#409)

`RUST_WORKERS_ON=drive-maintenance` and `RUST_WORKERS_ON=drive-preview`
(`src/drive_workers.rs`) take Go's two Drive loops. Each refuses to start unless
`GO_WORKERS_OFF` lists the same name, uses `DB_WORKER_DSN` (fallback `DB_DSN`;
every step is cross-tenant) and needs the object store (`S3_*`), as Go does. They
have shared effects (row deletes, S3 deletes and puts): never leave both copies on.

- **drive-maintenance** (5 min): per tick, error-isolated, in Go's order:
  `drive_maintenance_sweep()` (its queue enqueue feeds the GC of the same tick),
  zero-ref chunk GC (200 rows; re-referenced rows only dequeue, `retain_until` in
  the future stays queued, the rest delete the row then the object under the
  per-key advisory lock in Go's two transactions), canonical-orphan reaper
  (`drive/` inventory, 200 keys per tick, process-local `start-after` cursor,
  exact key grammar incl. Go's `ParseInt` sign quirk, 24 h age, absence check
  under the lock), `tmp/upload/` reaper (24 h) and WORM retry (`worm_pending`
  chunks in `s%` scopes, `PUT ?retention`, mode default `governance`, then
  `worm_applied_until`). `DriveMaintenance::new(.., retention)`: `false` is Go's
  nil `SetRetention` handle (no retries; chunks stay pending). The executable
  always passes `true`.
- **drive-preview** (15 s): up to 5 `preview_status='pending'` versions per tick:
  assemble content chunks (64 MiB source bound, declared and streamed), run
  `DRIVE_PREVIEW_CMD` (`sh -c`, `{in}`/`{outdir}`, 2 min), first `.pdf`, 64 MiB
  output bound, 4 MiB `drive/<scope>/<sha>` chunks stored as `application/pdf`,
  `drive_preview_attach(.., 'ready')`; any error attaches `'failed'`. Unset
  command: the worker returns at once (inert).
- Tests: `tests/drive_workers_recorded.rs` (frozen Go's real `tick()` through
  overlays in `tests/conformance/drain/`, fake stateful S3 in
  `tests/drive_workers_oracle/fake_s3.rs`, fake preview command; goldens in
  `tests/conformance/drain/goldens/drive-*.json`), `tests/drive_workers_startup.rs`.
  Record: `GOFREE_RECORD_DRAIN=all GOFREE_GO_SOURCE=<sha>`; S3 requests compare as
  a multiset (Go interleaves list pages with deletes; the sets are identical).

## Blob cleanup worker (#411)

`RUST_WORKERS_ON=blob-cleanup` (`src/blob_cleanup.rs`) takes Go's
`blob.Handler.StartCleanup` (5 min, first tick after one interval). It refuses to
start unless `GO_WORKERS_OFF` lists `blob-cleanup`, runs on `DB_WORKER_DSN`
(fallback `DB_DSN`) and needs the object store (`S3_*`). Shared effects (row and
S3 deletes): never run both copies. Per tick, in Go's order, each statement
autocommit:

- **cleanup queue:** `blob_cleanup_queue` rows past `scheduled_at + delay_minutes`
  whose blob has `ref_count = 0`; each does `DELETE FROM blobs WHERE sha256=$1 AND
  ref_count=0` (the queue row cascades) and, only if a row went, an object delete
  keyed by the bare sha. A failed delete lands in a process-local ledger (1024 max,
  arbitrary eviction).
- **orphaned_message_blobs:** every `raw_ref`; inline text (contains CR/LF) is only
  dequeued; otherwise, if no `messages.raw_ref` matches, the exact key is deleted
  (a refused delete leaves the row queued, no same-tick retry), then the row goes.
- **reap retries:** ledger entries re-checked against `blobs` (re-uploaded: dropped),
  else the delete is retried, so a refusing store sees a delete again each tick.
- `BLOB_RECLAIM_GRACE_MINUTES` is Go's PUT-time arming of `delay_minutes`; the tick
  only reads the column. Go's WORM retention-retry ledger (armed by Go's own PUT)
  is `blob_retention`'s ledger: Rust's PUT arms it and the last step of the tick drains it.
- Tests: `tests/blob_cleanup_recorded.rs` (frozen Go's real cleanup steps through
  overlay `tests/conformance/drain/blob_cleanup_tick_test.go.txt`, shared fake S3,
  goldens `goldens/blob-*.json`; `ticks` > 1 replays the retry ledger),
  `tests/blob_cleanup_startup.rs`. Seed ages need margin: a cold Go build can take
  minutes between seeding and the tick.

## Compliance (#289)

F04 console registrations mount at `/api`, including while forwarded to Go.
`compliance.rs` translates eDiscovery requests; family authority and database
operations live in `crates/domains/compliance` ([contract](../../crates/domains/compliance/DOX.md)).
The recorded HTTP/effect suite is `tests/compliance_recorded.rs`; the 12 eDiscovery
entries are ON after their case floors, route/family mutants and commit-loss
qualification. `main.rs` installs request/worker executors, process-local search
jobs and the shared S3 client. `compliance_export.rs` owns bounded HTTP streaming;
all business writes remain statements or family reducers. WORM hold/release
remains owned by F04 Compliance #289 and forwarded pending its S3 SetLegalHold
adapter; F16 PutObjectRetention is qualified by #301/#419. A quoted-NUL KQL is refused locally (400)
(owner-approved security fix 2026-11-05, #436; frozen Go's parser hung). Both inventory OFF and the global switch
restore Go ownership. The retention/audit (#290) and chat compliance (#291) slices are ON.

## Exchange replacement (#294)

F05 Exchange HTTP dispatch and recorded oracle: [family contract](../../crates/domains/mailboxes/DOX.md#exchange-replacement-294).

`exchange-assessment-deletion` is an explicit shared-effect worker transfer;
its startup requires the same name in `RUST_WORKERS_ON` and `GO_WORKERS_OFF`,
a worker database, S3 and the continuity signing key. The Exchange HTTP artifact
routes and deletion task share the [mailboxes Exchange contract](../../crates/domains/mailboxes/DOX.md#exchange-replacement-294).

Shared raw JSON compaction (`src/jmap/reply.rs::go_compact`) validates through
borrowed `RawValue`, preserving Go RawMessage's unbounded numeric tokens and
JSONB field order. F04's recorded `read-huge-json` response guards the precision
boundary (#291); materializing a machine number here incorrectly returns500.

Chat compliance ZIP uses the maintained `async_zip` streaming writer, SHA-256
from `sha2`, bounded duplex/channel buffers and the existing Go 2 KiB response
framer. Messages preserve PostgreSQL JSONB text (including spaces); the manifest
is last. A producer failure abandons the archive without a central directory.
HEAD drains the same producer; disconnect cancels it and its dedicated snapshot.


Chat compliance registers its production adapter from `main.rs`. All13 slice
entries are ON, with173 immutable Go HTTP/effect recordings,13 status mutants,
16 real COMMIT cuts with authenticated receipt lookup and both-switch byte
preservation proofs. Its detailed scope, snapshot, audit and oracle contracts
live in [Compliance DOX](../../crates/domains/compliance/DOX.md#chat-compliance-291).

F04 retention/audit/content-search adapter and its scoped reducers (#290):
[family contract](../../crates/domains/compliance/DOX.md#retention-and-audit-290).
`main.rs` registers `retention_audit.rs` with the request executor and a clone of
the configured Compliance worker executor. All 14 entries are ON after 150 Go
recordings, route/effect mutants, seven write-shape commit cuts and both switches.
`tests/retention_audit_recorded.rs` requires bundled ON decisions and no Go upstream.
A NUL in content-search KQL is a local 400 (#436, owner-approved security fix 2026-11-05).
`tests/conformance/retention-audit/catalog.py` creates only Go-derived projections
and the slice's qualification metadata; other slice records remain unchanged.

## Catch-all mux and SPA (#416)

Catch-all qualification and recording seam: [oracle](../../tests/conformance/catchall/README.md).
The F22 root and API mount and F12/F14/F13 fallback registrations belong to
this gateway boundary. More-specific family handlers retain their authority.

`RouteTable::with_catchall` installs the last adapter and enables the root mux's
clean-path redirects before concrete dispatch. The six structural registrations
are ON by default, with the usual inventory and global rollback. API unknowns
have Go's outer guest belt; Chat/Drive/Meet additionally require authentication,
live feature state and app entitlement before their inner 404/405. Authenticated
identity checks that the foundation cannot prove stay forwarded (Identity
#331–#333), as do entitlement denials with Go-owned audit effects. No catch-all
request writes business data. Headers and problem bodies use shared gateway helpers.

`WEBSITE_DIR` build validation, streamed representations, cache/validator rules
and the public bootstrap predicate: [static contract](../../crates/domains/static/DOX.md#webmail-representations-and-catch-all-416).
`SETJOIN_CONFIG` root pages use the resolved startup configuration (#414);
the executable serves them without a Go upstream.

## ACME :80, `acme-renewal` and the setup control socket (#305)

Contract and rollback: [Platform DOX](../../crates/domains/platform/DOX.md#slice-acme-control-305);
issuance engine: [setjoin-acme](../../crates/acme/DOX.md). Startup guards (executable tests
`tests/acme_startup.rs`): `RUST_WORKERS_ON=acme-renewal` needs `GO_WORKERS_OFF=acme-renewal`.
HTTP-01 requires the :80 descriptor `acme`, TLS-ALPN-01 shares the active :443 frontend `https`,
and DNS-01 requires no HTTP descriptor. DNS manager creation/config-file errors log and leave
cached/static HTTPS serving, matching frozen Go; other managed challenge startup failures stay fatal.
Configuration and provider contracts live in the ACME crate;
an activated `acme` descriptor needs `GO_WORKERS_OFF=http-port80`;
`RUST_WORKERS_ON=setup-control` needs `GO_WORKERS_OFF=setup-control` (Go gates its control
socket on that name since #305). Oracles: `acme_renewal_recorded.rs` (seed plus one tick against
pebble, `GOFREE_RECORD_ACME`), `acme_http80_recorded.rs` (`GOFREE_RECORD_HTTP80`),
`setup_control_recorded.rs` (`GOFREE_RECORD_CONTROL` with the private Go binary).

JMAP1 (#315): `Email/changes` is served by `src/jmap/changes.rs` with no feature
toggle (`authorize_request`; the inventory entry is the switch). Order as Go:
account (own mailbox; a mailbox with no delegate grant is `accountNotFound`,
delegated accounts forward), malformed `sinceState` (`cannotCalculateChanges`),
reducer. Goldens: `email-changes*` in `tests/conformance/jmap/goldens`.
`Email/get` (#315, `src/jmap/get.rs`): one call, `accountId` + 1..=256 string `ids`
(+ optional `properties`); malformed ids fold into `notFound` as Go's `addNotFound`
(sorted-key re-marshal). Read plus `email_get` audit row in one `exec.run`
statement; any email with `cryptoType = smime-encrypted` writes nothing and forwards
(S/MIME decrypt-on-read stays Go's). Oracle: `tests/jmap_email.rs` +
`tests/jmap_email_oracle/` (one case table, recorded with
`tmp/gofree/jmap1-rec.sh`; fixture IDs are named per table, timestamps scrubbed).
General `Email/query` (#315, `src/jmap/query.rs`): `accountId` + optional `filter`/`sort`
(raw JSON passed to `jmap_email_query` as written), integer `position`/`limit`
(limit clamped to 50 outside 1..=256). A reducer error is Rust's answer only when the
database reported it deterministically (`setjoin_jmap::classify_failure`: BZ006/BZ011/BZ002,
SQLSTATE 22/23/42/P0001 as Go's `serverFail`/`database error`); anything else forwards.
The specialized inbox-list adapter serves its shape regardless of either retired
pilot flag; other supported queries use this general path. Cases of commands whose catalog suite also holds `jmap_recorded` cases
live in that binary (`mod jmap_email_oracle`): one suite replays from one test binary.
General `Email/set` (#315, `src/jmap/set.rs`): exactly one phase, `update` (canonical ids,
object patches, no `snoozeUntil`) or `destroy` (<=256 strings); `create`, snooze,
mixed phases and `ifInState` forward to Go (attachment-blob gate, per-message snooze and
the multi-reducer batch are not one statement). One statement: the existing
`jmap_email_set_update`/`_destroy` reducer plus the `email_set` audit row (owner
decision 2026-10-29: `details.operation`, reviewed divergences per case); a rolled-back
command answers as `classify_failure` or forwards. The retired mark-read/inbox-list
flags do not affect dispatch. Goldens `email-set-*` with row effects.
`Email/recover`/`Email/purge` (#315, `src/jmap/batch.rs`): `ids` 1..=256, one reducer call in
`run_receipted_command` (Go writes no audit row, so the receipt is a `rust_operation_receipts`
row, family `jmap`); malformed ids fold into `notRecovered`/`notPurged`. `Email/deletedQuery`
and `Email/bundles`: paged `READ ONLY` reads (cap 256/200, else 50; bundles wraps as Go's
sorted map). Purge also inserts `orphaned_message_blobs` (global table): oracle cases clear
the fixture's fixed raw refs before and after each run.
`Email/nudges`/`Email/nudgeDismiss` (#315): `feature.stale_nudges` (registry default OFF) is read
from the toggle row (`gates::toggle_state`; process-env overrides are Go's alone). OFF answers Go's
inert empty list / `dismissed: []` natively; ON calls `stale_thread_nudges_list` or the receipted
`nudge_dismiss` reducer (writes `users.view_prefs`; Go writes no audit row). The recorder sleeps
500 ms after toggling so Go's notification-fed flag cache catches up.
`Email/recoveryReceipt` (#315): `feature.client_recovery_receipts` OFF is Go's `forbidden` answer, given
before Go reads arguments or account (so the account is not compared here); ON forwards (the signing
key and raw-MIME fetch stay Go's until the continuity port).

## JMAP WebSocket and Chat presence (#318/#418)

`main.rs` installs `jmap::push::WebSocketRoute` and `jmap::presence::PresenceRoute`
with one connection registry, beside the shared `JmapCommands` (including JMAP2
services and JMAP3 worker). Both inventory
entries are ON. SSE (#319) clones the same `hub` and `registry` exposed by
WebSocketRoute. Domain/API contract: [JMAP DOX](../../crates/domains/jmap/DOX.md).
`Intercept::shutdown` runs after front-door acceptance stops and evicts upgraded
sockets before the HTTP drain. Registry callbacks never run under its lock. The three original Chat presence
floors now replay through `chat_deferred_recorded` with Go unset and zero proxy
counters (#418), alongside the live WS/SSE lifecycle recordings.

Push requires an explicit `DB_DIRECT_DSN`; a missing value cannot fall through
to libpq defaults or use the request pool. Its process-local device snapshot
uses `DB_WORKER_DSN` (fallback `DB_DSN`) for global reads, refreshes on demand
at five seconds and fails closed before its first successful snapshot. Keep Go's
process-local caches running until Go is deleted; no shared-effect worker is
transferred here. Production origin policy mirrors Go's TLS_CERT_FILE,
TLS_AUTOCERT_DOMAINS and HTTP_MODE=proxy test, including its second upgrader check.
Cookie authentication, 1000-client and 10MiB bounds, ping30/pong70/revalidate300,
app admission and targeted revocation are exercised over live sockets.
Legacy HS256/SM2 credentials remain the named Identity #331 shape; shared HTTP
security admission for presence remains #420. No new rollback path is added.
The route catalog binds the recorded suite and one planted status mutant per
route; native replays require total Go proxies zero. Deferred batches separately
prove unchanged frames, one Go attribution and absence of preceding Rust writes.

## JMAP2 folder methods (#316)

The unflagged `POST /jmap` adapter also serves Mailbox/get, query, changes,
queryChanges and set. The [family contract](../../crates/domains/jmap/DOX.md#mailbox-methods-316-jmap2)
owns phase atomicity, receipt recovery and frozen-Go input defaults.
`tests/jmap_other.rs` replays Go-recorded response bytes, rows and notifications
without a Go upstream, including per-method changed-status mutants.

JMAP2 HTTP discovery/upload/download use `JmapServices` for the explicit worker
pool, public hostname/upload bounds and existing S3 client. Session GET may
write the native-device heartbeat through a receipt; live admin permissions,
SoD self-knowledge, configuration and delegate identities mirror Go.
Upload streams to a bounded local spool, puts a temporary S3 object, commits
`blob_upload_account` once, then promotes and removes the temporary object.
Unknown keeps the staged bytes and returns its operation ID. Download checks
Go's metadata-before-ownership order, then actor/delegate attachment scope,
object size and untrusted-content headers. Family detail stays in the
[crate contract](../../crates/domains/jmap/DOX.md).

Identity/get, changes and set are JMAP2's remaining submission-capability
methods. Read selectors are ignored as Go; Identity/set shares SetRequest and
its new atomic family wrapper. Database cancellation on JMAP2 methods returns
Go's serverFail locally; fault replays require zero proxy attempts. Shared
HTTP/WS batch/reference execution remains the #318 integration seam.
F18 EmailSubmission (#317): request translation is in `src/jmap/submission.rs`,
using `urn:ietf:params:jmap:submission` rather than the mail capability.
See the [family contract](../../crates/domains/jmap/DOX.md) and HTTP oracle
`tests/jmap_submission.rs`.

F18 submission REST (#317): `src/jmap/submission_actions.rs` serves the mounted
`/api/messages/{id}/undo|recall` actions. The inventory mounts F18 `/messages/*`
registrations at `/api`, preserving pinned `/jmap` paths. Typed submission input
and S/MIME ownership probes live in `src/jmap/submission_input.rs`; the entire
mixed map defers to #328 when its Go-style sign/encrypt probe requests processing.

#317's same #328 MIME boundary includes attachment-only submissions: an
owner-scoped draft preflight runs before writes, and any map needing assembly
forwards whole. Go error-branch reachability is recorded in the
[JMAP harness](../../tests/conformance/jmap/README.md).

F09 Rules (#329): `src/rules.rs` mounts rules and template handlers at `/api`;
[family contract](../../crates/domains/rules/DOX.md), oracle target `rules`.

Federation whole-listener swap (#347): `main.rs` starts the native inherited
`federation` socket, product-feature snapshot, admitted Chat typing producer,
and guarded independent residue reaper. Configuration, oracle and shutdown
contracts: [Federation DOX](../../crates/protocols/federation/DOX.md#native-activation-and-delivery-347).

F18 SSE (#319): `main.rs` constructs `EventSourceRoute::new(&push)` after WS
production-origin configuration, then installs it beside WS and Chat presence.
All three use one registry; the two push transports also share the client
counter and direct-DSN notification hub. The SSE inventory row is ON; the
[family contract](../../crates/domains/jmap/DOX.md) and
[recorded oracle](../../tests/conformance/jmap/sse/README.md) define lifetime,
query, wire and named Identity #331 handoff parity. No shared-effect worker or
Go-off setting changes. The executable test leaves the Go mail upstream unset;
its required auth-upstream setting is an unreachable #331 endpoint and receives
no request.

SMTP post-commit webhook adapter (#348): `smtp_events::DeliveryEvents` implements
`setjoin_smtp::DeliveryEvents` using the process-wide `webhook::Dispatcher` and
the reducer-derived mailbox/user subject. The staged listener receives it via
`with_delivery_events`; #351 wires activation. `smtp_events_recorded` compares
frozen Go's signed HTTP requests and delivery rows, including self-subscription
isolation; see [SMTP contract](../../crates/protocols/smtp/DOX.md).

F21 legacy JWT verification (#331): the existing shared JWKS source now also
carries configured JWT_SECRET/SM2_PRIVATE_KEY_FILE verification material.
HS256 and SM2 use the same downstream claim/session/guest gates as ES256;
[authz contract](../../crates/authz/DOX.md#first-party-key-custody-and-legacy-jwts-331).
The standalone auth process reuses `src/problem.rs`, including the distinct
sorted-map CSRF response used by Go's shared middleware.
Qualified `rust-auth` entries now reach setjoin-auth under the front-door rate
budget. The retired blanket Go-auth deferral no longer bypasses that process;
its own handler owns #420/#405/#406/MFA handoff before effects.

SMTP outbound object reads (#350): `smtp_outbound::BlobSource` supplies the
protocol worker's raw objects through native S3, retaining MinIO date-header and
XML error behavior. An explicit `S3Store::with_region` matches a configured
MinIO region; unspecified regions keep discovery. Worker and oracle detail:
[outbound contract](../../crates/protocols/smtp/src/outbound/DOX.md).

SMTP outbound task handover (#350) is selected only by the two worker-name
lists, uses `DB_WORKER_DSN`, and is joined at shutdown. It emits no mail.sent
publication: that event belongs to committed submission, as in Go. Forward
preparation uses the existing LinkProtect token verifier and runs before DKIM;
[protocol contract](../../crates/protocols/smtp/src/outbound/DOX.md). #351 wires
native DANE/MTA-STS/TLS-RPT through `smtp_outbound::HttpPolicyFetch`, system DNS
and the worker credential. Its authoritative feature snapshot is mandatory at
startup and reloaded per tick; the MTA-STS cache is preloaded before scheduling.
Whole-listener activation remains staged pending #420 plus submission/inbound
security adapters; no listener ownership is transferred here.
Executable worker fixtures provide a valid request credential for Identity's
startup cache; the outbound fixture uses a read-only request connection and
proves its queue write is denied with SQLSTATE 25006. Direct-listener assertions distinguish the session
worker's `session_revoke` subscription from Identity's `config_changed` listener.
#333: `link_protect` re-exports its existing Go net/url authority parser from
`setjoin-authz::go_url`. `ssrf::blocked` re-exports the same literal-IP policy from
shared authz; gateway `ssrf::valid_url` keeps its existing URL parser unchanged.
This lets authserver admission reuse the foundation without importing a binary.

#333: Native Drive token issuance is a separate adapter before the Drive router.
It verifies the source, guest/revocation/CSRF policy, then delegates the narrow
mint to identity. Both Go upstreams may be unset for native shapes. Shared
runtime/CA components remain #405/#420 and guest program admission #406; no
completed-shape return-to-Go switch is introduced. Drive adapters use actual-path
scoped admission; non-Drive surfaces continue to reject mirrors.
The front door answers mailserver global CSRF denials before route budgets
(#406), including requests sent to either auth upstream. Only an auth-only
inventory (auth rows present, no gateway rows) models the direct auth listener
and retains authserver's per-route CSRF ordering and response headers (#516).
`tests/proxy.rs::auth_csrf_is_scoped_to_the_listener` pins cross-origin TOTP
verify and WebAuthn login finish through both listeners and both auth targets,
with/without edge limiting; same-origin requests still reach the handler.
NativeTokenRoute retains a method-aware check when used directly.
The recorded csrf cases check wire bodies/headers and zero Go counters with the
upstream unset.

The process-local auth-chain listener (#333) starts when the enabled gateway has
DB_DSN and DB_DIRECT_DSN, reads configuration through the request credential and
uses only the direct DSN for LISTEN. It refreshes on reconnect and joins on drain.
Go keeps its own cache task. Native Drive uses its Basic-admission generation;
only the unported Basic/Negotiate proof shapes forward to #420/#339 respectively.

The link-protect oracle accepts GOFREE_LINKPROTECT_DNS_IP (loopback only;
default 127.0.0.66), so independent workers can own different UDP53 fixtures.
GOFREE_RESOURCE_PREFIX namespaces and removes its temporary resolver file.
DNS responses and all golden assertions remain identical.
Inventory dispatch keeps F06's public `/link-protect` pinned at the root even
when LocalRust is ON; the generic local-route API mount rule cannot override it.
The link-protect HTTP corpus verifies the actual dispatch and parser together.

## HTTPS runtime (#413)

The socket-activated descriptor named `https` is a native TLS 1.2/1.3 listener, selected by
`RUST_WORKERS_ON=http-tls`. Startup requires `GO_WORKERS_OFF=http-tls,http-h2c`, a configured
certificate source, and the enabled Rust front door. It never becomes a plaintext listener or
an all-Go proxy. Plain HTTP/h2c and HTTPS share route dispatch, limits, metrics and a 30s drain;
ALPN selects the HTTP engine. Direct TLS overrides a trusted plaintext scheme header, and
HTTP/2 `:authority` becomes Host before forwarding. TLS handshakes have a single 30s budget.

`tls_runtime` starts `cert-monitor` / `tls-ticket-keys` only when explicitly selected, their
Go copies are off, and the HTTPS listener is present. They use `DB_WORKER_DSN` (fallback
`DB_DSN`), never an owner credential. Persisted keys are applied before the first handshake;
rotation defaults to 24h (`TLS_SESSION_TICKET_KEY_ROTATE_SECS`, nonpositive → default), keeps
one prior generation, and a fatal entropy error shuts down the HTTP listeners. The monitor
probes the first usable configured SNI's actual served chain, immediately then every 24h;
renewed cache blobs are seen on its next check. Both SQL adapters cancel/drain and join on
shutdown. Frozen Go's missing codec wiring/plaintext persisted key JSON is retained for parity.

Checks: `tls_front`, `tls_startup`, `http_lifecycle`, `cert_monitor`, `ticket_worker`, `proxy`.
The DB-backed live-worker case compares the actual chain's health row to the recorded Go
seven-day oracle, and proves loaded keys resume a client across fresh listener instances.
The executable case adopts separate HTTP/HTTPS descriptors and exits cleanly on SIGTERM.
Shared authenticated runtime gates, cache lifecycle and DSN split (#405): [runtime contract](runtime-access.DOX.md).

## Terminal shared admission (#406)

The global CSRF rejection is native before route budgets/authentication, including
when `GATEWAY_UPSTREAM` is unset. It uses `problem::middleware` (Go's sorted-map
wire format), retaining the security headers and request ID. Safe methods bypass
CSRF. `tests/authz_defer_recorded.rs` exercises the front-door HTTP seam.

`RouteTable::with_admission` installs deployment-owned signature verification for
native terminal authentication answers. `Intercept::requires_session` names the
matched shapes wrapped by Go's `RequireAuth`; public/capability adapters retain
their own authentication. Invalid/expired session credentials get Go's 401 problem
and Negotiate/Bearer challenge without an upstream attempt. Basic/Negotiate
strategies remain owned by #420/#339. The executable and replay share this table.

All protected gateway adapters opt into the shared terminal session check;
composite F15/F16 adapters delegate to their matched child. Calendar booking,
approval email capabilities, public Meet/webhooks, SCIM, Office callbacks, attachment
capabilities, static public documents and push handshakes retain their distinct
seams. The executable oracle records expired/wrong-audience credentials on one
protected route in each of F01–F20 and F22, compares raw response bytes and headers,
and requires the total Go proxy counter to remain zero. F21 is the standalone
identity process. Corpus: `tests/conformance/authz-defer/invalid.json`.

A signature-valid session is also checked against `guest_account_status` on the
worker credential before any native adapter or route budget. A claimed guest with
no satellite row, or an inactive/expired satellite, gets Go's unchallenged 401;
a failed/bounded-out satellite read gets the gate's 503. The guest mismatch corpus
pins this distinction from RequireAuth's challenged 401 across all gateway families.

The satellite belt also runs on public matched adapters: a live guest is hidden
with Go's plain-text 404 while the guest program is OFF, regardless of the token's
account-type claim. `guest-off.json` records 46 cases including public OpenAPI and
RTC. Test fixtures restore program toggles and delete their exact mailbox-less
users even after an assertion panic.

With the guest program ON, containment matches the frozen Go allowlist, copied
verbatim as native tuples in `src/guest_allowlist.rs`. Go source is not a Rust
build input. Invalid rules fail initialization; unlisted methods/paths deny with
the same hidden 404.
`guest-on.json` records 38 denied member-claim/guest-claim paths. No token-owned
identity can bypass the satellite or select a guest host domain.

Guest JMAP discovery (`GET /.well-known/jmap`) uses the shared user proof and
returns Go's empty accounts/capabilities plus the fail-closed guest capability
projection before any mailbox lookup. App flags, user entitlements and profile
hints keep their authenticated-user predicates. `guest-session.json` records
both explicit and satellite-forced guest claims at the executable boundary.

Allowed Chat/Meet/Drive guest requests use sealed user-only database scope; both
explicit and stripped guest claims reach the same canonical reducers. Guest
conversation attachments remain disabled as Go specifies. `guest-domains.json`
records native reads and reducer-refused creates. The shared guest proof replaces
F4's old whole-request handoff before route budgets; per-target checks remain in
family reducers.

Full OpenAPI documents now resolve Go's live governed grants and write native
`console.denied` rows before the exact bare 403. Signed non-admin `system.config`
and scoped-member grants retain Go's behavior. `full-spec.json` records both
formats under five authority shapes, raw denial bytes, audit rows and successful
content hashes. Problem bodies use the central FIX3 encoder.

Meet entitlement refusals now answer locally using Go's typed Forbidden problem
and the existing canonical app_blocked audit statement. The shared twelve-case
corpus covers list/create/get, repeats, full-policy audit rows and lean suppression.
The executable entitlement test runs with Go unset and requires zero forwards.

The terminal guest belt precedes route budgets, while RequireAuth follows them.
`jwt-route-budget.json` pins expired JWT responses at 401, then 429 in one admin
bucket; the request never reaches Go or a family handler.

Positive cached or durable session revocations answer Go's sorted-map
`session_revoked` problem after route budgeting. The durable predicate uses the
verified uid/iat/jti/fam only and covers every gateway family (`denylist.json`).

Deployment startup validates the feature-registry singleton before listening,
matching frozen Go's toggle initialization refusal. Cold/nil session denylist
state answers the exact runtime 401 only with CAE enabled; positive revocations
remain authoritative first. Process-local refresh runs in both languages during
migration. Other CA/device runtime work remains owned by #405.

Fault corpora cover a worker guest probe blocked beyond one second (503 and
same-process recovery), unavailable JWKS (challenged 401), missing registry
(startup refusal), and a permission-failed startup denylist (CAE cold 401).
The crypto profile corpus exercises HS256 and SM2 signatures on every gateway
family plus a member read: standard ignores SM2; configured hybrid/smx accept it.

`authority-error.json` records the frozen-Go permission-resolution failure bug:
a signed admin with `system.config` still receives the full document if the live
assignment SELECT fails; without that signed claim, 403 plus console.denied.
This exception is explicit parity; healthy live authority still replaces claims.

The CSRF corpus covers every family plus Go URL userinfo/Referer handling,
Origin precedence, Fetch-Site, opaque/invalid origins and mixed-port IPv6. Safe
GET crosses Origin checks without changing the headers passed to its adapter.

SMX deployment startup requires SM2_PRIVATE_KEY_FILE, as Go does; the immutable
`smx-key-absent.json` observation pins refusal before any listener opens.

JMAP and socket batches retain positive cached revocations even after durable
rows disappear. A negative cold cache is usable with CAE OFF; with CAE ON it
refuses. The HTTP worker-cache regression installs production terminal admission
and checks native 401s rather than an old Go handoff. F22 recorded full-spec
refusals likewise install terminal admission and require zero forwards; denial
fixtures remove their exact synthetic console audits.

Terminal guest dispatch also covers F21 auth-proxy entries. It follows Go's
root mux: canonical redirects precede the belt; ordinary SPA GETs bypass it;
API mounts and registered legacy mutations pass through it before routing.
`guest-dispatch.json` pins these boundaries, live disabled/expired satellites,
and expired-JWT mux404/method405/legacy308 versus protected Chat401.

Main pairs CatchallRoute::with_terminal_auth with RouteTable::with_admission.
That builder admits user-scoped guests and lets already-gated public mux/alias
outcomes finish locally. Its RequireAuth classification names only the outer
Chat/Drive/Meet mounts. The existing injected with_auth builder retains its
member-only contract; no deployment rollback control is added.

## Gateway configuration (#414)

`inventory_guard::platform_slice_ownership_is_exhaustive_and_disjoint` pins
`POST /admin/reload` as F08's sole ON `configuration` entry, separate from terms.

`src/configuration` owns the operator configuration seam: frozen Go's defaults,
optional `SETJOIN_CONFIG` YAML, then overrides only for existing keys using
Go's first-underscore/double-underscore transform and unique conventional-name
fallback. `config.env` is supplied by systemd as the process environment, as in
Go. The YAML parser is the workspace's `serde-saphyr`; scalar conversions and
undeclared login-field behavior preserve Go. The recorded precedence table and
recording overlay live in [gateway-config](../../tests/conformance/gateway-config/README.md).

`Runtime` publishes a newly validated config snapshot on SIGHUP and
`POST /api/admin/reload`; both refresh `trusted_proxy_ips` through the request
credential. Missing/malformed/empty arrays retain the prior set; a nonempty
array replaces it, discarding invalid members. The executable defaults to Go's
loopback proxy trust unless `GATEWAY_TRUSTED_PROXIES` is supplied. The reload
loop is process local (both Go and Rust may run it), coalesces signals, and joins
on shutdown. It needs no shared-effect worker handover. Direct DSNs remain
LISTEN-only.

Go's HTTP report is only `{"status":"reloaded"}`, without a restart-required
list. Boot handlers, network detection, website assets, SCIM registration and
AD enablement retain startup configuration; the config pointer has no handler
readers in frozen Go. `config.env` changes need a process restart. The public
bare reload path remains the 308 API alias; auth's same-named internal route
belongs only to its direct listener. An auth-only inventory used by the
recording/replay front door selects that listener's `/admin/reload`; including
gateway listener entries retains the public alias (#516).
Reload uses Go's `system.config` gate,
including signed scoped grants, and the existing durable console-denial audit.
The oracle includes raw responses, audits, repeat/invalid loads, native zero-Go
counts, a status mutant and HTTP/SIGHUP client-IP rate-budget proofs.


A disabled SCIM registration reaches the configured root mux, as Go does:
404 without `WEBSITE_DIR`, SPA content with a valid website. The recorded
`f7-disabled-scim.json` verifies the latter's body and representation headers;
the startup fixture verifies the former for every concrete SCIM registration.
An explicitly supplied YAML configuration runs the same validation before bind
as HTTP/SIGHUP reload; an invalid encryption algorithm never opens a listener.


Go's `authserver.jwks_url` is optional. With `JWT_SECRET`/SM2 configuration and
no JWKS URL, the executable uses the existing legacy verifier plus an empty ES
key source (no invented endpoint or outbound request); public config and
permission-gated reload remain native. `legacy_jwt_configuration_...` proves
this through HTTP with Go unset, including an audited-primitive HS256 token.

## HTTP listener resource bounds (#413)

`src/http_limits.rs` applies to native HTTPS and loopback HTTP/h2c. Production
read/write/idle budgets are 30s/120s/120s, matching Go's public server. Reads
cover headers plus the complete request body without refreshing on each byte;
write budgets cover handler execution, response streaming and pending socket
output through flush (body EOF alone is not completion). Queued DATA bytes
retain the request lifetime through HTTP/2 flow control without copying payloads. An expired
connection deadline closes the transport and cancels its pending handlers.
An active response keeps its request budget instead of becoming idle. HTTP/2
also probes at 60s with a 30s acknowledgement timeout; answering PINGs does not
extend the independent 120s request-idle deadline. HTTP/1 keep-alive waiting is
separate from the next request's full header deadline. Both TLS and h2c
prefaces also have a 30s read budget before entering HTTP/2 idle waiting.

One semaphore is shared by both listener clones. `GATEWAY_MAX_CONNECTIONS`
(default 1024, positive supported integer, startup-only) configures capacity.
Overflow sockets are dropped immediately, before TLS negotiation; acceptance
never waits for a permit. A permit stays with the transport through upgrades
and is returned on disconnect, handshake failure or shutdown. Application
WebSocket lifetimes remain owned by the existing upgrade handlers.
`Gateway::with_http_limits` exposes the same policy with shorter durations for
socket tests. `tls_front` checks idle h2, slow h1 bodies, pending h1/h2 responses,
shared TLS/loopback overflow and capacity recovery. No database or Go change.

## Shared protocol threat runtime (#420)

Named IMAP descriptors load the shared `setjoin-threat::Gate` and its independent
configuration listeners before activation. There is no allow-all default. The
runtime's process-local denylist feeds IMAP's registry through `apply` on NOTIFY
and `reconcile` on durable refresh; all-scope revocation closes password sessions.
IMAP accepts no sessions until a bounded initial revocation snapshot succeeds;
failed loads retry with shutdown cancellation. After every successful LISTEN
subscription, a bounded refresh immediately repairs missed notifications before
the notification loop resumes; failed refresh retains the prior snapshot and the
independent 30-second timer retries. This is the owner-requested #420 security
hardening of Go's delayed reconnect reconciliation.
Every listener and cache task belongs to a JoinSet and ends on shutdown/drop.
IMAP uses configured IMAP_TLS_*_FILE, then TLS_*_FILE, then native TLS_CERT/TLS_KEY.
Server boot before listener/worker construction (#415): [boot contract](../../crates/boot/DOX.md).
Executable tests with `DB_DSN` use `tests/common/boot.rs`'s `CommandBootExt`:
owned private config file and local S3 peer, explicit worker/owner defaults,
valid request credential, and fixture teardown restoring boot-upgradable
secret rows and newly written MinIO health rows. Children are killed/reaped
before teardown. Run these tests serially; explicit test configuration,
including empty environment values, remains authoritative. Storage-worker
peers must answer bootstrap location/list/ping operations before recording
their worker tick; bootstrap operations belong to the boot oracle.
The IMAP refusal fixture keeps BOOT's request database live and makes the direct
policy-subscription connection unavailable; it asserts boot completed before refusal.
Short executable TCP readiness guards allow 30 s for the complete boot on a
shared host; their admission and refusal assertions remain the same. Shutdown
and worker cadence bounds are independent of that startup allowance.
The SMTP executable fixture grants an owned `gofree_boot_smtp_request_<pid>`
role read access plus boot's config/health writes, verifies queue UPDATE is
denied, then drops its grants and role in the assigned disposable database.
A read-only request connection cannot run Go's secret-locking boot phase.
Federation's delayed first snapshot fixture uses a worker-only search-path
view and advisory barrier, keeping boot and HTTP toggle reads available. SSE's legacy
origin-rejection recording now states its mismatched Host explicitly; a new
matching-authority Go recording covers cookie acceptance after Host preservation.

F16 conditional/ranged attachment reads (#419) and lazy multipart streaming: [Blobs contract](../../crates/domains/blobs/DOX.md#read-paths).

F12 URL sends (#418) stay native with Go unset. `ChannelRoute` shares one safe
unfurl service/S3 store with cached-image reads; it starts enrichment only from a
committed send. Transaction, receipt and fetch bounds: [Chat contract](../../crates/domains/chat/DOX.md#url-send-enrichment-418).

HTTP authority compatibility (#418): synthesize `Host` from HTTP/2 `:authority`
only. HTTP/1 absolute-form requests without a Host header retain that absence,
including the frozen SSE cookie-origin 403. The unchanged SSE golden and native
TLS HTTP/2 authority test cover both wire shapes.

## Static and Assist leftovers (#417)

`surface`, `assist`, `translate` and public `telemetry` share the existing
F20/F22 contract in [Static DOX](../../crates/domains/static/DOX.md). Native
secret loading uses the foundation codec; device-only authority comes from
`setjoin-authz`, and telemetry's single INSERT uses the worker credential.
An absent DAV redirect registration uses main's same startup catch-all snapshot.

F17 CalDAV HTTP method transfer (#426): [Calendar contract](../../crates/domains/calendar/DOX.md#caldav-http-slice-426).

## Owner-approved security fixes (SECFIX3, #509, 2026-11-05)

Persisted TLS ticket keys are sealed in the `system_config` secret envelope (`ticket_keys::codec`
from `identity.deployment_id` plus `IDENTITY_CONFIG_SECRET_KEY`/`DB_ENCRYPTION_KEY`); legacy
plaintext rows are never trusted and are replaced at startup; without key material the keys
stay in memory only and a legacy plaintext row is deleted (a sealed row is kept) (#503). The global CSRF gate runs before the over-budget branch (#491). Every over-budget request (core and route buckets) is answered with Go's 429; nothing defers to Go (#357). An /auth spelling no inventory row claims gets the root mux's answer (decoded-segment slash redirect to an F21 subtree row, else the catch-all) after CSRF, budgets and admission (#357, #378, src/unmatched.rs). Adapter-less local rows still fall back to Go until DELETE (#142).
Failed live authority lookups fail closed in rules, `system.config` and the JMAP session (#484).
Tests: `secfix3_csrf`, `secfix3_rules`, `ticket_worker`; divergences in `tests/golden/secfix3-divergences.json`.
OIDC OP public namespace closure (#339): `oidc_namespace::Namespace` is installed
by the executable before generic adapters and the positional final catch-all in both
public-only and database-backed tables. Appending it afterward breaks root fallback
dispatch. The qualified gateway `/oauth`, `/oauth/` and `/authorize/` registrations
are local terminal404s. Only the exact
allowlisted OP endpoints proxy to Rust auth. The direct auth listener's `/oauth/`
mount remains an OP namespace with its own CORS/threat tail; those are distinct
recorded contracts. Unknown children never reach the SPA or an auth upstream.
F17 CardDAV HTTP transfer and family closure (#427): [Calendar contract](../../crates/domains/calendar/DOX.md#carddav-http-slice-427).

SMTP listener swap (#501): `smtp_runtime.rs` serves inbound `smtp`/`smtps` and `submission`
from named systemd FDs (`activation.rs`), refuses to start unless `GO_LISTENERS_OFF` lists
`smtp` / `submission`, the webhook dispatcher and the shared gate (`imap_runtime::shared_security`, one
gate/watchers for IMAP and SMTP) are wired. Flags are the gate's live `feature_toggles`
snapshot; `smtp.env` carries the allow-listed settings (`SMTP_INBOUND_MAX_CONNS`,
`SMTP_SUBMISSION_MAX_CONNS`, `SMTP_PER_USER_MAX_CONNS`, `SMTP_INBOUND_TLS_ENFORCE`,
`SMTP_TLS_CERT_FILE`/`SMTP_TLS_KEY_FILE` or TLS_CERT/TLS_KEY, and the derived link-protect keys; no master secret, so HS256 auth/device/attachment secrets stay unset and the /link-protect click route and forward un-rewrite use the derived keys). Submission revocation reuses `SessionDenylist::attach_protocol`.
Contract: [SMTP crate](../../crates/protocols/smtp/DOX.md#submission-and-the-listener-swap-501).
OIDC OP completion POST (#523, owner-approved security fix 2026-11-05):
`Inventory::find` maps `POST /auth/oidc/op/complete` onto the census's single
`GET /auth/oidc/op/complete` registration, so the CSRF-protected bind is served by
the same owner (rust-auth). The inventory/census is unchanged: frozen Go never
registered a POST, and the route-inventory guard forbids an extra entry.

## Message REST routes (#469, JMAP1B)

`src/jmap/messages.rs` mounts `POST focus`, `GET|HEAD download`, `GET|HEAD attachments.zip` and
`POST unsubscribe` under `/api/messages/{id}/` on `JmapCommands`, behind the same admission as undo/recall
(unadmitted requests forward whole to Go, #331). Focus decodes its body like Go's `json.Decoder`
(first value only, case-insensitive keys, `null` ignored). Download resolves the owned message, then
runs the native `/jmap/download` with only the Authorization header and answers `message/rfc822`
(any non-200 inner status is Go's 404 `email not found`). `src/jmap/messages_zip.rs` streams the zip
(`compliance_export::stream` framing, `async_zip`, one bounded S3 chunk at a time; a blob that cannot
be read leaves an empty entry as in Go; no size cap, as in Go). Unsubscribe validates with
`go_url_parse` (Go `ssrf.ValidateURL`), refuses non-public literal addresses before dialing
(the URL crate reads `2130706433` as 127.0.0.1) and POSTs on `webhook::safe_http_client` (public
addresses only, no redirects, no proxy, 15 s); a failed POST still records the audit row and the block.
Oracle: `tests/jmap_messages.rs` over the shared `jmap_email_oracle` runner (zip bodies are observed
through `tests/conformance/jmap/zip_listing.py`).

F08 updates-deploy recovery administration (#455): [Platform contract](../../crates/domains/platform/DOX.md#recovery-administration-455).
F08 signed offline update appcast/files (#455): [Platform airgap contract](../../crates/domains/platform/DOX.md#airgap-updates-455).

F08 deployment wizard lifecycle (#455): [Platform deploy contract](../../crates/domains/platform/DOX.md#deploy-wizard-455).
## Spam trainer (#451)

`src/spam_trainer.rs` owns the F06 collector/flush over the worker credential,
with a per-user model-byte CAS and message ownership join. The complete
model and seed/tick oracle contract lives in [F06](../../crates/domains/mail-security/slices/spam-trainer.md#trainer-flush-451).
`RUST_WORKERS_ON=spam-trainer` requires the exact Go-off token, worker DSN for
model writes and direct DSN for `spam_train`. It schedules the first flush at
30 s, bounds the event queue at 1000, reconnects LISTEN and cancels/joins on
shutdown. Executable proof: `tests/spam_trainer_startup.rs`.

## Optional HTTPS client certificates (#468)

Before opening HTTPS, `tls_runtime::client_verifier` reads operator-owned global
`auth_methods` through the request credential and loads the first enabled certificate
method's `ca_bundle_path`. Bad JSON, unreadable/empty bundles and unreadable/unparseable
`crl_paths` skip the method as in Go. No user identity comes from this read. CA admission
reuses the F06 Go certificate profile; rustls/ring verifies the TLS chain and proof of
key possession, allowing certificate-free clients. With no usable method, system roots
and empty CA hints match Go's nil ClientCAs. With no configured or system roots,
a rejection-only policy still permits certificate-free clients and rejects every presented
peer; it performs no cryptographic operation or verification assertion. This startup snapshot is independent of HTTP config reload,
as Go's listener holds the original pool. CRL-file admission does not move per-request
certificate-login revocation policy into TLS. The first verified peer leaf travels in
request extensions to F06's status route; certificate headers supply no identity.
`mailsec_smime::cert_status_uses_configured_client_ca` exercises DB configuration → real
TLS → authenticated status; `cert_status_from_the_actual_tls_peer` covers the transport
constructor directly. Both also pin the no-peer response despite forged headers.

The HTTPS activation fixture honors `GOFREE_RESOURCE_PREFIX` for its owned directory
and gateway executable; its default namespace and assertions are unchanged.
F08 storage execution and joined task lifetime (#459): [Platform storage](../../crates/domains/platform/storage.DOX.md).

## Mailserver-local identity self-service (#494)

`identity_self_service` serves qualified mailserver-only F21 registrations
locally, using verified user context. It never forwards a matched shape to Go.
Authserver remains a distinct process. [Contract and transaction map](../../crates/domains/identity/SELF_SERVICE.md).

The #494 migration adapter is `identity_migration.rs`, composed after the same
verified-session admission. Owned status/history SQL stays in identity; existing
migration worker and config custody are composed in the gateway.
SMTP inbound FTRL and the spam dashboard share the process-local `setjoin-spam`
store gauges (#526); [model and batch contract](../../crates/spam/DOX.md).

Calendar byte parsing (`src/ics.rs`) re-exports the shared [calendar-format foundation](../../crates/calendar-format/DOX.md); SMTP and calendar HTTP/workers share Go parsing without a family dependency (#526).

SMTP6 wires deployment ClamAV, CAPE timeout/failure mode, anti-phish domain/name/cache
settings and pre-derived link-protect keys (`SMTP_LINK_PROTECT_KEY`/`_KEY_PREVIOUS`/`_VERSION`, never `JWT_SECRET`; `link_protect::TokenKeys::from_derived_env`) into the same native pipeline as
the toggle-ON Go replays. The shared live gate drives FTRL batch posture logging at
startup and on flips; this process-local observer stops with the runtime. Installer
SMTP sockets default ON on fresh and legacy upgrades; explicit empty addresses remain
operator disables. `scripts/test-smtp-systemd.py` qualifies actual rendered units,
Go-free enabled delivery and condemnation, capabilities, restart and posture logs.

F21 cancellation replay (#494) also pins the existing runner's ICS/VCF I/O
lifetime: upload phases subscribe to the job cancellation signal, drop the pending
upload future on cancellation and use the same reducer finalizer. The actor's
HTTP control remains admission only; no second request-side writer is added.

F21 multipart migration input uses `Orchestrator::store_upload` after an
actor-owned job lookup, with a 64 MiB total body bound. It keeps Go's ordered raw
ICS/VCF PUTs and ignored-error200 sizes; [self-service contract](../../crates/domains/identity/SELF_SERVICE.md) and signed S3 effect replays document partial persistence.

All eight exact migration registrations use the existing mailbox-less user proof
when the actor has zero owned mailboxes; other self-service admission stays strict.
IMAP testing reuses the shared DNS-policy connector under a 30-second total deadline,
rejects caller private exceptions and returns Go's sanitized result without a job.
The HTTP oracle and mixed-answer connector test pin the outbound boundary.

Owner-approved security fixes 2026-11-05 (#547, `tests/secfix13.rs`, `scripts/test-secfix13-mutants.py`):
every self-service JSON body (test-imap, migration start, webhook, app password, read receipt)
is capped at 1 MiB (`identity_self_service::BODY_CAP`, 400 over it); `tls_mode` `none` is refused
(400) on test-imap, and an IMAP start allows only `tls` or `starttls` (an omitted mode would inherit
`imap.defaults`'s); the runner also refuses `none` for any job that is not `self_service: false`
after defaults are merged (jobs created earlier included); webhook registration resolves the URL's host through the
route's `HostResolver` (system resolver in production, five seconds) and refuses a name that does
not resolve or answers any non-public address, where delivery-time `PublicOnly` still applies; and
the runner (`migration_runner::imap_config`) never lets a job that is not administrator-created
(`self_service: false`) inherit `imap.defaults`'s `private_hosts`/`private_cidrs`, so a user's
host override cannot reach an allowlisted internal host (an admin who wants users to reach a
private IMAP server migrates them through the admin API).

## Subtree rows and Go-proxy attribution (#472)

The wildcard-method rows `/`, `/api/` (F22), `/chat/` (F12), `/drive/` (F14), `/meet` and `/meet/` (F13) are
served by the catch-all alone (`Inventory::is_subtree_row`): a request only they claim never reaches a
concrete adapter that merely matches it. A rolled-back F15/F16 request arrives under `/api` and is claimed
only by the F22 `/api/` row; `Inventory::proxy_family` counts its Go forward under the owning family
(F15/F16), not F22. Tests: `tests/subtree_dispatch.rs`.
