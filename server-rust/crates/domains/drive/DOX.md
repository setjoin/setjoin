# Drive and sharing (F14, #273–#276)

One family crate; only foundation dependencies. HTTP registration lives in
`bins/gateway/src/drive.rs` and external paths are mounted at `/api`.
Frozen Go is the authority (ARCH-029/030); no accepted divergences.

## Disjoint inventory slices

- `golden-routes` (#273): ten direct `/me/sharing` and `/admin/sharing` registrations.
- `sub-router-a` (#274): core `handler.go` space/node/chunk/sync routes (19).
- `sub-router-b` (#275): content, branches, history, Office, exports, search,
  audit/WORM, activity, trash and native-token routes (29).
- `sharing-watch` (#276): ACL governance, folder admins, locks, as-of/watches
  and the `/drive/` catch-all (21); closes the shared-effect watch worker.

The catch-all forwards until the remaining handlers qualify. Sharing self-service
uses the explicit worker credential as frozen Go does, with every list scoped
to the sealed verified user. Mailbox IDs are independent of user IDs.

Tests: `setjoin-gateway --test drive_recorded`, using only the assigned disposable
database. The covered Go recorder is opt-in; ordinary replay has Go unset.

## Sharing adapter authority and effects

The ten sharing adapters are qualified and ON by default. Member routes bind actor and primary mailbox from shared ES256
admission. Admin routes resolve current active, unexpired governed permission
assignments and the narrowest domain override, matching frozen Go. Signed
non-admin permissions retain Go's behavior. Scope is not inferred from a
request-owned identity. Organization-wide sharing audit is permission-gated.

All six mutators call existing mailbox-delegate or sharing-default reducers
through `run_receipted_command` with family F14. The reducer owns business
rows, audits, calendar state and notifications; the foundation receipt commits
in that transaction. Unknown returns 503 and an opaque X-Operation-ID, never
success. No Go or canonical SQL source is changed and no reducer bypass is
introduced. Delegate re-grants/revokes are idempotent; repeated default clears
return Go's not-found problem. Self-service ignores spoofed ownership fields.

`drive_recorded` compares HTTP replies and committed rows, verifies the core
audit chain, and observes both fixture calendar notification channels. It
retains immutable early tracer recordings with explicit legacy normalization.
The unqualified first admin-list recording is retained under `historical/`;
its stale fixture rows are not admitted into the route catalog. Fixture
cleanup runs after errors and unwinding. Route status mutants affect actual
HTTP replies; family SQL mutants use owned private schemas and never alter
the observer or canonical database definitions.

List reads use the foundation's [iterated-read compatibility seam](../../pg/DOX.md#frozen-go-row-iteration-reads-273). Frozen Go ignores deferred Rows.Err in these handlers; their per-row JSON projections preserve delivered rows and ordering. Authority and single-row ownership lookups retain ordinary fail-closed reads.

## Qualified cutover

The route catalog binds each mutator's full-state V2 success, foreign-caller,
invalid-input and repeat recordings. These include complete fixture mailbox
and calendar rows, JMAP entity state/journals, all sharing rows, verified core
audits and both notification channels. Early immutable tracers remain useful
regressions. Recorded query-setup, deferred-row, partial-wire-row and audit
rollback cases preserve Go's error handling. No accepted divergences.

The executable installs `DriveRoute` with request and explicit worker DSNs.
All ten registrations are mounted at `/api`; inventory OFF overrides retain
that mount for rollback. `drive_dispatch` drives every route through the real
executable with Go unset, then tests global/inventory rollback and exact
forwarded requests. Normal replay asserts zero total/F14 Go proxy counters.

`drive_recorded` cuts the actual PostgreSQL COMMIT request and acknowledgement.
Both outcomes return 503/X-Operation-ID; the committed receipt resolves the
actual outcome without replaying a write. The after-COMMIT case compares the
full V2 Go business effects, audit and notifications; the before-COMMIT case
retains the seeded snapshot. Concurrent primary-mailbox changes defer the
untouched request to Go. Shared-authz unsupported token/guest/security cases
retain ARCH-027 forwarding pending identity #331–#333. Drive workers: #276
(watch) and #409 (maintenance, preview; see the gateway DOX).

Admin JSON reads preserve Go's first-value, 1 MiB decoder bound: a complete
value with a larger ignored trailer succeeds; an oversized value is rejected.
Both cases have frozen-Go HTTP/effect recordings.

`setjoin-gateway --test inventory_guard` checks the four disjoint slice
counts across all 79 F14 registrations and this ticket's exact ten route keys.

## Core transaction adapters (#274)

`src/core.rs` owns the core slice's scoped statements. The list-spaces GET
is a mutator: `drive_rust_list_spaces` provisions the personal space and
projects accessible non-chat/non-meeting spaces in the same transaction.
Its receipt is system metadata; all business effects stay reducer-owned.
Public HTTP recordings and replay live in `drive_core_recorded` and
`tests/conformance/drive/core/`; Go runs only in opt-in recording mode.

Core membership, tree, batch metadata and managed-client sync adapters bind the
verified user in the statement and call the existing Drive capability helpers.
All run under the user's transaction-local GUC. The core oracle also retains
full-state V2 observations for write qualification, including independent audit
chain verification; initial control-plane recordings remain immutable tracers.
No worker transfers in this slice; shared-effect Drive workers belong to #276.

The core HTTP module is `bins/gateway/src/drive_core.rs` (`drive::core`). Node
mutation attempts retain Go's separate committed name-rate transaction. Combined
rename/move calls `drive_rust_node_patch`; trash, restore and purge call their
canonical reducers. Chunk staging retains Go's unknown-length multipart sequence
through `S3Store::stage_drive_chunk`; authorization and the advisory lock precede
canonical copy, registration and the receipt share the command transaction, and
only temporary bytes are cleaned after Unknown. Preview streams ready manifests
without adding original-content gates or hash checks that Go does not perform.

The observer preserves audit sequence numbers, epochs, relationships and event
counts. It validates audit checksums before replacing them and normalizes only
generated identities/timestamps. `core/legacy-identities.json` declares exact
fixture-ID pointers in the immutable early patch/preview recordings; each rule
asserts its recorded original scalar. Multipart control XML normalizes equivalent
namespace/MIME serialization; object metadata, bytes and operation order remain
strict. The fake S3 peer independently verifies SigV4 and streamed part signatures.

Core policy/quota PATCH precedence and delegated `?folder=` membership reuse
canonical reducers. Admin listing checks live `drive.view` on the scoped app
pool before the explicit worker metadata read; WORM merge failures degrade to
zero as in Go. Preview `none` requests call `drive_preview_request`; audited
ready opens use `drive_rust_preview_audit` for Go's fifteen-minute dedup window.
Staging starts multipart before consuming the bounded body and aborts on read
or size failure. The S3 observer keeps a bijection of temporary keys across
repeated calls, including copy and cleanup. Empty streamed parts retain Go's
signed-header/zero-length transport shape.

The executable installs `CoreRoute` before the sharing adapter, sharing F15's S3
client. All nineteen core entries are qualified ON. Inventory rollback retains
`/api/drive` mounts and F14 attribution; the executable oracle also verifies the
global kill switch, unchanged forwarded requests and zero native Go counters.
The catalog binds each route's full-state floors and live changed-status mutant;
mutators include first/second call snapshots. Qualified metadata projections
retain the original Go recording SHA-256 and assert identical business data;
the replay reads and checks their row-effect projections too. PostgreSQL wire
cuts before and after the provisioning COMMIT verify 503/operation receipts and
unchanged versus committed Go business effects without replaying the command.
No accepted divergences. Existing workspace/root index lines already cover F14
slices and are intentionally unchanged.

Unconfigured preview storage declines before any audit write; its executable
adapter regression checks unchanged rows/notifications and the untouched Go
request. Fault fixtures are owned by the disposable database and restored even
on panic: app read grants, private worker views, renamed canonical functions,
and actor/space-scoped audit or chunk-registration triggers. Registration failure
after S3 copy preserves Go's temporary cleanup and leaves no committed chunk or
claim; business rows, rate attempts and notification order remain observable.

The recorded `preview-revoked-audit-state` deterministically revokes membership
inside the admitted metadata projection. Frozen Go then reads an empty manifest
in a fresh scoped transaction and still records the admitted open. Rust retains
both boundaries. The audit wrapper's admission flag is internal, set only after
that verified metadata read; it is never taken from request fields. Its default
keeps direct unadmitted calls capability-fenced, including the original foreign
pgTAP assertion. Fresh foreign HTTP requests fail before this path. This is Go
parity, with no accepted divergence or canonical-reducer bypass.

Admin fixtures use custom Drive-only roles, preserving the last-Super-Admin
protection. Repeated name mutations avoid the last fifteen seconds of a minute
before either request so both strict counter observations share Go's bucket;
counts are never normalized away.

## Sub-router B (#275)

The authored HTTP/effect case table lives in
`tests/conformance/drive-b/CASES.md` (workspace-relative). Native-token issuance
keeps forwarding pending identity #331's Postgres signing-key authority; this
slice must never create a competing signer or rotate stored keys.

`src/part_b.rs` contains the user-scoped reducer and projection boundary;
`bins/gateway/src/drive/b.rs` translates the sub-router HTTP surface. The
sealed actor supplies `app.current_user_id`, independently from the primary
mailbox. Existing reducers retain capability checks and atomic audit/journal/
notify effects. Mutators use the shared F14 receipt in the same transaction.
The private HTTP observer compares complete scoped table sets; HTTP arrays and
notifications keep their ordering. Initial tracer envelopes remain immutable;
qualification recordings carry explicit request metadata and separate write
row-effect envelopes. Fixtures remove alarms/grants before their restricted
space foreign keys, and preserve checksum/refcount verification.

The content byte plane is `bins/gateway/src/drive/content.rs`: capability and
chat-history-floor scoped metadata precede lazy, bounded S3 chunk streaming.
Ordinary original bytes retain the protected-classification export gate;
export consumption commits its one-use grant before streaming, exactly as Go.
The executable supplies the configured S3 store; sharing-only tests may omit it.
Office launch/export credentials use fresh 32-byte randomness, pass only their
hashes to reducers and expose plaintext only in the HTTP response. The oracle
checks returned credentials against those stored hashes and validates S3 SigV4.

Content view auditing calls `rust_drive_audit_view` after download admission,
preserving Go's snapshot-visible 15-minute dedup transaction. The byte plane
keeps Go's range-error CSP/disposition, performs HEAD storage reads, and keeps
uploaded JSON-looking bytes intact. CSV export streams 1,000-row pages through
the same audit reducer, formula-escapes data cells, stops after 50,000 rows,
and preserves Go's header-only 200 when a page fails or is forbidden.

GXP put/restore applies per-chunk S3 Object Lock after metadata commits. The
explicit worker credential records successful retention with a same-statement
accepted-version/actor guard. Storage or bookkeeping failure only changes
`wormPending`; committed versions remain saved. No process worker transfers
here (#276). Frozen Go performs its original post-commit bookkeeping too.

`drive_b_recorded` plants private-schema branch audit/notify/tenant/state
mutants and verifies that full-state comparison rejects each. Real PostgreSQL
COMMIT request/acknowledgement cuts return 503 with an operation ID; the receipt
resolves absent versus committed without replay. The committed branch effects
are compared with frozen Go; the absent case retains the original snapshot.
Query/permission faults, post-consume metadata failure and reducer audit
rollback have separate Go recordings. These scoped handlers check Rows.Err;
ordinary fail-closed reads are intentional here.

`drive_b_dispatch` drives all 28 transferred registrations through the real
executable with Go unset. Global/inventory rollback preserves method, mounted
path and body. The bundled inventory stays ON after oracle qualification;
normal replay asserts zero total/F14 proxy counters. Native-token remains OFF
and forwards unchanged pending identity #331. No independent signer is added.

Metadata and manifest reads intentionally use separate statement snapshots
inside `rust_drive_content_meta` (VOLATILE), matching frozen Go. A concurrent
membership revocation after metadata admission makes the content manifest
empty, while the admitted view is still audited. `content_revoked` forces this
with an owned advisory barrier; it compares the truncated response and zero
storage calls. Restore uses `rust_drive_restore_version` to retain the same
fresh source-manifest statement after its canonical save, atomically.

## Sharing, locks, watches and the drive-watch worker (#276)

`sharing-watch` serves 20 registrations (ACL node detail/subjects/grant/revoke/
inheritance/quick views, access requests, folder admins, file locks, as-of,
watches); only the `/drive/` catch-all stays forwarded. Gateway:
`bins/gateway/src/drive/acl.rs`; reducer boundary: `src/part_c.rs`. Every call
passes the verified actor first; every write is one receipted F14 command that
calls Go's own reducer (`drive_acl_*`, `drive_access_request`, `drive_file_lock`,
`drive_file_unlock`, `drive_folder_admin_*`, `drive_watch_*`). Go's separate
per-user ACL mutation rate check is its own receipted command, exactly as Go
commits it in its own transaction (429 + `Retry-After: 60`).

Parity quirks kept from frozen Go: ACL bodies are one JSON value (16 KiB, no
unknown fields, case-insensitive keys, null leaves a scalar unchanged) followed
by EOF; lock/watch bodies are optional, take the first complete value and ignore
unknown fields. Reducer JSON is passed through verbatim (`::text`), lock and
watch lists use Go's struct field order, as-of is `{"items":<compacted>}`.
BZ252/BZ253/BZ254/BZ256 map to 400/403/409 with class detail and no slug.
`feature.drive_access_governance` is read per request.

Oracle: `setjoin-gateway --test drive_c_recorded` (112 tests: V1 goldens in
`tests/conformance/drive-c/goldens`, one status mutant per route) and
`--test drive_watch` (seed-plus-one-tick worker goldens). Identities and
timestamps are canonicalized, `_checksum` is stripped after the audit chain
verifies. Recording: see the shared notes `drive4-oracle.md`.

`setjoin_drive::watch::DriveWatch` is the Rust `drive-watch` worker: LISTEN
`drive`, resolve the change/lock node, fan out to `drive-watch:<uid>` for every
watcher up the ancestor chain whose ops admit the event and who still holds
`read_metadata`; process-local 60 s dedupe. Enable with BOTH
`RUST_WORKERS_ON=drive-watch` and `GO_WORKERS_OFF=drive-watch` (missing Go-off
refuses startup); it needs `DB_DIRECT_DSN` and uses the worker DSN.

## Mailbox-less guest admission (#406)

User adapters accept live guest proof only through the shared program/route belt.
`session(actor)` returns user-only scope for a mailbox-less guest; scoped mirror
containment and every node/space membership predicate remain in force. User command
wrapper guards assert the verified actor rather than requiring a fictitious mailbox.
Members preserve real mailbox scope. The shared guest-domain corpus records native
preview lookup on a mailbox-less user; no S3 grant is manufactured by authentication.

Binding detail: receipted commands retain mailbox-compatibility `$1` and verified
actor `$2`. Plain `read_scoped` binds exactly its explicit arguments; Part B
`simple_read` uses actor `$1`, target `$2`, payload `$3`. Its audit-action catalog
therefore tests positive actor `$1`, even though its unused target is zero.
