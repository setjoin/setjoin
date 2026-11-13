# setjoin-jmap — DOX (#214)

Parent: [server-rust/AGENTS.md](../../../AGENTS.md). Moved verbatim from the parent (#385).

Rust mail commands on
`setjoin-pg`. `set_message_seen` (`SetMessageSeen`, sheet `MARK_SEEN`):
`run_command`: one scoped transaction whose body is one `jmap_email_set_update` call
(mailbox from the auth context; the reducer's `$seen` effects) with the
Go call site's `email_set` actor audit row in the same statement (CTE;
a second statement held the mailbox lock one round trip longer than Go
at c=8), all atomic; a reducer per-item error commits as Go's
`notUpdated` entry (owner direction
2026-10-29, #224: the per-statement version re-planned partitioned-table
statements every call, ~11-14 ms/command). A no-op read writes only the
audit row (#219). `Unknown` returns the operation ID, never success; the ID is in the
audit row (`details.operation`) and `lookup_set_seen` uses the shared lookup
scoped to the authenticated actor and mailbox (owner decision 2026-10-29).
Contract: `src/set_seen.rs`. `query_email_list` (#216): the
`jmap_email_query` listing for one tag as one static SELECT in a
`READ ONLY` scoped read — writes nothing (no audit, state, journal,
push). Contract: `src/email_list.rs`.

`email_changes` (#315, JMAP1): `Email/changes` as one static
`SELECT jmap_email_changes($1,$2,$3)::text` in a `READ ONLY` scoped read; the
reducer owns the journal collapse and cap. SQLSTATE `BZ011`/`BZ006` map to
`ChangesError`, anything else is `Other` (the gateway forwards to Go).
Writes nothing. Contract: `src/email_changes.rs`.

`email_get` (#315): `jmap_email_get` plus the `email_get` audit row (details NULL as
Go) in one statement inside `exec.run` (no receipt row: a read that is not served
forwards to Go). Encrypted mail (`cryptoType = smime-encrypted`) writes nothing and
returns `Encrypted` so Go decrypts. Contract: `src/email_get.rs`.

`email_query`/`email_set`/`failure` (#315): `Email/query` passes filter/sort JSON to
`jmap_email_query` in a `READ ONLY` read; `email_set` is one update-or-destroy reducer
statement plus the `email_set` audit row (`run_command`, audit receipt as set_seen);
`failure::classify` is Go's `mapReducerErr` for deterministic database answers.

`email_batch` (#315): `Email/recover`/`Email/purge` as one reducer call each in
`run_receipted_command` (`jmap`/`email.recover`, `jmap`/`email.purge`; no mailbox audit
row, as Go) and `read_paged` for `Email/deletedQuery`/`Email/bundles`.

Connection state (#318/#418): `connections::ConnectionRegistry` is the shared
process-local WS/SSE registry. Register only verified user and resolved mailbox
IDs, after channel admission; the `chat` bit controls presence. A connection
guard removes its entry on drop. `evict_user`, `evict_mailbox` and `shutdown`
remove entries and invoke close callbacks outside the registry lock. Clone the
same registry into SSE (#319) and Chat presence; never create a handler-local
online map. Shutdown permanently closes registration; late upgrades invoke their close callback immediately. The live-socket oracle exercises multiple sockets, targeted user/mailbox eviction and front-door shutdown.
`GET /chat/presence` (#318's scope amendment) is a user-domain projection:
members retain Go's coarse directory-wide read; guests see only channel
co-members, with outsiders and nonexistent IDs uniformly false. Guest membership
reads use `read_user_scoped`, including for mailbox-less accounts. Raw trimmed
numeric response keys are preserved. Bad query-escape/semicolon pairs are
discarded as Go's URL.Query does; invalid decoded IDs produce the shared problem.

F18 slices (#315-#319, `JMAP_SLICES` in `scripts/check-gofree-route-inventory.py`):
`email-methods`, `mailbox-thread-other`, `submission`, `websocket-push`,
`sse-event-source`. `POST /jmap` is owned by `email-methods`; the method
families on it are served per command and unclaimed shapes forward to Go.

JMAP1 admission (#315, 2026-11-04): `feature.rust_mark_read` and
`feature.rust_inbox_list` are retired pilot switches. Their OFF/ON values do
not change native Email/set or Email/query service. The gateway authorizes
once through `authorize_request`, retaining security gates and bounded reads.
`tests/jmap_db.rs` compares both flag values against frozen-Go reply templates
and exercises deferred encrypted Email/get (#328) without Rust audit or writes.
The gateway's coarse budget likewise uses `EdgeLimit::for_front_door` and
Go's captured 429 bytes under every flag value; the legacy flag-reading
constructor is removed. Recording explicitly uses a proxy-only route table
([harness](../../../tests/conformance/jmap/README.md)), independent of flags.
Seen/List share the general adapters' native `accountNotFound` denial for an
account without a delegate grant. Delegated accounts still require the
unported delegated-method policy. The flag matrix checks both query adapters'
cross-account denials against frozen-Go bytes.

JMAP4 (#318) WebSocket transport is ON in the gateway's `src/jmap/push.rs`.
`push_state::tokens` reads the six mailbox/satellite cursors in read-only scoped
transactions; mailbox ownership is the verified actor/mailbox pair. Query
failures retain Go's `unavailable` sentinel independently for each lookup.
The transport coalesces mailbox notifications for 20 ms, sends control
payloads before StateChange, and reads database cursors rather than payload state.
One shared direct-DSN dispatcher has independent bounded state/revoke/raw rails;
full rails drop new notifications as Go does. No LISTEN uses the request pool.
The immutable live-socket oracle is [push/README.md](../../../tests/conformance/jmap/push/README.md).

The WS batch envelope uses the qualified HTTP command executor with sealed
push authorization; Go's push seam has no HTTP CSRF or lifecycle middleware.
Core/echo, typed request errors and ordered result references are native.
Methods/shapes not claimed by the merged command adapters, encrypted reads
and submission MIME preprocessing (#328), delegated invocation policy (#316)
and continuity helpers (#316) forward as a whole WS application frame **before any Rust command runs**. The handoff
uses Go's WS seam, not HTTP POST, and counts as an F18 Go proxy. The shared classifier includes the Mailbox, Identity, Blob and
submission adapters. Preflight checks submission draft attachments before any call writes;
WebSocket responses accumulate createdIds across set methods. Never retry a partly
executed batch. Qualified Email commands retain their existing reducer,
receipt and audit contracts; the transport adds no business-data writer.

## Mailbox methods (#316, JMAP2)

`mailbox::read` calls frozen Go's Mailbox/get, query, changes and queryChanges
reducers in authenticated read-only scope. Malformed IDs remain notFound;
get-all, ignored properties, the unused changes maxChanges and queryChanges'
empty-state default are Go parity. Responses larger than 2 KiB use Go's
chunked HTTP/1.1 framing via `jmap::reply::response`.

`mailbox_set::set` calls `jmap_mailbox_set_batch` once through the foundation
receipted executor (`jmap` / `mailbox.set`). The wrapper preserves Go's atomic
phase order and merge, using the existing effect-owning reducers. Go writes
no mailbox audit; the Rust receipt is internal commit-recovery metadata.
Unknown returns the operation ID, never success. Request accountId is only
compared; database scope and actor always come from verified auth.
Oracle: gateway `tests/jmap_other.rs`, shared case/record runner in
`tests/jmap_email_oracle/`, frozen-Go goldens in `tests/conformance/jmap/`.

Thread/get, Thread/changes and SearchSnippet/get (#316) use the same scoped
read adapter and Go reducers. Thread/get's absent-id serverFail is preserved;
state tokens validate before calls, and BZ040 exposes only Go's allowlisted
public validation message. Foreign thread/message IDs remain notFound.

## Core and Blob metadata (#316)

Core/echo reflects arbitrary JSON under the core capability (including null or
a foreign accountId); it reads/writes no user data. Blob/get, copy and lookup
use `blob::owned` on the explicit worker credential, with actor ownership in
the attachment join across owned mailboxes. Account strings are echoed, not
used as authority. Blob/copy writes nothing in frozen Go. Empty errors omit
detail through the common gateway `problem::jmap` encoder.

`JmapServices` supplies that worker executor; the executable always installs
it. Native replay scrapes HTTP metrics and requires both total and F18 Go
proxy counters to remain zero. The shared single-call argument adapter handles
unique ASCII struct field names without case, preserving raw create/update
JSON. Batch/result-reference execution and full envelope/client-id/argument
grammar (including duplicate/non-ASCII struct-field keys) and deferred delegated method admission belong to #318's shared
HTTP/WebSocket execution engine; these shapes forward whole before effects.
Identity methods use the submission capability and are ported here in #316;
EmailSubmission stays with #317.

## Discovery and HTTP peripherals (#316)

`session` supplies the discovery document's scoped capability/configuration
reads and actor-owned delegate projection. Native session registration calls
`jmap_session_device_register` through a receipt (`jmap` / `session.device`).
The SQL adapter reproduces frozen Go's mailbox-only `CallScoped` GUC posture:
under `setjoin_app` the underlying user_devices RLS rejects the call and the
session falls back to base capabilities; before the native-RLS flip, the owner
credential permits registration. The function-local GUC restores on return.
This observed Go fault is preserved, not repaired here. Unknown registration
returns 503 plus the operation ID, never a success or a proxy retry.

HTTP upload calls `blob_upload_account` through `jmap` / `blob.upload` receipts,
with measured bytes, authenticated actor, configured grace/quota and no new
mailbox audit. Staging precedes accounting; canonical promotion follows commit.
Download reads immutable metadata and actor/delegate attachment ownership on
the explicit worker pool; invalid account selectors retain Go's own-blob path.
The gateway supplies Go's untrusted-content headers, range framing and ETags.

Raw recovery is a GET mutator: `continuity_recovery_receipt_context` commits
server-global wall-clock/boot metadata under `jmap` / `recovery.raw`, then the
handler serves eligible exact MIME bytes (inline reference or bounded S3 read).
Account admission mirrors Go's primary/delegate precheck and scoped reducer;
the global continuity row has no tenant owner. Unknown never retries or returns
success. Recovery is hidden without the existing product feature and a valid
operator Ed25519 PKCS#8 key; ring validates the key, rustls decodes PEM, and the
process retains only its boot UUID for this endpoint.

Attachment-transfer mint writes no database rows. The native-device lookup
binds authenticated actor/fingerprint/platform; the authoritative policy reducer
supplies the exact JSONB text whose SHA-256 is the generation. Blob scope is the
same actor/delegate attachment join as download. `jmap::transfer::Signer` uses
ring HKDF-SHA256 and HMAC-SHA256, salt `mailserver-mail-attachment-token-v1`,
master `MAIL_ATTACHMENT_TOKEN_SECRET` falling back to `JWT_SECRET`. It copies
only Go's allowed parent identity/device/family fields, derives origin JTI/iat
from verified admission and mints a fresh UUID for 300 seconds (Go does not cap
this by parent expiry). The `/api` mount includes this F18 JSON API and the submission REST actions.
Tests verify signatures with a fixed KDF result captured from Go, validate live
binding/TTL/freshness, then normalize generated token fields. Common admission
shapes not yet handled by authz remain owned by #331; no new rollback switch.

Identity/get and Identity/changes are JMAP2 (#316) submission-capability reads,
not EmailSubmission (#317). Go ignores their account selectors; queries still
bind the verified actor, with the same request/worker credentials as Go. Get
lists primary, owned aliases and send-as/full-access delegates; changes uses
the same users.updated_at Unix-seconds token. Identity/set uses the shared
SetRequest adapter and `jmap_identity_set_batch` receipt (`jmap` / `identity.set`)
for atomic create/update/destroy order. Existing reducers own alias ownership,
user state and per-item failures. No new mailbox audit. SQL cancellation/fault
answers are native serverFail for these JMAP2 methods, never a Go retry.
EmailSubmission (#317): `src/submission.rs` calls the frozen-Go reducers.
`get`/`query` use authenticated `read_scoped` reads (nil/empty IDs mean all;
malformed IDs go to `notFound`; query filters remain unused as in Go).
`cancel` calls `message_cancel` with the authenticated mailbox; `set` calls
`jmap_email_submission_set` with authenticated mailbox and actor on the worker
credential for local recipient fan-out. Each mutation uses
`run_receipted_command` (`jmap` / `submission.cancel|submission.set`), preserves
reducer-owned state/journal/notify, and writes no extra mailbox audit row.
Unknown commits return the operation ID for scoped `lookup_command`; they never
report success or retry through Go. The gateway mirrors Go's top-level
`createdIds` accumulation. Signing/encryption preprocessing stays with #328;
a mixed map needing it forwards whole before any write. The generic JMAP
multi-call/reference and delegated-account policy remains the #318 boundary.
HTTP/effect recordings: gateway `tests/jmap_submission.rs`, shared runner
`jmap_email_oracle`; full `scheduled_actions` rows join the mailbox row diff.

REST submission actions (#317): `undo` calls `undo_send` on the request pool;
`recall_source` reads only mailboxes owned by the verified actor, checks Go's
sender/alias and five-minute gates, then `recall` calls `recall_message` on the
worker pool. The selected recall mailbox comes from that owner-filtered lookup,
including a secondary owned mailbox. Receipt names are `submission.undo` and
`submission.recall`. Recipient writes, recall audit and pushes stay in the
existing reducer transaction. Go's Message-ID-wide undo queue deletion, missing
undo expiry check and recall's absent Sent predicate remain frozen parity;
the HTTP/effect cases explicitly capture them.

The REST adapter is `src/jmap/submission_actions.rs` in the gateway, mounted at
`/api/messages/{id}/undo|recall`; inventory/golden paths retain Go's registration
paths without `/api`. Problems use the gateway's shared Go-ordered encoder.
`submission_input.rs` mirrors the anonymous Go request structs (ordered folded
keys, nulls and typed errors). Its separate raw encrypt/sign probes decline a
whole mixed map requiring #328, including Unicode-folded flag spellings, before
any write. Generic envelope/reference/delegate handling remains #318 and shared
identity admission remains #331.

Qualification (#317): all four submission commands and both REST registrations
are ON in the bundled inventory and catalog, with success, tenant denial, invalid
input and each write's repeated-call/effect recordings. Native replay uses the
bundled decisions with no override and no Go upstream. Six changed-status and
four per-write no-notify mutants are rejected; recall also rejects a removed
audit insert. The existing F18 audit/tenant/double-bump family mutants remain.
COMMIT-loss tests cut the submission worker connection before COMMIT and after
its acknowledgement: both replies stay Unknown, scoped lookup resolves the
receipt, and effects are absent or equal one Go request. No rollback tests or
new kill switches were added (owner decision 2026-11-04).

Submission MIME boundary (#317): the same #328 preprocessing pass also assembles
plain attachments, independently of S/MIME flags. Before any write, the gateway
extracts Go's ordered/folded emailId probe and `has_attachments` checks only the
authenticated mailbox in `read_scoped`. A draft requiring assembly or an ID that
would fail the helper's draft load forwards the entire map to #328 unchanged.
Typed probe failures remain reducer-owned as Go does. The helper fake tests both
attachment-only mixed maps and invalid load IDs, with zero native effects.
SSE (#319) is ON in gateway `src/jmap/sse.rs`, cloning the configured WebSocket
service's commands, hub, registry and client budget. The executable installs it
beside WS and presence. Oracle: [SSE recordings](../../../tests/conformance/jmap/sse/README.md).

SSE lifecycle (#319): state and raw application notifications use the same
`PushHub` direct connection and bounded rails as WS. `EventSourceRoute::new(&ws)`
clones its atomic client counter as well as the registry, so the default 1000
budget covers both transports. The response body owns the permit, connection
and denylist session guards; body drop aborts the task. Registry and session
callbacks cancel a blocked writer; callbacks never run under the registry lock.

SSE takes a Bearer credential before a cookie, applies origin policy only to
cookies, and uses the sealed shared push verifier (access token, scope, guest
satellite and revocation belts). Its primary mailbox is resolved by verified
user ID; guests have none. Entitled guest app rails retain Go's topology;
ordinary members retain Go's unconditional app rails. Every 300 seconds the stream
rechecks expiry, admitted guest app entitlements and admitted Drive admin
permissions. These are read-only operations and create no business, audit,
receipt, journal or notification effects.

The SSE oracle also retains Go's HTTP write deadline of 120 seconds: an idle stream can
remain open past it, but its next write or final chunk fails. An authorization recheck at 300 seconds
close therefore has truncated chunk framing. Native output preserves that
termination rather than silently extending the lifetime. The periodic case
records Go's real 300-second window and observes an idle guest through HTTP presence;
native replay waits token expiry then advances Tokio's clock. Exact raw frames,
clean versus abrupt termination, unchanged complete rows and proxy-zero checks
remain observable. No new accepted divergence is introduced.

SSE qualification (#319): 52 immutable Go recordings and four native seam
checks cover authentication, parameter parsing, cross-user isolation, raw bytes,
notifications, guests, scope-specific revocation, periodic authorization, mixed
WS/SSE presence, the default 1000-client budget, write deadlines and HEAD.
The catalog binds a live status mutant; native cases require bundled ON state,
zero Go proxies and unchanged complete rows. Main-executable replay checks the
same recorded initial frame. The public registry test verifies user/mailbox
eviction, untargeted survival, body-drop cleanup and latched shutdown.
Legacy HS256/SM2 verification uses the configured shared keys (#331/#333);
stream-specific admission remains on the sealed push verifier.
No new kill switch or rollback test was added. F18 closure is checked on the
integration branch: #469 (JMAP1B) owns download, attachments.zip, unsubscribe
and focus, satisfying the closing criterion for #319 by named ownership.
No SSE worker is outstanding.

## Mailbox-less discovery (#406)

The gateway's JMAP HTTP adapter admits active guests through shared user proof.
Its exact discovery branch returns Go's minimal guest capability object before
constructing mailstore authority. Ordinary mail commands keep real primary
mailboxes; guest route containment remains the front door's shared belt.
`authz-defer/guest-session.json` records explicit and stripped-account claims.


Shared HTTP mailbox read admission (#419) delegates to
`setjoin_authz::mailbox::can_read`: authenticated user scope for FORCE-RLS grants,
per-request revocation, primary mailbox fast path and the same four mail grants.
Blob ownership remains actor-or-exact-admitted-mailbox; no account string becomes
actor authority. Download/upload/raw-recovery HTTP oracles cover the shared gate.

## Message REST routes (#469, JMAP1B)

`src/messages.rs` holds the statements of `/api/messages/{id}/{focus,download,attachments.zip,unsubscribe}`.
Ownership is always `mb.user_id` of the verified token (R1-R3), on the worker credential
because a message may sit in any of the user's mailboxes (Go's `ResolveOwnedMessage`).
`set_focus` is one receipted statement (`jmap/message.focus`): the owner join, `received_at`
and `m.mailbox_id` feed `set_message_focus` in the same statement; the gateway first resolves
the owning mailbox only to pick the command scope. `record_unsubscribe` writes the
`unsubscribe_newsletter` audit row and the `user_sender_list` block in ONE statement
(`jmap/message.unsubscribe`); Go issues them as two best-effort statements. The id stays text
and is cast by PostgreSQL (pgx hands Go's string to an int8 parameter), so any error reads as 404.

Security (#476/#470/#478/#469, owner-approved 2026-11-05): `undo_send` and `jmap_email_purge` are mailbox-scoped (reducers `message_lifecycle.sql`, `jmap_email.sql`); the `/jmap/download` ownership check precedes the blob metadata read (a foreign and an unknown hash both answer 404); the Mailbox/set system-tag precheck is mailbox-scoped; `attachments.zip` renames `.`/`..` entries to `attachment`, refuses more than 200 attachments (413) and stops at 1 GiB. Tests `secfix6.rs`, mutants in `scripts/test-secfix6-mutants.py`.
