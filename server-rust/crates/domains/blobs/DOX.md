# Blobs, attachments and recovery uploads (F16, #265)

`setjoin-blobs` depends only on foundation crates. Reducers remain the business
authority. The gateway translates HTTP and storage/scanner protocols; the sealed
shared-authz context supplies every actor. Mailboxes and users deliberately have
different IDs. Database rules R1–R4 apply to reads and writes.

## Selection and admission

The inventory contains ten F16 method/path registrations; GET also admits HEAD.
Go mounts blob/recovery registrations below `/api`; `/mail-attachment` is
root-pinned. Bare GETs remain SPA routes. `f16::F16Route` installs all ten in the
executable and HTTP dispatch tests. Inventory selection and the global kill
switch precede adapters. Missing storage leaves F16 forwarded; missing continuity
leaves recovery forwarded. No adapter forwards a consumed body or attempted write.

All ten bundled F16 registrations are ON by default after recorded replays and
family mutants qualified them. The global gateway kill switch or an inventory
OFF entry returns the whole request to Go; no mutator forwards after starting.

Normal routes use shared `authorize_request`/`authorize`: CSRF, ES256/JWKS,
current guest/session state, primary-mailbox/lifecycle and current governed admin
roles. Recovery additionally requires `feature.client_recovery_ingest` and the
storage/continuity prerequisites. The gateway admits a member before spending
its tighter recovery budget, then authorizes again before data access. Unsupported
credentials and unmirrored security gates forward untouched per ARCH-027.
JWKS and the S3 cache are shared across the installed family.

`DB_DSN` is the request credential. `DB_WORKER_DSN` (fallback `DB_DSN`) is a
separate pool for Go's recovery reducers and cross-mailbox-for-one-user reads;
there is no pooled `SET ROLE`. Every query still carries the authenticated actor
or a join deriving ownership from that actor. Signed device/account targets in
attachment tokens are revalidated against live authority before opening bytes.

## Transactions and storage

All writes call the existing frozen-Go reducer through `setjoin_pg::run_receipted_command`.
Its trusted `$1`–`$3` are mailbox, actor and operation ID; targets start at `$4`.
The reducer commits its data, audit, state and notification effects together.
A definite rollback uses Go's error classification; Unknown returns 503 with
`X-Operation-ID`, never success, compensation or forwarding. The shared helper inserts its opaque operation receipt in the same transaction;
`lookup_command` resolves Unknown without inferring success from dedup/no-op
state. No reducer or business audit metadata changes.

| HTTP operation | Reducer and external effects |
| --- | --- |
| Blob PUT | Upload random `tmp/upload/<32 hex>` object, verify measured SHA-256, call `blob_upload_account`, copy to canonical hash, remove only temp object. |
| Recovery begin | Verify receipt and inventory, call `mail_recovery_upload_begin`; atomic session/items, reservation budgets, idempotency and consent audit. |
| Chunk PUT | Write deterministic quarantine key, call `mail_recovery_upload_chunk_record`; row and both offsets are atomic. Exact replay writes nothing. |
| Item commit | Assemble verified chunks to an exclusive 0600 file, upload canonical object, call `mail_recovery_upload_item_verify`; remove quarantine keys only after acknowledged commit. |
| Finalize | Read verified raw item, require scanner, parse MIME, call `mail_recovery_artifact_quarantine`; artifact/session/ledger, audit and incident notification are atomic. |
| Abort | Call `mail_recovery_upload_abort`; delete returned keys after acknowledged commit. Chunk rows remain for cleanup, including failed deletes. |
| Fork consent | Call `mail_recovery_fork_consent`; locked artifact/device/affected-user or full-delegate authority, consent timestamp and audit. Repeat preserves the first consent. |

PUT uses a 100 MiB bounded exclusive 0600 spool, then streams the temporary
object. Hash mismatch, reducer rollback or promote failure removes only that
temporary key; canonical content is shared and is never compensated. The reducer
owns quota, charge and reclamation arming. `BLOB_RECLAIM_GRACE_MINUTES` defaults
to 1440 for nonpositive/invalid input; `BLOB_USER_QUOTA_BYTES` defaults to zero.
Cross-user dedup succeeds in Go and preserves the first uploader's charge.
`WORM_MODE` (`governance|compliance`, `WORM_RETENTION_DAYS` default 2557) arms Object
Lock retention on the canonical key after the upload (`blob_retention.rs`, Go's
`ApplyAll`): a refused retention is non-fatal (201) and joins a bounded process-local
ledger that the `blob-cleanup` tick drains. A configuration Go would refuse to start
with (bad mode or days) keeps PUT on Go pending the startup validation owned
by #415. There is no database retention marker in frozen Go: admission, charge
and reclamation remain the single `blob_upload_account` reducer call; retention
is the later S3 operation.

Chunks accept Go's canonical signed-64-bit Content-Range grammar and at most
256 KiB. Reads constrain session/item/chunk to the sealed uploading actor.
A known record rollback probes the same owned coordinate: only proven absence
permits deleting its object; a failed probe or unknown commit retains it.
Item commit checks ordering, contiguity, every chunk digest/length and assembled
digest/length. The temporary file is removed on return or cancellation.

Finalization repeats the actor-owned raw-item read. A terminal replay returns the
existing artifact without S3 or scanner I/O. Raw reads are bounded at 50 MiB.
`ClamAV` mirrors `nINSTREAM`, 4096-byte frames, a 30-second deadline and connection
cache, using TCP or Unix sockets. Scanner failure writes nothing; infection and
malformed MIME become rejected artifacts through the same reducer. The MIME
projection retains Go's raw transfer encoding, converts declared charset and
bounds text/HTML fields at 64 KiB. Parsed message dates follow Go's validity window.

Begin and fork JSON preserve Go's case-insensitive, last-field-wins decoding and null
string behavior, rejects unknown/trailing fields and bounds input at 1 MiB.
Recovery UUID parsing accepts Go's compact/braced/URN forms and rejects zero.
Go returns its shared BZ003 denial text for consent, generic 500 for foreign
abort, generic 400 for foreign chunk/commit/finalize, and BZ002/403 for terminal
abort. A repeated abort retains the first audit and terminal state.

## Read paths

Blob GET uses Go's actor-owned attachment/mailbox join and HR receipt requester,
approver, governed-role and super-admin arms. Unowned and malformed hashes are
404; Go performs no GET hash syntax validation. Cold objects smaller than 10 MiB
buffer once; repeat cache hits use ServeContent headers. The cache has Go's
10-minute TTL, 512 MiB bound and replacement accounting. Larger objects stream
with bounded reads and response-owned cancellation; HEAD emits no body.
All conditional and range forms are native (#419). Go emits no ETag here.
Its first small non-ranged read bypasses validators entirely (including failed
If-Match), while cached reads use unspecified modification time. Streamed reads
use S3 Last-Modified with Go's HTTP date layouts and validator precedence.
Single/suffix/open/multipart ranges, malformed and disjoint 416, HEAD, empty
objects, zero suffix and Go's excessive-range fallback have frozen recordings.
Sandbox and content metadata follow the recordings; response-owned S3 parts
open lazily and never require buffering an entire multipart representation.

The dedicated `/mail-attachment` bearer uses Go's HS256 kid and HKDF-SHA256
separation in shared authz. `JWT_MAIL_ATTACHMENT_SECRET` falls back to
`JWT_SECRET`; `JWT_MAIL_ATTACHMENT_PREVIOUS_SECRET` verifies the retiring key.
Every request repeats origin JTI/family/watermark, fingerprint/platform/wipe,
effective offline-policy generation and blob ownership checks. Responses retain
Go's immutable cache policy, strong ETag, attachment disposition and sandbox.
Live S3 size is checked independently of the shared small-object cache; a missing
object or size mismatch returns Go's plain 404 before immutable headers are set.
Conditional and range reads are native (#419), including strong/weak ETag lists,
validator precedence, If-Range, single/suffix/open/multipart ranges, HEAD and 416.
Go intentionally supplies no modification time on this immutable route: date
validators do not replace its strong hash ETag. Authority checks precede every
conditional/range response, including 304. Multipart boundaries are independently
validated 60-hex values before golden normalization; S3 parts open sequentially as
the response is consumed and cancellation drops the current read. Delegates are native through `setjoin_authz::mailbox::can_read` (#419).
The request credential sets authenticated user scope for FORCE-RLS grants; read,
send_as, send_on_behalf and full_access admit the exact selected shared mailbox,
while manage_calendar alone does not. Each request rechecks grants, so revocation
denies the next range or conditional read before any bytes or 304. Own attachments
remain readable across the actor's mailboxes even with another account selector,
as Go does. Normal `/api/blobs` retains its separate owner/HR receipt predicate.
JMAP HTTP upload/download/recovery reuse the same foundation read gate.
The standard verifier never accepts this narrow token on ordinary routes.

Recovery incident listing calls `mail_recovery_user_incident_list` with the
sealed user on the worker credential. Go ignores an invalid limit query.

## Recovery cleanup worker

`recovery_worker.rs` runs immediately and hourly, independent of the intake flag.
It calls `mail_recovery_uploads_expire`, selects Go's oldest 256 terminal chunks
on the worker credential, deletes their exact S3 keys and acknowledges through
`mail_recovery_chunk_cleanup_complete`. Delete failure leaves the row for retry;
failed acknowledgement can repeat the idempotent deletion. Shutdown cancels I/O.
Enable `RUST_WORKERS_ON=mail-recovery-cleanup` and stop Go's shared-effect copy
with `GO_WORKERS_OFF=mail-recovery-cleanup`. Process-local Go caches stay running.

S3 uses `S3_ENDPOINT`, `S3_BUCKET` (mailblobs), `S3_ACCESS_KEY`, `S3_SECRET_KEY`,
`S3_SECURE`, and corresponding `MINIO_*` fallbacks. Missing/partial credentials
are anonymous, matching Go. Scheme-less loopback defaults to HTTP; remote
endpoints require TLS. Scheme/secure conflicts fail startup. Private CAs use the
system trust store; bucket-region discovery and signing follow Go's MinIO client.
Recovery readiness requires `CONTINUITY_SIGNING_KEY_FILE` (clean absolute path,
one Ed25519 PKCS#8 PEM block) and `CONTINUITY_SIGNING_KEY_ID`. The receipt verifier
uses Go's field order, sorted blob IDs and empty-blobs-null canonicalization,
180-day maximum age plus five-minute skew, account/eligibility/artifact bindings
and complete bounded inventory. `CLAMAV_ADDR` configures finalization's scanner.

## Verification and recording

[CASES.md](../../../tests/conformance/blobs/CASES.md) maps every registration to
its corpus. `tests/conformance/route-catalog.json` binds exact replay selectors,
row recordings, sources and mutants to the T3 gate. Every route has success,
foreign and invalid input; every mutator has repeat and row effects. PUT's
cross-user case records Go's successful shared-content dedup, not a denial.

`tests/common/go_oracle.rs` launches one named disposable frozen-Go container per
recording, with only the supplied disposable database, fake JWKS, S3 and optional
ClamAV. It requires `GOFREE_RECORD_GO_BINARY`, full `GOFREE_GO_SOURCE`,
`GOFREE_RESOURCE_LEDGER` and `GOFREE_GO_COVERAGE_DIR`. Shared-effect workers are
stopped while LISTEN/process-local caches remain. Generated continuity keys and
containers are removed on drop. Ordinary replay never starts Go. Existing
goldens are immutable; supplemental qualified PUT files preserve the original
observations and add request/audit/notify plus row-effect envelopes.

The S3 peer independently verifies SigV4 and every Go signed streaming chunk,
including the terminator, before comparing keys, content type, digest and size.
Worker HTTP recordings also compare exact signed DELETE envelopes, region and
anonymous behavior. Finalization independently reads ClamAV frames.
Complete recovery rows, core audits, mailbox state and commit-ordered NOTIFY are
observed; generated IDs/timestamps are checked before declared normalization.
Only the owning disposable fixture is removed; teardown releases message locks
before deleting mailbox/user together for the deferred primary-mailbox invariant.

`f16_dispatch.rs` exercises all ten registrations with Go unset and zero proxy
count, and the global kill switch with identical requests. Each route has a real
changed-status adapter mutant. Family mutants shadow a reducer in a disposable
schema to remove audit/notify or add two mailbox state bumps; the tenant mutant
makes the worker mailbox predicate tautological without changing token identity.
They must fail the same recorded comparison and drop their schemas afterward.

Integration qualification runs `python3 scripts/check-gofree-oracle-adequacy.py
--execute --coverage` and `bash scripts/check-server-rust.sh`. Worker tasks run
the affected targets and default guards with assigned full-schema owner/app
DSNs, `REQUIRE_DB=1`, task-owned target and two Cargo jobs. Never treat a DB skip
as pass.

## Security (#531 F3)
Security (#531 F3, owner-approved 2026-11-06): `blob-cleanup` checks at startup (`BlobCleanup::worker_bypasses_rls`, `pg_roles.rolbypassrls OR rolsuper` for `current_user`) that the worker credential is not filtered by row security, logs and refuses to run otherwise (its global `ref_count`/`messages.raw_ref` re-checks must see every tenant). `DB_WORKER_DSN` (or `DB_DSN` when unset) must therefore be `setjoin_worker`/BYPASSRLS. A transient check failure retries each tick. Mutant `blob-cleanup-no-bypass-check`; test `blob_cleanup_refuses_a_credential_without_bypassrls`.

Foundation receipts / protected audits and the WORM retry handoff qualification (#419): [RECEIPTS.md](RECEIPTS.md).
