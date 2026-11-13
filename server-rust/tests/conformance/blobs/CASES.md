# F16 case ledger (#265)

Frozen Go has **10 method/path registrations**, rather than the issue title's
14; GET registrations also accept HEAD. Blob/recovery routes mount below `/api`;
`/mail-attachment` is root-pinned. Bare GETs are SPA routes. Go controls whenever
OpenAPI differs.

Sources: `internal/blob/handler.go`, `internal/jmap/attachment_transfer.go`,
`internal/mailrecovery/{handler,quarantine,verify}.go` and their existing reducers.
The catalog binds exact HTTP replay selectors, immutable Go observations,
mutator row effects and handler sources to the T3 gate.

| Registration | Go corpus / native HTTP replay |
| --- | --- |
| GET `/blobs/{sha256}` | Own, foreign, invalid hash, repeat/cache, HEAD, missing storage, escaped hash, 10 MiB stream; conditional cold/cache/stream semantics, HTTP date layouts, If-Range, malformed/disjoint/suffix/open/multipart/empty/zero/excessive ranges; status, ignored-validator and tenant-filter mutants. |
| PUT `/blobs/{sha256}` | Success, cross-user dedup, invalid hash, repeat, `WORM_MODE=governance|compliance` retention (one `PUT ?retention` with mode and 30-day retain-until) and a refused retention (Go's minio client makes ten attempts; PUT still 201; the Content-Type of the retention request is not compared: rust-s3 always sends one); accounting/charge/reclamation rows, signed temp upload, canonical copy and temp delete; status mutant. Qualified envelopes supplement the immutable first recordings. |
| GET `/mail-attachment/{sha256}` | Scoped bearer success, foreign blob, mismatched path hash; strong/weak ETag and validator precedence, zero-modtime date conditions, If-Range, single/suffix/open/multipart ranges, HEAD and 416; status mutant. Checks origin session, device, effective policy generation and ownership before bytes or 304; all four mail grants, calendar-only/no-grant/wrong-actor/wrong-account denial, live revocation, delegated range/304 and own-blob selector fallback are qualified by #419 on the app credential. |
| GET `/recovery/incidents` | Own, foreign, empty and ignored invalid limit; status mutant plus member-budget/guest-forwarding and API-mount checks. |
| POST `/recovery/uploads` | Signed receipt success, foreign actor, invalid session, repeat, mixed-case names and duplicate/null fields; complete inserted session/item rows and consent audit; status mutant. |
| PUT `/recovery/uploads/{sessionId}/items/{itemId}` | Success, foreign session, invalid range, replay; exact offsets, inserted chunk and signed S3 bytes; status mutant. |
| POST `/recovery/uploads/{sessionId}/items/{itemId}/commit` | Success, foreign session, invalid UUID, repeat; canonical/quarantine storage and complete row effects; status mutant. |
| POST `/recovery/uploads/{sessionId}/finalize` | Success, foreign session, invalid UUID, repeat; complete artifact, session/mailbox state, core audit, notification, S3 read and ClamAV frames; status mutant plus no-audit, no-notify and double-bump mutants. |
| DELETE `/recovery/uploads/{sessionId}` | Success, foreign, invalid UUID, terminal and repeat; session/item/chunk rows, audit and S3 delete; status mutant. |
| POST `/recovery/artifacts/{id}/fork-consent` | Success, foreign, invalid UUID, repeat and mixed-case duplicate fields; full recovery/mailbox row effects and audit; status mutant. |

Parity details: blob PUT has no tenant-owned target to deny; Go admits another
user's dedup without moving the first uploader's charge. Go ignores invalid list
limits; returns generic 500 for foreign abort and generic 400 for foreign
chunk/commit/finalize; terminal/repeated abort returns BZ002/403 and preserves the
first audit. No accepted divergence was invented and no golden was overwritten.

The executable and `f16_dispatch.rs` use the same complete family registration.
Bundled ON inventory tests run with Go unset and zero proxy count; the kill
switch forwards all ten unchanged requests. Inventory selection still controls
native acceptance. Unsupported token/security/conditional/delegate paths retain
Go per ARCH-027; configured WORM PUT is served by `blob_retention.rs` (#301). Missing continuity/storage retains the recovery control plane.

All ten bundled F16 registrations are **ON**. Every mutator uses the foundation
receipt helper with its existing reducer name; committed/no-op attempts receive
an opaque receipt in the command transaction. Unknown returns its operation ID
and resolves through `lookup_command`, without target-state inference or replay.
The JMAP pilot's audit receipt is unchanged. Protected audit keys use the named,
transaction-local foundation allowlist from trusted deployment configuration.

Declared row-effect normalization rule: **exclude
`public.rust_operation_receipts`**. It contains only Rust-owned operation UUID,
static family/command and commit timestamp. The explicit F16 business-row
snapshots omit this system metadata table; every existing business row, audit,
state and notification comparison remains strict. No golden was rewritten.

The cleanup task has seeded and actual S3 HTTP one-tick Go recordings, executable
replay on a worker credential, exact-key acknowledgement, anonymous/region/private
CA tests, and cancellation. Configure `RUST_WORKERS_ON=mail-recovery-cleanup` and
`GO_WORKERS_OFF=mail-recovery-cleanup`; keep process-local Go caches running.

#419's HEAD wire captures remain immutable. Their `*-head-qualified.json`
companions record the nominal GET registration with `external_method: HEAD` for
T3. Each catalogued observation has its own exact replay selector.


#419's `worm-retention-retry-worker.json` is a separate worker seam: real Go PUT
produces the retry entry, four real cleanup ticks observe 403/403/200 then no
more retention calls. Replay uses native PUT, worker ticks, row/audit/NOTIFY
comparison and an independently verified S3 peer; a missing-tick mutant fails.
The #301 HTTP PUT goldens retain ownership of complete response headers.
