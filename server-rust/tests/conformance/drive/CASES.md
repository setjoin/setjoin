# Drive/sharing oracle (#273)

The first F14 slice owns the ten directly registered sharing routes. Each
case sends HTTP through the gateway. Recording starts the covered, unmodified
Go executable; replay has no Go upstream. Actor identity comes from a signed
ES256 token. User and mailbox IDs are forced to differ; calendar IDs are normalized by resource type.

The overview tracer includes delegates and calendar grantees; the foreign
caller must see only their own records. Reads that ignore malformed query
parameters in Go must preserve that behavior. Writes compare business rows,
core audit rows, calendar state, notifications and repeated calls. Rust-only
operation receipts are excluded under the foundation contract.

Goldens are exclusive-create. No accepted divergences are authorized.

The floor has 30 cases (ten success, ten foreign-caller, ten invalid-input),
plus a repeated call for each mutator. Some malformed GET parameters are
ignored in Go; foreign self-service writes remain confined to the caller's
mailbox/default even when request fields name someone else. Every native
replay asserts zero total/F14 proxy counters. Mutants change actual HTTP
responses or the worker SQL execution seam. Recordings are never overwritten.

The catalog selects full-state V2 floors for all six mutators, preserving
complete mailbox/calendar rows and JMAP entity counters and journals. All
recorded additional cases are executable: inherited defaults/toggles, active
permissions/domain bounds/expired and dormant JIT grants, Go JSON decoding,
problem language, reason-required autonomous audits, query/iteration errors,
partial row delivery, transactional rollback and pagination/query decoding.

Unreachable Go error branches under the frozen front door/schema: handler
nil-user guards and duplicate admin permission guards (outer wrappers already
admit the same claims); typed Scan failures for NOT NULL correctly typed
canonical columns. These do not authorize skipping a query failure case.
The [covered-Go receipt](COVERAGE.md) records handler coverage; regenerate
it with `go tool covdata func` over the recorder's GOCOVERDIR.

Full-state fixtures explicitly seed `sending_quota_reset_at` to `2026-10-31`
(the recording date); the canonical `CURRENT_DATE` default otherwise changes
the fixture at midnight. Snapshot comparison remains strict; no recorded
observations or date fields are normalized away.
