# F07 MAM HTTP oracle (#311)

`bins/gateway/tests/mam.rs` sends requests through the HTTP front door, recording
frozen Go once and replaying Rust with no Go upstream. Independent fixtures and
request plans are in `mam_oracle/plan.rs`. The oracle compares byte-exact response
bodies, headers, committed policy/event rows, audit and `device_policy` NOTIFY.
Only generated identities and timestamps are normalized. Existing goldens are
rechecked rather than overwritten.

Run `cargo test --locked -p setjoin-gateway --test mam -- --test-threads=1` with
the assigned disposable DB, owner/app DSNs and `REQUIRE_DB=1`. Serialize with
other F07 suites: fixtures temporarily replace global policy configuration.
Recording uses `GOFREE_RECORD_GO_BINARY`, `GOFREE_GO_SOURCE` and optionally
`GOFREE_GO_COVERAGE_DIR`, as in the [MDM oracle](../devices/README.md), with owned
container prefix `gofree-devices2`. No accepted divergences.

`goldens/initial-plans/` retains immutable observations captured during corpus
authoring before the expanded request plan was installed. Their labels describe
the intended scenario, while the actual requests used the old success plan.
They are retained for provenance; qualified cases use the corrected plans and
fresh recordings in `goldens/`.

Qualification includes 173 ordinary cases, ten status mutants (one per route),
and four actual database mutants: missing denial audit, suppressed notification,
removed domain predicate, and duplicate evidence event. The failure corpus pins
atomic map rollback, committed data before failed evidence, committed evidence
before failed notify, and scope re-checks on reads/upserts/deletes/evidence.
Private views/triggers in the assigned DB inject faults; `users` projections
select the lost reach at the data/evidence/read statement boundary. They never
change production SQL or shared PostgreSQL functions and are removed on exit.

The registry seed deliberately collides one own console id with another owner's
canonical device id. A registry-only row also reuses the other owner's fingerprint.
Reads/writes must resolve by both owner and fingerprint. App-role cases cover all
ten routes. Policy configuration is organization-wide in Go: scoped grants are
allowed; missing/wrong grants supply that surface's denial floor. Read routes
without validated inputs record ignored malformed query fields.

Go recording must select ordinary cases (for example a new exact test or `_error`);
mutants refuse recording mode. Normal verification always runs the entire target.
SQL companions: `rust_mam_policy.pg` (15 assertions), `mam_device_projection.pg`
and `V060__mam_policy_engine.pg`. No accepted divergences; the global NULL-key
upsert duplicates values exactly as Go does.

Four COMMIT-loss checks cut the PostgreSQL wire before/after an actual write
commit (map reducer and event statement). HTTP must return Unknown with its
operation id, actual rows/receipt must match the cut, and no later notification
may run. The existing read-only-aware wire helper ignores preflight commits.

All ten inventory entries default ON. Executable target `devices_startup` covers
all 21 MDM/MAM registrations, zero Go forwards for them, the remaining offline
forward and both global/per-route rollback switches.

[Qualification map and coverage limits](COVERAGE.md). The family catalog keeps
F07's existing MDM mutant identifiers; this target additionally runs its four
MAM database mutants, so family identifiers remain unique across slices.

Event detail numbers follow Go's float64 map decoding and fixed/exponent JSON
formatting, including precision loss for stored integers above 2^53. The numeric
details golden pins that frozen-Go behavior; storage remains unchanged.
