# F09 frozen-Go oracle (#329)

Run `cargo test --locked -p setjoin-gateway --test rules -- --test-threads=1`
with `REQUIRE_DB=1`, `TEST_DB_DSN`/`DB_DSN`/`DB_DIRECT_DSN` pointing at an
owned disposable schema and `DB_APP_DSN` at its request credential. Normal
replay configures no upstream and asserts both proxy counters remain zero.

`cases.json` describes the authored inputs; `tests/rules_oracle/profiles.rs`
contains their seeds and request transformations. Expectations come exclusively
from frozen Go, including ignored input, forbidden ownership, failed dry-runs,
repeated writes and malformed programs. `divergences.json` is empty: no behaviour divergence is accepted.
The HTTP observations include exact
problem bodies, persisted rows, state counters, audits and notification channels.
Timestamp/actor masks retain distinct owners and never reorder response JSON.
Row companions are projections of the same immutable Go observations.

The active schema has no template tables. `schema-missing` cases use it unchanged.
Other template cases explicitly create `legacy-fixture.sql`, refuse existing
tables and drop only their own fixture tables afterward. This fixture is not a
migration or permission to restore the archived schema in production.

Recording is explicit: set `GOFREE_RECORD_GO_BINARY`, full `GOFREE_GO_SOURCE`,
`GOFREE_GO_COVERAGE_DIR`, `GOFREE_RESOURCE_PREFIX`, and `GOFREE_RESOURCE_LEDGER`;
set `GOFREE_RULES1_CASES=action:label,...` and run the exact test
`recording_driver_or_replay_smoke`. It shares one frozen process but resets each
case. Golden creation refuses overwrites. Clear all recording variables for CI.
The recorded binary source is stored in every golden; the Rules, Templates,
authentication and response dependencies were unchanged from that source.

Each route has a changed-status mutant. Family faults suppress a real audit,
introduce an extra mailbox-state bump, or expose the planted foreign rule.
COMMIT wire cuts exercise absent and committed operations for personal rules,
audited admin writes, retro scheduling, templates and visibility; the HTTP
response must expose an ambiguous operation ID whose receipt resolves the
observed transaction. No-notify is inapplicable: frozen Go emits none for F09.

Schema-missing recordings always start a fresh frozen process: a prepared query
cached while legacy fixtures existed can otherwise defer its missing-table error
to `Rows.Err`, an artificial warm-fixture result. The real absent-table schema
has no such cached description. Oversized-body fingerprints normalize fixture
identities before hashing; folded and string-valued identity fields keep distinct
actor/other labels as well.
