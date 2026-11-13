# F12 compliance HTTP recordings (#266)

External URLs are `/api/admin/chat-channels...`; inventory keys use the stripped
registration path. `bins/gateway/tests/chat_recorded.rs` is the HTTP seam. Each
recording runs the covered frozen Go binary behind the real Rust front door with
an empty local route table. Replays configure no Go upstream. Recordings are
immutable; there are no accepted divergences.

| Registration | Test prefix | Floor and repeat |
| --- | --- | --- |
| POST /admin/chat-channels/{id}/hold | `hold_` | success, foreign, invalid release, same-matter repeat |
| PUT /admin/chat-channels/{id}/retention | `retention_` | success, foreign, zero days, repeated audit |
| POST /admin/chat-channels/{id}/classification | `classification_` | success, foreign, invalid transition, repeat rejection |
| GET /admin/chat-channels | `list_` | success with participant, foreign, invalid userId, repeated read audit |
| GET /admin/chat-channels/{id}/audit | `audit_` | nonempty chain, foreign, invalid beforeId, repeated read audit |
| GET /admin/chat-channels/{id}/audit/verify | `verify_` | valid nonempty chain, foreign, invalid channel ID |

"Foreign" is a verified principal without live compliance authority, even when
its signed token carries the permission. Go permits a compliance admin to read
and change channels they do not belong to, across domains. Domain and channel
membership do not narrow these six administrative registrations.

Observations compare response status, headers and structured body, channel
settings/sequence, full chain-act business fields, core admin audits and direct
commit-ordered `chat:<member>` notifications. Audit-chain validity is checked
before checksum normalization. Participant IDs and emails must match the fixture
before replacement. Only generated timestamps, fixture identifiers and validated
chain checksums are normalized. The original foreign hold recording retains a
raw generated channel ID in console URL notes; the declared ID normalizer handles
both expected and actual without editing the recording.

The executor's opaque `rust_operation_receipts` are system metadata excluded by
the foundation normalization contract; business effects remain unchanged. Request
execution uses the constrained app credential. Explicit organization-wide reads
and classification's Go knob preset use the worker credential. No SET ROLE.

The committed catalog contains 66 Go recordings, including the floor and
targeted error/fault cases. See [coverage and unreachable branches](COVERAGE.md). Additional cases cover CSV
formula escaping and summary failure, query failure, broken/truncated/notarized
chains and anchor verification, feature-off, encoded-slash 404, Go JSON edge
cases, PostgreSQL integer range, GxP floor, federated classification and rollback.
SQL fault functions/triggers and mutant schemas are private to each fixture in
the assigned database and removed on exit. No canonical SQL function is edited.

Native-only invariants cover global and inventory kill switches on all six routes (original request reaches Go),
six real COMMIT wire cuts (both classification phases), distinct generated UUIDs,
and the three database mutants. Every native replay asserts total and F12 Go
counters remain zero. Each route also rejects a changed-status response mutant.
No-notify qualification is not-applicable under the #266 orchestrator ruling:
all 66 Go observations have empty notification lists. The adequacy gate derives
that exemption from enabled-route recordings and still rejects surviving notify
mutants when notifications exist. The six entries default ON/local-rust.

Re-record only a new case with a covered binary built from the catalog's
`go_source`, `GOFREE_RECORD_GO_BINARY`, `GOFREE_GO_SOURCE` and an optional
`GOFREE_GO_COVERAGE_DIR`. Supply `GOFREE_RESOURCE_PREFIX=gofree-chat1` and an
existing `GOFREE_RESOURCE_LEDGER` for task-owned names. Replays clear recording
variables. The recorder refuses overwriting an existing golden. The seam uses
`TEST_DB_DSN`, `DB_DIRECT_DSN` and constrained `DB_APP_DSN`, with `REQUIRE_DB=1`;
run serially because feature toggles and oracle audit windows are database-wide.

Chat seeds only verified-principal identity and primary-mailbox rows, with distinct
user/mailbox IDs. It creates no unrelated mail messages or partition fixtures.
Both principals are created in one transaction; a failure rolls back both
users, mailboxes and domains with a detailed database diagnostic. This avoids the
shared mail fixture's irrelevant partition work and partial-setup residue.

Raw invalid-UTF-8 request bytes are stored as an explicit base64 descriptor in
the request observation. Go replaces each invalid byte inside JSON strings;
invalid UTF-8 search text instead reaches PostgreSQL encoding failure (500).
Problem instances use Go's decoded path. An encoded `/api` prefix returns Go's
plain 404 because `StripPrefix` also checks the raw path. These cases retain a
zero Go counter during native replay.
