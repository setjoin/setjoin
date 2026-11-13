# F04 eDiscovery (#289)

Frozen Go source `1d9d2b58caa0c73bac2eba9331414c8bf411b1e8`, covered Go 1.26.6
binary; handlers unchanged at integration base `61fde0967`. No frozen Go code is
changed by this ticket. All 174 cases (167 registered-route cases and seven HEAD cases) record actual
HTTP plus committed effects.

| Routes | Observable coverage |
| --- | --- |
| Cases list/detail | Success, domain-scoped denial, invalid/ignored query, missing, NULL description, large chunked JSON, search count/order |
| Case create/update/delete | Verified actor, spoofed identity, malformed/folded/null/trailing JSON, empty/clear fields, closed cases, repeats, associated searches |
| Close/associate | Reason/audit, repeat, closed/missing, association/FK rejection, best-effort audit fault |
| Hold/release | Changed flags, duplicates, null/empty/foreign IDs, repeat, swallowed UPDATE/audit faults; no added JMAP state/notify |
| Search start | Legacy keyword/from/date/mailbox filters; KQL Boolean/group/field/date/bounds/quote quirks; async complete/failed state and persisted bindings |
| Search read | Persisted results only, unbound/pending/zero/missing fields, mailbox float conversion, stored KQL validation |
| Export | Active case/completed bound IDs, mandatory audit failure, original-ID digest/count, duplicates/nonnumeric IDs, PST 501, raw/binary/large/missing object bytes, independent SigV4 verification |

Cross-tenant means Go's organization-wide admin boundary: domain-scoped admins
receive audited 403 before the target is touched. Global admins are allowed to
operate across creators/mailboxes; adding a creator restriction would break parity.
Some invalid inputs deliberately return success because frozen Go ignores them.

Native replay (no Go binary/upstream):
```
REQUIRE_DB=1 cargo test --locked -p setjoin-gateway --test compliance_recorded -- --test-threads=1 --nocapture
```
Use the assigned disposable schema and owner/app/direct DSNs. `REQUIRE_DB=1`
makes missing DB fatal. SQL seam: `pg_prove ... mailserver/sql/tests/rust_compliance.pg`.

Recording uses `GOFREE_RECORD_GO_BINARY`, `GOFREE_GO_SOURCE` and
`GOFREE_RESOURCE_LEDGER`, with the CI image and named `gofree-compl1` containers.
Set `GOFREE_GO_COVERAGE_DIR` for the covered binary. Recording creates each file
exclusively. `GOFREE_VERIFY_GO=1` compares live Go without writing. Run ordinary
case selectors when recording/verifying; mutants, COMMIT faults and switch proofs
are Rust-only qualifications and must never be Go-recorded. Run the entire target
for native qualification. `catalog.py` derives immutable row projections from Go
observations and appends this slice's catalog entries; it never manufactures
expected responses or effects from Rust.

Volatile normalization checks syntax before replacing timestamps, request filename,
fixture IDs and audit digests. Raw MBOX bytes are retained (base64 for binary),
including literal SHA-256 digests for constant-ID and invalid UTF-8 ID cases. Query masking only touches
the `ids` parameter. Successful/failed background jobs settle before observation.
Row projections keep exactly the Go HTTP recording's effects.

The 15 planted mutants change the running adapter/DB boundary and use the normal
comparator: each route's status, a suppressed audit INSERT, an extra mailbox state
bump and a PostgreSQL Parse rewrite removing the domain scope projection. Eight
wire faults cut actual COMMIT before delivery/after acknowledgement, verify 503
and X-Operation-ID, resolve the receipt and compare durable whole effects without
replaying a mutation. No-notify is inapplicable: all recorded notification lists
are empty, including observed admin and tag channels.

Deferred shapes: WORM hold/release require Platform retention registry #301;
a NUL KQL (Go's parser hung) is a local 400, #436. A fake-Go test proves the
WORM requests forward original request bytes and increment only the Go counter. No reviewed
behavior divergence is accepted (`divergences.json` is empty).

Coverage: the catalog lists the adapter and family handlers, KQL/search/export
modules and the shared S3 transport used by this slice. Integration runs Rust
line/region coverage with the adequacy gate; the implementer was explicitly
instructed not to run its hours-long execute/coverage modes. The reused Go
recorder binary's profiles cover `cmd/mailserverd` only, so they do **not** prove
F04 Go handler coverage (the existing T3 recorder limitation). All 164 original
ordinary recordings were separately verified against live Go without rewriting;
the seven HEAD and three query-byte cases were captured directly from Go too.
