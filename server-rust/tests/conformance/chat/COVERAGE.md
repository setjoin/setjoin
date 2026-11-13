# Frozen-Go coverage for F12 compliance (#266)

Measured from the covered Go binary at `c9d7fc026c20067965ee2e5a1a36b44c3dacf20b`
through the real gateway and 66 immutable HTTP recordings. Coverage instruments
`cmd/mailserverd` and `internal/admin`; `go tool covdata textfmt` merges the
per-process counters. Counts below are covered/total Go statements, including
defensive and optional-data branches, rather than a claim of 100% coverage.

| Function | Statements |
| --- | --- |
| `ListChannels` | 30/34 |
| `SetHold` | 19/20 |
| `SetClassification` | 30/32 |
| `SetRetention` | 18/20 |
| `GetAudit` | 36/41 |
| `VerifyAudit` | 63/67 |
| `writeAuditCSV` | 21/21 |
| `chainSummary` | 23/27 |

Every reachable handler branch that writes an error status or calls a reducer
is exercised. The three remaining status-writing branches are defensive Scan
errors unreachable through these static queries against the canonical schema:

- `ListChannels`, line 500: typed IDs/counts/booleans are non-null; optional
  columns scan into pointers; participants is non-null JSONB text.
- `GetAudit`, line 908: ID, timestamp and action are non-null with fixed types;
  the canonical audit writer supplies finite clock timestamps;
  nullable actor/target/notes use pointers, JSON fields use raw JSON, and IP
  uses `COALESCE(ip::text, '')`.
- `VerifyAudit`, line 1166: the canonical `chat_chain_anchor_verify` return
  types are fixed; the canonical anchor writer supplies range/digest fields,
  and checksum validation precedes this query. Its selected verdict fields
  are non-null for those records. The parse and
  iteration failure branches are separately reached with private fault functions.

Changing schema types/nullability, producing malformed PostgreSQL wire values,
or replacing a function with a contract-breaking return would invalidate those
reasons; none is a request admitted by the frozen application schema. SQL query
and iteration failures are injected separately without editing canonical SQL.

The defensive 401/403 branches inside `requireManageClaims`/`requireViewClaims`
are unreachable at these registrations: main wraps each handler in `requireAuth`
and the matching compliance permission middleware first. Foreign recordings
exercise that real middleware denial and its independent core audit. Unmirrored
shared-authz gates continue forwarding to Go.

Native Rust line/region measurements for each of the six routes are emitted by
`bash scripts/check-server-rust.sh` via the committed route catalog. The complete
suite also covers six actual COMMIT cuts, both rollback switches on all six routes, six status mutants,
three database mutants and generated request IDs. No accepted divergences.

The shared adequacy gate records `no-notify` as not-applicable under the #266
orchestrator ruling: zero notifications occur across all 66 enabled-route goldens.
The six `golden-routes` entries default ON/local-rust. A notifying family still
must reject its no-notify mutant; gate CLI regression tests enforce both cases.
See [the family contract](../../../crates/domains/chat/DOX.md).
