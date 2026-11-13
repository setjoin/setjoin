# F15 Office oracle (#270)

Nine Go method/path registrations move together. Office routes mount below
`/api`; GET also accepts HEAD. Provider application/runtime management remains
Platform/CLI work. No shared-effect Office worker is assigned to F15. Both
processes retain their own proof-key cache until Go is deleted.

Frozen source: `c9d7fc026c20067965ee2e5a1a36b44c3dacf20b` (integration base).
The covered, unmodified Go mailserver executable is run per case behind the
Rust front door, against the assigned disposable database and real TLS/S3
protocol peers. Replay removes Go entirely and uses the app-role credential.
`route-catalog.json` binds the authoritative envelopes, separate mutator row
observations, exact replay selectors and planted mutants. Earlier tracer-bullet
recordings remain immutable; the catalog selects the complete wire revisions.

| Registration | Recorded cases |
| --- | --- |
| GET `/office/wopi/files/{id}` | Success, another user's real file/launch, invalid ID, disabled feature, missing proof, current/rotated key, both proof headers, old/old rejection, corrupt/stale/future proof, cache reuse, Unicode simple uppercase, request ID, query escaping, escaped route segments and an encoded slash retained inside the ID. |
| GET `/office/wopi/files/{id}/contents` | Success, foreign launch target, invalid ID, HEAD, tampered stored chunk. The buffered Go stream abort becomes the front door's 502. |
| POST `/office/wopi/files/{id}` | Success, foreign file, missing lock header, repeat, UTF-8 conflict headers and unlock/relock/refresh sequences; complete lock/session rows and exact conflict headers. |
| POST `/office/wopi/files/{id}/contents` | Success, foreign file, invalid ID, repeat, FORCE-RLS ACL mode; five reducer faults after canonical copy prove rollback and the shared Drive error classes. Signed temp PUT, canonical CopyObject and temp DELETE are independently checked. |
| GET `/admin/office` | Success, revoked live grant, malformed query/body ignored by Go. |
| PUT `/admin/office/providers/{providerId}` | Success, revoked grant, invalid JSON, repeat/stale generation, signed non-admin, UTF-8 audit reasons, duplicate/null fields and persistent earlier type errors and the 64 KiB decoder boundary. |
| POST `/admin/office/providers/{providerId}/qualify` | Success, revoked grant, invalid receipt, missing proof key, repeat; actual TLS discovery/editor GET/HEAD observations and synthetic-save receipt binding. |
| POST `/admin/office/providers/{providerId}/activate` | Success, revoked grant, invalid UUID, repeat/stale generation, Unicode JSON field folding and Go UUID wrapper forms. |
| DELETE `/admin/office/providers/{providerId}` | Success, revoked grant, missing audit reason, repeat; repeated removal retains Go's second audit/notification. |

Provider administration is organization-wide in Go: the foreign floor revokes
live permissions rather than inventing domain tenancy. Go ignores malformed
list input; that floor is a recorded 200. WOPI authenticates the opaque launch
bearer, not a browser JWT. The reducer derives its actor and repeats current
file membership/fence checks. Browser routes use shared verified session/CSRF
admission plus fresh Office permissions. Unsupported identity/security modes
still forward under ARCH-027 pending the identity slices (#331–#333).

Every route has a changed-status mutant. Family SQL mutants execute actual
mutated function bodies in private, disposable schemas: missing audit, missing
notify, double generation bump and omitted launch/file credential predicates.
They change the command database, never the observer or expected output.
`f15_dispatch` uses the executable's family factory and bundled ON inventory:
all nine registrations run with no Go upstream and zero proxy count; global
kill and per-family inventory rollback forward the same requests to Go.

Normalization validates UUIDs/timestamps, both audit chains and actual chunk
reference counts before replacing fixture identifiers, clocks, checksums and
transport nonces. JSON response whitespace/order and framing headers are
transport differences. Shared dedup rows project this fixture's reference
count after verifying the global count against all version-chunk references.
Rust operation receipts are excluded system metadata, as in the foundation
contract; all Go business rows, audit entries, notifications and peripheral
observations remain strict. `divergences.json` is empty: no accepted differences in cataloged observations and no golden overwritten.

Recording environment: `GOFREE_RECORD_GO_BINARY`, `GOFREE_GO_SOURCE`,
`GOFREE_GO_COVERAGE_DIR`, `GOFREE_RESOURCE_LEDGER`; native replay leaves them
unset. Recorder containers and mutant schemas use `gofree-office1-` /
`gofree_office1_mutant_` ownership prefixes and are reaped. Provider keys and CA
in `provider/` are synthetic test material only. The Rust fake pins the TLS
peer to loopback while retaining certificate hostname verification; native
proof discovery checks every DNS answer, pins checked addresses, refuses
private/special-use targets and constrains redirects to the HTTPS origin.

Frozen-Go function coverage (covered production executable, merged real HTTP
case counters) is recorded in `test-results/gofree-office1/go-functions-final.txt`.
Final merged recording coverage: CheckFileInfo 100%; GetFile
65%; PutFile 73.1%; lockOperation 82.6%; List 66.7%; Configure 83.3%; Qualify
66.7%; Activate 86.7%; Remove 71.4%. This is statement coverage, not a claim
of complete branch coverage. Uncovered paths include infrastructure/decoder
faults, oversized saves, additional lock failure paths and provider-network/XML
errors. App-management functions in the same Go source are outside F15.
The required Rust gate separately measures instrumented handler lines/regions
for each catalog route and its selected replay cases. Remaining coverage gaps
must be considered at the whole-rewrite Go-deletion gate; no threshold or test
was lowered to qualify this slice.

The shared Rust adapter/domain files are measured for each route; their
coverage denominators include other F15 branches. The separate Go report
measures individual frozen handler functions.
