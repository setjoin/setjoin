# Drive B recorded-oracle receipt (#275)

Frozen Go source: `559bb903e5ff5bb4f2d15cb79f7016261eafc4ea`.
No Go source changes. The 28 transferred registrations have 197 immutable V5
HTTP/effect recordings; 17 route contracts write or consume state. The native
suite also has 28 real HTTP status mutants, four private-schema SQL effect
mutants and two actual COMMIT wire cuts (231 tests total). Four executable
tests cover native dispatch with Go unset, both rollback switches and the
native-token deferral to identity #112. Accepted divergences: none.

The Go 1.26.6 covered build must include **both** packages:

```sh
# In the prescribed CI image, from mailserver/:
go build -p 2 -cover -coverpkg=./internal/drive,./cmd/mailserverd \
  -o /evidence/mailserverd-covered ./cmd/mailserverd
```

Instrumenting only the helper package emits no counters on this toolchain.
The covered executable is semantically unchanged. `GOFREE_COVERAGE_PROBE=1`
starts frozen Go but compares existing goldens instead of overwriting them;
normal native replay leaves all recording/probe variables unset. Recording
always uses exclusive-create files. The task's evidence directory retains
source/binary hashes, raw counters, command logs and the resource ledger.

Every handler has successful, foreign-caller and invalid-input recordings;
Go's public audit catalog and ignored query parameters legitimately succeed.
Additional seams cover JSON decode bounds, feature gates, optional filters,
history cursor pagination/tampering, branch verbs, stale/hard-locked/quota saves,
raw alarm JSON and global alarms, Office URL parsing/encoding, byte framing,
S3 failures, CSV escaping/pagination and GXP retention/bookkeeping failures.
Query/permission faults, deferred row errors, reducer audit rollback and
post-consume metadata failure are recorded independently of the observer.

Unreached defenses include nil claims already excluded by the front door,
crypto/rand failure branches that Go 1.26 cannot return normally, and typed
Scan/JSON decode failures excluded by the canonical NOT NULL/schema-shaped
projections. Native-token is not qualified here: the shared signer is #112.
These are admission/schema exclusions and an explicit later-ticket boundary,
not accepted changes to frozen Go behavior.

## Covered frozen-Go handlers

`go tool covdata func` reports the following statement coverage. The table
measures statements, not a claim of complete branch coverage.

| Handler | Statements covered |
| --- | --- |
| `activity` | 92.3% |
| `searchNodes` | 95.0% |
| `createBranch` | 100.0% |
| `listBranches` | 86.1% |
| `patchBranch` | 97.1% |
| `resolveBranch` | 100.0% |
| `setLabel` | 100.0% |
| `removeLabel` | 100.0% |
| `postVersion` | 95.8% |
| `restoreVersion` | 100.0% |
| `listVersions` | 91.7% |
| `getContent` | 91.1% |
| `fileHistory` | 89.1% |
| `officeChoices` | 100.0% |
| `officeLaunch` | 86.5% |
| `officeRevoke` | 100.0% |
| `officeLocalOpen` | 100.0% |
| `handleExportRequest` | 87.5% |
| `handleExportConsume` | 88.9% |
| `auditActions` | 100.0% |
| `auditQuery` | 100.0% |
| `auditCSV` | 93.3% |
| `listAlarms` | 92.0% |
| `createAlarm` | 100.0% |
| `updateAlarm` | 100.0% |
| `deleteAlarm` | 100.0% |
| `adminTrashList` | 100.0% |
| `purgeRestore` | 100.0% |
| `handleVerifyAuditChain` | 91.4% |
