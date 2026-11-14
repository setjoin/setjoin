# Drive sub-router B (#275)

The agreed spec #251 seams are the front door HTTP boundary and its committed
row/audit/state/notification effects. Go is frozen at `559bb903e`; immutable
recordings are exclusive-create. Ordinary replay has no Go upstream.

The inventory assigns 29 registrations here. Native-token issuance retains
whole-request forwarding pending the shared Postgres signing-key implementation
in identity #112; ARCH-027 requires this rather than an independent signer.

Each transferred route requires success, foreign caller and malformed input.
Mutators also repeat. The authored cases follow these Go handlers:

| Handler | Routes / additional decisions |
| --- | --- |
| activity.go | activity; optional node, beforeId and max parsing |
| search.go | search; optional space/max; missing q reducer rejection |
| branches.go | create/list/rename/status/resolve branches, set/remove labels; exact-one-field patch, all=1, all resolve verbs |
| content.go | put/restore/list versions, content; upload manifests, stale bases, byte ranges, protected classifications and view-audit dedup |
| history.go | history; feature gate, limit, signed cursor pagination/tampering |
| office.go | choices, launches, revoke, local-open; feature gates, provider URL, credentials and live grants |
| export.go | request/consume; grant token hash custody, repeated burn, streaming |
| audit.go | catalog, audit JSON/CSV, alarm CRUD; live admin permission, optional filters, bounded CSV |
| worm.go | audit verification; live drive.view and broken-chain result |
| trash.go | admin trash/purge restore; tier=2 and live drive.manage |

The four family effect mutants remain required: missing audit, missing notify,
missing tenant filter and double bump. Route response mutants must alter actual
HTTP replies. Faults act on the database wire or private fixture schema, never
on the observer or on a checked-in golden.

Qualified V5 recordings bind every transferred registration to its success,
foreign-caller and invalid-input case, plus repeated requests for all writes
(including content auditing and export consumption). The route catalog selects
these immutable envelopes and their separate write row-effect files. Early
V1–V4 tracer envelopes are retained and are not admitted as cutover floors.

Additional recordings cover first-value JSON limits/trailers, case-folded
fields, encoded IDs, exact-one-field branch patches, raw alarm patches,
feature gates, history pagination and signed-cursor tampering, Office URL
validation, JSON/CSV audit filters and failure paths. CSV recordings include
formula/control-character escaping and 1,000-row pagination despite `max=1`.
Content covers byte-exact JSON-looking data, ranges, HEAD storage reads,
protected originals, storage failure and deduplicated view auditing. GXP
put/restore compares signed retention I/O, successful chunk bookkeeping and
storage failure without undoing metadata.

`branch_commit_before/after` cut the actual database COMMIT wire and resolve
the operation receipt without another write. Private-schema branch mutants
remove audit, notify or tenant authority, or double the state bump. Every
route also has a real HTTP status mutant. Observers keep their independent
owner connection and verify both audit chains plus chunk refcounts.

Parity details: the audit-action catalog is visible to every authenticated
caller; foreign search/version lists are empty rather than errors. Go's
version list never populates `branchId` and always emits empty `labels`.
Native-token is explicitly deferred to identity #112 under ARCH-027, with an
executable exact-forwarding proof. No accepted behavioral divergences.

The [coverage receipt](COVERAGE.md) records source, instrumentation, case counts
and admission/schema exclusions. Content framing witnesses retain explicit
Content-Length for full, ranged and HEAD responses. GXP bookkeeping faults
preserve the saved version and return pending just like storage failures.

Malformed source IDs precede restore JSON decoding. Invalid UTF-8 in a label
path is a failed Go text argument, never a replacement-character label
mutation. Uploader content-type CR/LF bytes become spaces as Go's HTTP writer
does. These each retain separate Go recordings and full effect comparisons.

The `content_revoked` barrier revokes membership after metadata admission but
before the fresh manifest read. Go emits an empty/truncated stream, still
appends the admitted view audit, and performs no S3 read. Separate statement
snapshots are required; combining the reads into one CTE/subquery serves bytes
that Go no longer reads. New content/restore reducers preserve these boundaries.
