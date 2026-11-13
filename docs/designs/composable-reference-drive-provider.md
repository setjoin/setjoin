# PAPER reference — Drive document-processing Provider

Date: 2026-09-06

Status: CP0.4 paper fixture; not an implementation, frozen schema, or public API.

## Purpose and authority

This fixture exercises a Provider that reads one authorized immutable Drive
version and produces a bounded derived document. Drive accepts or rejects the
result. It is a document-processing Provider, not a storage backend, an Office
editor session, or permission to replace SeaweedFS/S3.

Authority comes from the CP0 contract-freeze plan,
the [extension control-plane design](extension-control-plane-public-system-apps.md),
the app-data lifecycle amendment
and the [lifecycle packet](composable-lifecycle-transitions.md). Drive owns source
versions, ACLs, accepted output, conflicts, quota, retention, deletion and audit.
The Provider owns a bounded computation and reports its observations; neither its
exit code nor its output upload is a committed Drive version.

The narrow paper operation derives a result from input version A and proposes a
new version on a separately authorized output file B. It never replaces or deletes
A. Choosing B and the permitted transform belongs to the initiating authorized
workflow. This exercises a conflicting output base without granting source writes.
The exact public derived-output relation remains to be frozen; the fixture does
not claim that a Provider-specific result-acceptance reducer already exists.

## Current source facts, not extension promises

| Inspected boundary | Current behavior | Consequence for this fixture |
|---|---|---|
| [drive/content.go](../../mailserver/internal/drive/content.go), `versionMetaAndManifest`, lines 236–274 | User-scoped lookup checks the exact node `download` capability and live attachment predicate, then resolves ordered Drive chunks internally. Missing/invisible lookup returns the same sentinel. | Reuse the authority, not the internal manifest or storage reference as a public Provider credential. A public immutable-input handle is proposed. |
| [drive/chunks.go](../../mailserver/internal/drive/chunks.go), `StageChunk`, lines 273–322 | Private staged values carry verified hash/size; temporary upload keys precede canonical promotion. Individual chunks are nonempty and bounded. | The mediated byte adapter, not the Provider, owns hash/length validation and storage credentials. |
| [drive/chunks.go](../../mailserver/internal/drive/chunks.go), `CommitStagedChunkBound`, lines 361–395 | Bound promotion checks target, ACL epoch and current capability, takes the shared chunk lock, copies bytes and calls the registration reducer. Canonical keys use `drive/<scope>/<hash>`. | This is an internal trusted ingest seam, not an extension API. Public handles must remain bound to target, operation and current grant. |
| [drive_file_put_version.sql](../../mailserver/sql/reducers/drive_file_put_version.sql), lines 30–166 | Rejects missing/deleted targets; rechecks mutation capability; enforces immutable Chat/Meet records, ref locks, manifest shape, current claim/ACL-bound proof and quota. A zero-byte file has an empty chunk manifest. | Drive, not the Provider, determines whether proposed output is admissible. Empty content is distinct from missing bytes or a failed read. |
| Same reducer, lines 169–248 | Compares the locked target head; creates a conflict branch when appropriate; records version/chunks, quota, audit and change facts. Lines 94–109 deduplicate matching content/base shapes. | A stale output base must not silently overwrite Main. Current content deduplication is not a public installation/operation receipt protocol. |
| [drive/chunks.go](../../mailserver/internal/drive/chunks.go), lines 290–294 and 339–345 | Temporary cleanup is best effort with a documented reaper backstop; promotion followed by reducer failure can leave canonical bytes for delayed orphan cleanup. | Object existence is not accepted-result evidence. The Provider gets neither canonical deletion rights nor authority to declare cleanup complete. |
| [backup/engine.go](../../mailserver/internal/backup/engine.go), `SnapshotBlobs`, lines 197–205; [mailctl/backup_recovery.go](../../mailctl/backup_recovery.go), lines 462–481 | These inspected inventories enumerate `blobs` with positive reference counts, not `drive_chunks`; Drive uses a separate key namespace. | These paths alone do not establish backup/recovery of Drive bytes. Full/selected app-Drive recovery remains an explicit gate, not a completed feature. |

This is bounded inspection, not a repository-wide assertion that no other backup,
export or retention path exists. Neither the current ingest seam nor existing
Office WOPI adapters establish a qualified generic processing Provider contract.

## Illustrative manifest and capability matrix

All `paper.*` names and field layouts are non-normative placeholders. The example
has no signed artifact, registry entry, endpoint or SDK. It cannot be installed.
Managed OCI is an illustrative server placement with broker-only communication;
this fixture does not authorize runtime provisioning or remote data disclosure.

```json
{
  "paperOnly": true,
  "schemaVersion": "<E0 manifest schema to freeze>",
  "app": "paper.example.drive-document-processor",
  "publisher": "<qualified publisher identity>",
  "release": "0.0.0-paper",
  "artifactDigest": "<signed immutable artifact digest>",
  "compatibility": {
    "apiLevel": "<supported range>",
    "domainContracts": {"Drive": "<processing contract major>"}
  },
  "dependency": "protected Drive system app",
  "runtime": {"kind": "managed OCI", "placement": "server"},
  "contribution": "document-processing Provider",
  "requestedCapabilities": ["read exact input version", "stage bounded result", "propose result acceptance"],
  "data": {"acceptedFiles": "Drive-owned", "scratch": "operation-scoped disposable"},
  "egress": "broker only; no arbitrary destination",
  "lifecycle": {"removeDataDefault": "retain", "acceptedWork": "Drive-owned disposition"},
  "resources": "<bounded input, output, CPU, memory, retry and time profiles>",
  "supportAndLicense": "<publisher support and license metadata>"
}
```

| Interaction | Scoped grant and authoritative check | Never granted |
|---|---|---|
| Read input A at an immutable version | Initiating actor's current `download` rights ∩ approved installation/provider generation ∩ operation, data class, audience and expiry; no wildcard enumeration. | Current-head substitution, other versions/files, raw storage keys, S3 credentials or a bucket listing. |
| Stage output bytes for B | Approved operation and output target, allowed media type, maximum byte count, digest and live grant; server mints an opaque bounded handle. | Arbitrary destination, unbounded upload, cross-operation handle reuse or a Provider-supplied object path. |
| Propose acceptance onto B | Current target write authority, original input authorization, expected target base and ACL/grant fences rechecked under Drive authority; server validates bytes and provenance. | Source overwrite/deletion, ACL/retention bypass, private reducer calls, quota accounting or direct Main-head mutation. |
| Read receipt / receive committed result event | Operation audience and current read authorization; event delivery checks current installation scope. | Treating a compute-complete callback or uploaded object as an accepted version. |
| Request scratch abandonment | Exact operation-owned temporary handle; Setjoin validates ownership and retention obligations. | Canonical-chunk deletion, shared/user files, accepted output, legal-hold data or backups. |

A scoped installation does not impersonate its installer or gain all files in an
organization. Actor and ownership are authenticated context, not request body
claims. Deployment/account scope must map to existing authority; mail domains are
not new tenants. Accepted output belongs to the selected Drive space. Any persistent
app-managed files use an organization-owned app-managed Drive space, not a personal
installer folder. Publisher identity, app installation, operation, provider
generation, grant/fence, API level, domain major and manifest schema are distinct.

## Four-path data flow

```text
authorized workflow -> broker/Drive -> immutable input A + output target B binding
  valid ----------> scoped read -> bounded compute -> staged result handle
                    -> Drive acceptance -> version/receipt/committed event
  missing/hidden -> unavailable input or target; no fallback to another version
  empty ---------> explicit zero-byte input -> declared transform outcome
                    -> valid empty result OR unsupported-input; never fake bytes
  upstream fails -> incomplete read/compute/upload/acceptance observation
                    -> receipt lookup or bounded retry; never infer acceptance
```

The empty-input/output behavior belongs to the declared transform contract. A
transform may return a valid empty document or a typed unsupported-input result;
this paper does not decide that behavior for all formats. A successful zero-byte
result carries size zero and the verified empty-content digest with no chunks.
Absent input, a truncated stream, omitted result metadata and object-store failure
are not successful empty documents. There is no silent conversion of those cases
to a zero-byte accepted version.

If input A is deleted or its ACL is revoked after a read, the proposed acceptance
path rechecks authorization and refuses publication under that old operation.
Bytes already disclosed to a Provider cannot be recalled by revoking a token;
runtime/data-class qualification and cleanup evidence must acknowledge that limit.

## Illustrative query, command, receipt and event

These are separate typed contract sketches, not implemented public routes or a
universal action endpoint. Handles, versions, deadlines and digests are issued or
verified by Setjoin; they are not trusted assertions from the Provider.

```json
{
  "paperQuery": "paper.drive.processing.input",
  "input": {"operationRef": "paper-operation-D"},
  "result": {
    "input": {
      "fileRef": "paper-input-A",
      "versionRef": "paper-input-version-7",
      "contentHandle": "<opaque read handle; not a URL or storage key>",
      "sizeBytes": 2048,
      "digest": "<server-verified content digest>"
    },
    "output": {"fileRef": "paper-output-B", "expectedBase": "paper-output-version-2"},
    "limits": {"outputBytes": "<numeric approved limit>", "deadline": "<absolute deadline>"}
  }
}
```

The output staging sketch takes the approved operation plus declared length,
digest and media type, and returns an opaque result handle after mediated byte
verification. It cannot create a version by itself. Its exact streaming transport,
size limits, expiry and resumability are contract-freeze work.

```json
{
  "paperCommand": "paper.drive.processing.accept-result",
  "requestId": "paper-request-D1",
  "input": {
    "idempotencyKey": "paper-acceptance-D",
    "operationRef": "paper-operation-D",
    "inputVersionRef": "paper-input-version-7",
    "outputFileRef": "paper-output-B",
    "expectedOutputBase": "paper-output-version-2",
    "resultHandle": "paper-staged-result-D",
    "resultDigest": "<verified staged digest>"
  },
  "receipt": {
    "operationRef": "paper-operation-D",
    "idempotencyKey": "paper-acceptance-D",
    "outcome": "accepted",
    "versionRef": "paper-output-version-3",
    "conflict": false,
    "eventRef": "paper-event-D"
  }
}
```

```json
{
  "specversion": "1.0",
  "id": "paper-event-D",
  "source": "paper:protected-drive",
  "type": "paper.drive.processing.result-accepted",
  "subject": "paper-output-B",
  "data": {
    "operationRef": "paper-operation-D",
    "inputVersionRef": "paper-input-version-7",
    "versionRef": "paper-output-version-3",
    "conflict": false
  }
}
```

Drive compares the staged metadata with actual bytes and the immutable operation
binding; the Provider cannot replace the input, output or expected base in a retry.
An advanced output head requires an explicit Drive conflict result. The current
reducer can preserve a stale-base save on a conflict branch; the public wrapper's
exact choice of rejection versus a returned branch result must be frozen. Neither
choice permits silent overwrite or hides the conflict as ordinary success.

An accepted receipt binds the input version, transform/config digest, installation,
provider generation, output target/base, result digest and current authority check.
`requestId` is transport-attempt correlation and may change on retry. The
illustrative durable retry scope is installation, logical operation and command
kind plus `idempotencyKey`; the receipt binds the authorized actor and immutable
intent. E0 must freeze its exact encoding. The same authorized key in that scope
plus identical intent returns that receipt; changed-intent key reuse conflicts.
The current reducer's content/base deduplication is not a substitute for this
operation identity. Receipt reads require current authorization.

The future domain outbox publishes the committed acceptance fact after the same
transaction. No acceptance transaction means no accepted event. Delivery is at
least once, with stable event-ID deduplication, declared aggregate ordering only,
bounded retries and reasoned dead-letter replay under current scope. Neither
Provider completion callbacks nor raw Drive notifications are the public outbox.

## Crash, revocation, ownership and paper lifecycle receipts

| Paper receipt / interruption | Authoritative interpretation | Resume and cleanup |
|---|---|---|
| `paper-stage-D`: upload complete, acceptance absent | Verified temporary result exists; no accepted Drive version is implied. | Provider crash is reconciled by operation/receipt lookup. An authorized retry reuses exact intent while the handle is valid; otherwise re-stage under a new permitted handle. |
| `paper-accept-D`: response lost after commit | Drive's committed receipt is authoritative; Provider memory is not. | Query the receipt with current authority; do not create a second version or delete bytes on uncertainty. |
| `paper-conflict-D`: target base advanced | The locked Drive target determines conflict; source A is unchanged. | Expose the rejected/branched outcome. A new attempt needs an explicitly accepted new basis, not automatic rebasing by the Provider. |
| `paper-withdraw-D`: new admission closed | Only previously accepted work explicitly permitted to drain remains eligible; old routes cannot accept new operations. | Bind drain to operation/generation and a domain-owned deadline; keep source/result obligations visible until acceptance or explicit abandonment. |
| `paper-revoke-D`: security fence committed | Old generation and handles cannot read, stage or accept further results. | Separate maintenance authority reconciles receipts and owned scratch; never renew the old token to complete a drain. |
| `paper-clean-D`: process exited, bytes cleanup unconfirmed | Process termination and cleanup are separate observations. | Retry exact owned scratch cleanup or record the retained/reaper obligation. Do not delete canonical keys or report remote erasure without evidence. |
| `paper-restore-D`: isolated inactive copy | Input/output/provenance recovered, but Provider routes/jobs/events have not been activated. | Revalidate current grants before explicit activation. Historical compute callbacks cannot overwrite the recovered version or emit new external effects. |

A generation older than the current new-work route is not invalid merely because
of its age. During a planned transition, an older pinned runtime may complete its
exact accepted operation while its grant/fence and drain authority remain valid.
A wrong operation binding, revoked fence or expired authority is invalid. The
positive drain oracle is one accepted result/receipt for that permitted operation,
while new work on the old route is refused; security revocation still denies its
subsequent acceptance immediately.

Each timer, stream, callback registration, subscription, runtime lease and temporary
handle has an operation owner, immutable ownership reference, expiry, cleanup
registration and completion observation. Cancellation prevents additional work but
does not prove cleanup. Crash recovery reconstructs obligations from receipts;
teardown is idempotent and cannot affect another operation's handles. Numeric
input/output bounds, handle lifetime, execution/drain deadlines, retries and receipt
retention remain explicit implementation gates, not universal values chosen here.

Accepted Drive versions, branch results, provenance and audit are persistent data,
never disposable scratch. Uninstall retains app-managed persistent files by
default; any later deletion needs exact scope preview, current authorization,
holds/retention checks and dependency handling. No operation deletes its source as
an implicit success or failure cleanup step.

Full/selected backup must bind declared app state, input/output versions, Drive
chunk bytes, ACLs and required dependencies at a consistent boundary. Missing or
corrupt bytes, unavailable secrets/external state, or configuration-only capture
must be represented honestly as incomplete recovery. The inspected blob-only
inventories above do not satisfy that contract. Restore first creates an inactive
separate copy and suppresses Provider jobs, callbacks and outbound events; explicit
replacement/activation follows current-authority checks. Historical grants are
provenance, not authority to restart computation.

## Proposed tests and remaining freeze work

These cases are future conformance requirements; no tests ran for this paper.

| Proposed case | Required observation |
|---|---|
| DP-P01 — four input paths | Authorized immutable version succeeds; hidden/missing input is opaque; valid zero-byte content is distinct from missing/truncated/upstream-failed content. |
| DP-P02 — current authority | Delete input, revoke input ACL after read, revoke output write grant, spoof actor or cross-installation operation; no acceptance or new disclosure under stale authority. |
| DP-P03 — bounded bytes | Oversized output, invalid media type, wrong digest, incomplete upload and wrong-operation/expired handle create no accepted result or bypass of quota. |
| DP-P04 — target-base race | Concurrent output save produces an explicit conflict result and never silently replaces Main or input A. Preserve any accepted conflict branch with a truthful receipt. |
| DP-P05 — crash and exact retry | Crash after upload, during acceptance, and after commit-before-response; a new correlation request ID with the same scoped idempotency key/intent yields one accepted result/receipt, no speculative deletion, and owned orphan cleanup evidence. |
| DP-P06 — callback/event replay and pinned drain | Wrong operation binding, invalid security fence, revoked subscriber and changed-intent key reuse cannot revive authority; duplicate/reordered events create no extra versions. An older pinned runtime with still-valid accepted-work authority can complete exactly one result while new admission is closed; immediate security revocation denies the same acceptance. |
| DP-P07 — lifecycle resource accounting | Planned drain versus immediate security fence; cancel versus acknowledged cleanup; repeated teardown and reaper recovery leave no unowned temporary handle. |
| DP-P08 — retention and recovery | Installer departure, retain-default removal, holds/dependencies, missing Drive bytes and inactive-copy restore preserve ownership and prevent silent incomplete-backup success. |
| DP-P09 — no private escape hatch | Complete the fixture without DB access, raw object keys, S3 credentials, source deletion, private WOPI tokens or direct chunk GC. Unknown contract/capability kinds fail closed. |

Existing source anchors, not fresh verification: [drive_file_put_version.pg](../../mailserver/sql/tests/drive_file_put_version.pg)
lines 16–38 cover version/head/chunk/quota effects, retry and invalid manifests;
[chunks_test.go](../../mailserver/internal/drive/chunks_test.go) contains
`TestPromoteChunkMismatch` (line 145), `TestStageChunkRejectsKnownZeroSizeBeforeStorage`
(line 194) and `TestPutChunkOversizedBody` (line 210). They do not prove the proposed
Provider broker, operation-bound handles, public receipts, lifecycle or app-Drive
recovery closure.

Freeze gaps: public immutable-input/result-handle grammar; input-version retention
pinning during accepted work; derived-output provenance and conflict projection;
actor/installation/grant mapping and command-time fences; deterministic operation
receipts; exact resource deadlines and cleanup evidence; event audience/schema;
consistent Drive-byte backup/restore and disabled-copy effect suppression. These
need owning engineering/security review. No new product choice or automatic
source-deletion policy is introduced. A transform's content/data-class needs that
exceed this fixture must be separately approved, not hidden in a generic grant.
