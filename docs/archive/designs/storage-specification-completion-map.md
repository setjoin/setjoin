# Storage specification completion map

Date: 2026-09-08. Status: planning work order; no new score, implementation,
cryptographic format, runtime claim or rollout authorization.
Authority: Storage E0–E10 and accepted D1–D12.

## Purpose and settled choices

Expand the held inventory into bounded review packets without asking again about
settled defaults. Source inventory precedes format selection. E3/E4/E5 form one
joint authority review; E6/E7 reuse that result rather than inventing a second
migration coordinator. Every packet distinguishes existing code, proposed changes,
future tests and actually retained evidence.

Preserve default encryption OFF, separate disk/SSE/object facts, explicit
unencrypted-install acknowledgment, security-scoped deduplication, default local
custody and one administrator recovery credential. Preserve staged data classes,
maintenance-first migration, seven-day minimum source retention plus separate
retirement approval, routine rewrapping versus compromise re-encryption, and the
accepted one-hour optional KMS grace. None is reopened by this work order.

## Finite outputs and rejection checks

| Packet | Required concrete output | Rejection check |
| --- | --- | --- |
| E0 byte-owner inventory | Source-hashed producer, read, Range, copy, delete, recovery and pin map; each admitted class and each omitted class has a disposition; shared machine-readable capability/status vocabulary | A direct byte consumer, preview/WOPI path, GC worker or backup pin is unclassified; primitive tests are called live encryption evidence |
| E1 installer posture | Probe schema, stable mount/device identity, ambiguity handling, acknowledgment/configuration field, receipt, capacity and emergency-headroom predicates | Probe changes a disk, a missing result implies encryption, or the data mount's shared failure domain is hidden |
| E2 provider SSE | Typed capability/configuration and qualification receipt, owned probe cleanup, freshness, required-profile activation predicate and credential-rotation effects | Provider SSE and Setjoin envelope status collapse into one boolean; provider-only KMS keys inherit Setjoin's grace |
| E3 authenticated bytes | Normative streaming framing, authenticated length/termination, AAD, nonce/usage limits, key domains, Range mapping, vectors and bounded plaintext-consumer contract | Whole-buffer helpers substitute for a format; unauthenticated plaintext or incomplete termination is treated as verified content |
| E4 server custody | Runtime/recovery hierarchy, cache identity, authoritative grace clock/deadline, revocation/expiry/restart/revalidation, admission/final-commit table, recovery ceremony/redaction and separate rotation/compromise procedures | Client cache re-provisioning replaces server recovery; retry renews grace or a recovery secret is stored in plaintext beside its package |
| E5 reducer generations | Immutable encoding and placement generations, operation records, authenticated predicates, locked rows, leases/fences, idempotency keys, receipts and transition guards | Encoding and provider placement are interchangeable; health observations or workers can select the authoritative generation |
| E6 conversion/rekey | Maintenance-fence participants, durable cursor, copy/verify/cutover pseudocode, crash transitions and independent backup/migration pins | Retaining the old generation is assumed sufficient to roll back after new writes; one lifecycle releases another's pin |
| E7 provider movement | One reconciler with raw-copy versus transform branches; four source/destination topologies; credential expiry, source loss, partial/orphan reconciliation and independently authorized retirement | Copy completion authorizes deletion, or a second migrator bypasses E5/E6 fences |
| E8 operator projection | Permission/action matrix, shared API/OpenAPI/CLI/UI projection, exact safe errors, confirmations, response-loss reconciliation and ETA/confidence | UI creates authority, unknown means failed/succeeded, or key-slot recovery timing is advertised as full restore timing |
| E9 evidence | Named case, owner, fixture, lane/profile, oracle, source/generation binding and retained result schema for every boundary | A skipped/unrun case passes; late effects, authenticated Range, grace boundaries or resource amplification are untested |
| E10 release | N/N−1 schema/envelope matrix, rollback fences, emergency stop, staged adoption and separate profile-specific evidence/claim gates | Installed capability, primitive availability or planning approval becomes a production/compliance claim |

## E0 sequencing and coverage denominator

Start with ordinary Drive files/chunks and mail attachments. The first source map
is deliberately partial until the following consumers and lifecycles are also
bound: generated previews, Office/WOPI, antivirus/DLP, indexing, export/legal
workflows, backup/restore, Provider migration and physical deletion/retention.
Meet recordings and third-party App volumes retain D8's separately gated adoption;
they still need inventory/disposition, not silent exclusion. Configuration secrets
and backup-purpose keys remain custody inputs, not ordinary Drive object keys.
The [initial Drive/mail map](storage-e0-drive-mail-byte-map.md) records this bounded
sample, existing test anchors and discrepancies requiring adjudication; it does
not close the E0 denominator or select the envelope format.

For every row retain the exact source paths/symbols and hashes, current physical
representation, business-authority owner, adapter boundary, consumer streaming
requirements, retention/pin owner, existing tests and missing named evidence.
Negative search alone does not prove a class has no byte path. A source change
invalidates affected rows without requiring another unrelated whole-tree scan.
Do not choose envelope/resource constants before the consumer map is complete.
The [posture vocabulary proposal](storage-posture-vocabulary.md) and its JSON
catalog separate requested policy, scoped evidence, maturity, coverage and action
admission. They are semantic planning inputs, not production schemas or completed
probe implementation; E1/E2/E8 still own exact bindings and qualification.

The next bounded records are the preview/Office byte map
and raw-message representation map.
They retain actual read ranges and whole-file hashes, not whole-protocol coverage.
The expansion evidence and future cases
track unresolved consumers and failure oracles before E0 can close.
The scanning/DLP/search map
separates plaintext byte consumers from database-field/metadata processing;
object-envelope coverage does not imply encryption of message text or indexes.
The SMTP sandbox/spool map
adds complete-message disclosure to external CAPE, per-recipient fan-out, local
temporary bytes and cancellation versus remote retention. Its seven proposed
oracles are unrun; external sample/report storage remains separately unqualified.
The export/legal-hold map
separates requested export metadata from verified output and logical holds from
effective backend protection. Seven unrun oracles bind filter failure, partial
streams, shared holders and reader/deleter interleaving to the common lifecycle.
The Mail hold/deleter map
preserves existing message-trigger/FK/transaction safeguards and identifies the
separate metadata-to-physical deletion window. Its MD oracles cross-reference
LP/EH/PD rather than counting duplicate tests as extra evidence.
The Chat/HR map distinguishes
shared bare-hash preview/receipt blobs from ordinary Chat's Drive versions/chunks.
Terminal approval state and preview-cache TTL do not imply equivalent evidence
retention; its five proposed CH cases preserve separate domain owners.
The Meet recording map
keeps Egress MP4 staging separate from admitted Drive versions/chunks and from
recording disposition. Five MR oracles cover complete-source verification,
reentry and protected cleanup; D8 adoption remains separately gated.
The closed CODE volume map
distinguishes persistent configuration, tmpfs working state, host credentials/
journal and authoritative Drive bytes. Five CV cases qualify actual contents,
drift and protected cleanup; install recovery is not general uninstall or restore.
The held/outbound mail map
closes the earlier inbound-callback source-wiring tail and identifies moderation,
hot/regular outbound queues and message rows as distinct reference owners. Its
explicit hash erratum is part of the source receipt, not source drift. Backup B0
consumes these distinctions in [its amended inventory](composable-backup-data-inventory.md);
whole E0, live queue durability and all-deleter protection remain unqualified.

The [E1 installer posture packet](storage-installer-posture-contract.md) expands
target binding, read-only observations, acknowledgement, bootstrap handoff and
failure oracles. Its exact source/schema/profile and numeric resource freezes
remain explicit prerequisites; it does not depend on selecting an E3 format.
The [E2 provider SSE packet](storage-provider-sse-qualification.md) separates
advertised capability, current enforcement evidence, operation and historical-data
coverage, safe probe cleanup and independent backup/key dependencies. Typed
profiles, exact source bindings and live qualification remain open; a byte
round trip alone cannot close its encryption-evidence gate.
The [shared protection/cutover packet](storage-lifecycle-protection-contract.md)
binds independent backup, migration, reader, domain-reference and compliance
lifetimes, including late object-store effects after executor expiry. It is an
invariant packet, not the concrete E3/E4/E5 schema/lock/provider-protocol freeze.
The [physical deletion packet](storage-physical-deletion-contract.md) requires a
durable exact-object obligation to survive logical metadata deletion, queue
cascades, provider failure and response loss. Its seven proposed PD cases preserve
existing reference/hold checks and separately address late remote effects.
The [plaintext-consumer packet](storage-plaintext-consumer-contract.md) binds
cache hits, authenticated Range, temporary bytes and external submissions to
current access/key authority. Its seven proposed PC cases do not select the E3
format or claim delivered/client-held plaintext can be recalled.

## E0 finite closure — current residual work

The eleven linked source maps establish bounded class/behavior coverage, not an
exhaustive callsite census. They are reusable evidence: do not restart their closed
wiring questions because an earlier historical report called them uninspected.
The next output is one machine-readable census/reconciliation register, not an
open-ended series of adjacent-source reports. No complete E0 candidate count is
established yet; the posture JSON is not that denominator.

The census register now holds its first
discovery pass:158 lexical Go object/retention/Range candidates across782 selected
non-test Go files. The next pass resolved157 source roles and excluded one comment;
all157 full E0 bindings remain unresolved. This is not the full E0 denominator.
Its source hashes, exclusions, extraction pattern and pending passes make the
next work resumable. Review ignored/excluded roots, alternate wrappers/POSIX,
SQL lifetime mutations, temporary/external handoffs, configuration/crypto and
non-Go/test bindings before declaring the universe frozen.
The C1 universe manifest
now pins the tracked-tree selector, first-party roots, source extensions,
generated/imported/test treatment, counts and selection digest. Worktree-only
source paths require an explicit scope delta; they are never silently folded
into the historical GO-OBJECT-01 snapshot. The finite class index
reconciles already discovered byte classes to one accountable owner and one
admitted, deferred or outside disposition. It does not claim that the 157
candidate rows have C2-C4 bindings.
The census interpretation records
transport-wrapper and runtime-capability traps without treating names as evidence.
The [E0-C3 compatibility proposal](storage-e0-drive-mail-byte-map.md#e0-c3-proposed-compatibility-contract--2026-09-08)
now specifies exact namespace mapping and upload-claim/reference separation, with
NC-01–06 oracles, including RFC8620 uploader privacy/quota/lifetime requirements.
Final legacy bindings and concrete claim schema remain open;
proposed behavior is not existing upload/backup parity or implementation approval.

| Unit | Deliverable and stop condition |
| --- | --- |
| E0-C1 universe | Freeze first-party roots, exclusions and discovered classes. The universe manifest and class index must reproduce their digest/counts and give every discovered class one owner and admitted/deferred/outside-envelope disposition; D8 CODE/Meet and external CAPE handoffs stay explicit |
| E0-C2 callsites | Seed from existing source registers; enumerate direct read/write/Range/copy/list/stat/delete/retention calls, temporary/external byte handoffs, relevant configuration/crypto helpers and governing reference/queue/hold mutations. Reconcile wrapper callers and startup/worker wiring. Every candidate has a disposition, not merely a search hit |
| E0-C3 consumers | Resolve namespace/inline/key/sentinel and producer/reader compatibility, access owner, full/Range/seek/buffering requirements and current bounds. Upload/refcount and live-versus-backup mapping mismatches need a specific proposed repair/refusal and oracle, not necessarily implemented fixes before design |
| E0-C4 lifetime edges | Close only named residual reference/deletion callers, including remaining cascades/partition retirement and protection writers. Bind every admitted/shared object to producers, reference owners, deleters and protection participants using LP/PD/EH/MD; future lock/schema details remain joint E3/E4/E5 work |
| E0-C5 reconcile and stop | Deduplicate test aliases and distinguish source assertions from proposed/runtime cases. Each unresolved row has one owner, exact source tail and acceptance question. Review the completed register; refresh only changed bindings |

### E0-C2 normalized register contract — v1 draft

The existing census is a source-role seed, not yet the normalized C2 register.
Every C2 projection must expose the following fields, even when a value is
`unknown`, `pending`, `not_applicable` or `excluded` with a reason. A nested
legacy shape may remain as provenance, but it cannot be the only representation.

| Field | Required shape and rule |
| --- | --- |
| `candidate_id` | Current snapshot key `path:line:column:operation`; a source revision keeps the prior key in `supersedes` and receives a fresh source hash. |
| `canonical_occurrence_id` | Deterministic logical occurrence key from path, lexical symbol/anchor, operation and normalized concrete receiver; identical keys merge pass provenance rather than creating another byte effect. It is distinct from the snapshot `candidate_id`, so line movement is a revision/alias decision rather than an accidental new byte effect. |
| `path`, `source_sha256`, `symbol`, `operation` | Exact source identity; a changed hash cannot silently reuse old evidence. |
| `inspected_range` | Ordered list of non-overlapping `[start,end]` line pairs (a single pair is a one-item list) or explicit `unknown`/`excluded` reason; disjoint evidence ranges are preserved, never collapsed across unread lines. |
| `call_kind` | One of `direct_provider`, `wrapper_provider`, `local_file`, `temporary_staging`, `external_handoff`, `reference_mutation`, `queue_hold`, `configuration_crypto`, `startup_worker_wiring`, `comment_excluded`, or `unknown` with a reason. |
| `receiver_binding` and `caller_wiring` | Normalized receiver/caller references or an explicit pending owner; startup/worker wiring is a first-class edge, not inferred from a method name. |
| `class_id`, `representation_namespace` | Class-index ID and namespace/inline/sentinel/encoding projection, or explicit pending/excluded reason; C3 may refine but cannot erase provenance. |
| `authority_owner`, `lifetime_owner`, `disposition` | One accountable owner each; disposition distinguishes `candidate_pending`, `explicitly_excluded`, `duplicate_alias`, `outside`, and `deferred` without claiming C3/C4 closure. |
| `evidence`, `unresolved_question`, `provenance` | Canonical source/range/hash references, one current question, and the ordered discovery-pass IDs that observed the row. |

The deterministic legacy projection is: `receiver`, `receiver_expression` and
`concrete_receiver` map to `receiver_binding`; `read_ranges` and an existing
`inspected_range` normalize to the ordered `inspected_range` list. A legacy
string shaped as `path:a-b,c-d` splits on commas into ordered inclusive line
pairs, must use the row's `path`, and must preserve every disjoint pair; an
unparsable or path-mismatched string becomes `unknown` with reason
`unparsable_legacy_range` rather than being collapsed across an unread gap.
`remaining_question` and `remaining_binding_question` map to
`unresolved_question`; `binding_ref` and `owner_boundary` seed
`caller_wiring` only as provenance/pending references, never as invented
authority. `operation_role`/`lexical_role` and `call_layer` map to `call_kind`
using this closed rule: `comment-only` → `comment_excluded`, `sdk-call` with a
concrete SDK client → `direct_provider`, `interface-call` or a receiver whose
method delegates to a provider → `wrapper_provider`, a POSIX/file receiver →
`local_file`, a staging/external receiver → `temporary_staging` or
`external_handoff`, and SQL/config/key/retention/worker signals → their named
`reference_mutation`, `queue_hold`, `configuration_crypto` or
`startup_worker_wiring` value. If the receiver/layer cannot decide between two
values, emit `unknown` with `ambiguous_legacy_shape` rather than guessing. The
raw nested role assessment stays attached as provenance.

Canonical identity is snapshot-stable by the current candidate key and
revision-aware by `source_sha256` plus `supersedes`. When two passes discover
the same key, the row is merged and both pass IDs/evidence references are kept;
conflicting source hashes create a revision record, not a silent overwrite.
Worked deduplication cases are mandatory: a wrapper delegating `GetObject` is
one occurrence with a wrapper edge; `SetRange` is an option edge, not a second
byte effect; a repeated SQL alias merges to the same reducer occurrence; and a
source move with a new hash is a superseding revision.

Keep three independent projections and never add them together: (1) C2 unique
candidate rows (`classified`, `explicitly_excluded`, `duplicate_alias`,
`unresolved`), (2) accepted C1 class owner/disposition rows, and (3) required
producer/consumer/authority/lifetime edges. C2 completion means no unowned
candidate in the selected pass and an explicit remainder for the next pass; full
E0 completion still requires zero unknown admitted-consumer and lifetime edges.

Each census pass carries `owner`, `input_selector`, `deliverable`, `acceptance`,
`rejection` and `handoffs`. A pass cannot be marked complete from a lexical
search alone. The first semantic C2 leaf after this contract is selected by the
queue and must not repeat the eleven existing source maps.

Register rows carry at least id, path, symbol, operation, source hash, inspected
range, class, physical representation/namespace, direct-or-wrapper classification,
caller/wiring, authority owner, lifetime owner, disposition, evidence link and
unresolved question. Keep three independent coverage measures: unique candidate
callsites (classified + explicitly excluded + unresolved), discovered class
dispositions, and required producer/consumer/lifetime edges. An exclusion needs a
reason; duplicate narrative reports or aliases cannot increase coverage.

E0-C1 closes only when the universe manifest reproduces independently, every
discovered class in the class index has one owner/disposition, and no root or
exclusion is implicit. This is deliberately weaker than full E0 closure.
E0-C2/C3/C4 remain responsible for candidate-level authority, consumer and
lifetime bindings. Full E0 closure requires zero unclassified candidates and zero unknown admitted-consumer
or lifetime bindings within the frozen universe. New discoveries enter an explicit
scope delta. This permits concrete E3/E4/E5 design; it does not approve a format,
establish runtime correctness, admit D8 data or close the full Storage plan.
Actual CODE contents may remain unknown and unadmitted pending D8 qualification.
Live CAPE retention, Egress completeness, backup/restore and crash/concurrency
proof belong to owned later cases rather than impossible pre-implementation tests.
Retroactive mailbox-hold semantics must first be established from authority; any
material policy change remains a grouped final decision, not an invented E0 default.

## E4 authority correction

[ARCH-015](../adr/ARCH-015-platform-crypto-sm4-key-custody.md) explicitly concerns
client offline-store crypto; [ARCH-016](../adr/ARCH-016-offline-vault-key-custody-model-m.md)
governs client OS-keystore custody and cache re-provisioning. They remain client
constraints, not the server runtime-slot/recovery-package authority.

The server specification must be explicitly authored under Storage D1/D7/D9/D10,
with D11/D12 covering the optional KMS boundary, then reviewed jointly with E3/E5.
Its record must bind purpose-separated database-sensitive-configuration,
object-storage and backup-integrity roots, registered future roots, runtime
wrappers, recovery wrappers and generation keys. “Re-sync the cache” is not a
server disaster-recovery procedure. Local keystore implementation, package format
and crypto parameters remain technical review outputs, not invented approvals.

## Decisions and evidence boundaries

No new user choice is needed to write the accepted default profile. Resolve
source-backed schema, locks, clocks, transition tables and test design through
Astra architecture/security review. Collect a material choice only if the proposal
changes scope isolation/deduplication, recovery custody, downgrade eligibility,
the accepted grace, or admits optional KMS/HSM/BYOK/SM4/online migration beyond the
approved boundary. Operator approvals for activation, protection downgrade and
final retirement remain required at execution time; they are not routine planning
section approvals.

This map has no numeric readiness score. The predecessor Storage plan remains
HOLD until these outputs and the applicable complete Autoplan stages have genuine
review evidence. Outside-review unavailability is never a pass.

## Read provenance

The inventory assessment used the full 448-line pre-edit Storage plan
(`1ec0e0b828873c20644bd31a29e4ddbdc0c5b5f46015796806b9847d818fd094`),
the Provider boundary at lines429–540 and610–741, and the complete two client ADRs.
Root independently read the full Storage plan and both ADRs. The workstream map
is documentation analysis, not a fresh whole-product source audit or crypto review.
New E0 source rows must carry their own bounded read/hashing evidence.
