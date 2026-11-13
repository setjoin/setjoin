# Restore, replica and backup-retention participation

Date: 2026-09-07. Status: bounded source inspection and proposed acceptance packet;
not implementation, a complete security audit, or recovery qualification.

Authority remains the existing recovery/backup owners and domain reducers:
[B1 snapshot](composable-backup-snapshot-contract.md),
[B2 inactive restore](composable-inactive-restore-contract.md), and
[RR records](composable-recovery-records.md). This extends BP07/BP08 residuals in the
[object-participation map](composable-backup-object-participation.md); it does not
replace first-boot disaster restore with a live plugin importer.

## Current paths and concrete boundaries

| ID | Source-observed behavior | Consequence for the proposed integration |
|---|---|---|
| RT01 Empty-target restore | [CLI orchestration](../../mailctl/restore.go:273) calls gateway blob restore, then schema reset, then dump download/`pg_restore`. [Reset](../../mailctl/restore.go:329) locks `public.users` ACCESS EXCLUSIVE, rechecks zero users, drops/recreates public schema and commits. The dump action is a later step, not part of that transaction. | Preserve this separately authorized destructive workflow. It is not a same-installation selected-copy API. Do not use its owner connection, reset, raw dump or setup socket as a plugin permission bypass. Startup/dispatch containment throughout the multi-step restore remains a separate trace, not proven by the users lock alone. |
| RT02 Partial blob result | [Setup](../../mailserver/internal/admin/admin_setup.go:275) returns HTTP 200 with `Status=completed` and nonempty `Errors` for per-blob failures, while recording a failed job via `retErr`. [CLI](../../mailctl/restore.go:277) checks the transport error before reset, but the returned `Errors` only become a CLI error at [the end](../../mailctl/restore.go:436). | Concrete source-level ordering gap: a partial blob response can reach schema reset/dump restore before the CLI reports failure. Add a focused regression first when implementation is authorized; require complete prerequisite bytes before destructive continuation. Do not relabel this as repaired by the proposed selected-copy design. End-to-end reproduction has not run. |
| RT03 Restore byte producer | [RestoreMissingBlobs](../../mailserver/internal/restore/engine.go:310) validates hash grammar, HEADs source, hashes a first source read, streams a second read into canonical `blobs/<hash>`, checks transferred size and hashes destination before incrementing restored count. [Manifest restore](../../mailserver/internal/restore/engine.go:281) checks counts/duplicates and verifies existing primary bytes before skipping. | Preserve independent destination verification. First-read verification does not bind a mutable second read; failed post-write verification can leave target bytes without successful acceptance. A new staged profile needs exact source version/digest binding and destination protections before writes, plus owned cleanup/reconciliation. This Mail producer does not implement Drive scoped-key/ordered-stream registration. |
| RT04 Job admission | [StartRestoreJob](../../mailserver/internal/restore/engine.go:227) takes a transaction advisory lock, checks pending/running jobs, inserts running and commits. [FinishRestoreJob](../../mailserver/internal/restore/engine.go:265) updates by ID. | This is single-flight admission, not a lock held across byte I/O or the proposed per-operation generation/lease and publication fence. Reuse the owner, not an unsupported claim that current jobs already satisfy RR2. |
| RT05 Config/trust | [DownloadManifest](../../mailserver/internal/restore/engine.go:62) parses a bounded latest index and verifies embedded integrity. [Verifier](../../mailserver/internal/backup/engine.go:83) accepts unsigned schema-0 legacy manifests and checks schema-1 signatures against their embedded key. [RestoreConfig](../../mailserver/internal/restore/engine.go:87) checks matching manifest only if HEAD succeeds, then calls `restore_config_apply(...,false)` in sorted-key order in one transaction. | Embedded integrity is not independent source trust. Preserve the restricted legacy workflow and reducer policy; selected recovery requires the admitted complete immutable manifest/trust reference and typed parser. Do not infer that legacy format or failed HEAD grants general publication, plaintext inspection or activation. |
| RT06 Optional replica | [replicateToBackup](../../mailserver/internal/backup/engine.go:393) is launched asynchronously after primary completion. Same-size replica objects are skipped without digest verification in that branch; newly copied blobs are verified. Errors accumulate/log, but the loop still attempts all five index/config copies including latest. [copyObject](../../mailserver/internal/backup/engine.go:446) reads metadata fully into memory and PUTs without independent destination reread. | Current primary success does not qualify a replica recovery point. A partial or same-size-corrupt replica must not acquire the new verified-copy claim. Bind immutable artifacts, verify every expected object (including reused objects) and their metadata, then accept a destination-specific publication receipt. Keep optional replica failure distinct from primary failure unless an explicitly admitted policy requires that destination. |
| RT07 Retention deletion | [ApplyRetention](../../mailserver/internal/backup/engine.go:602) deletes three timestamped index/config objects per selected run, logs object errors, then deletes its DB row and increments `pruned` if that DB operation succeeds. No blobs or mutable latest keys are deleted in this body; no restore-read protection is consulted there. | Indexes/config are recovery-critical byte participants even when blobs survive. New retention must honor active capture/replica/restore holds, record per-object pending/unknown/retained/deleted outcomes and reconcile before claiming cleanup complete. Existing `pruned` is not verified object deletion or reclaimed byte count. Trace explicit admin deletion and backend lifecycle separately. |
| RT08 GFS selection | [runsToPrune](../../mailserver/internal/backup/retention.go:41) retains newest runs in the configured day/week/month buckets; unparseable timestamps are retained. Input from [completedRuns](../../mailserver/internal/backup/engine.go:577) orders by created time and ID, not parsed manifest time. | Keep conservative unclassifiable retention; qualify ordering assumptions, ties and timestamp identity before reusing selection. Selection is a candidate list, never authority to delete protected objects or bypass backend WORM. No change to accepted retention durations is proposed here. |

RT02, RT06 and RT07 are source-backed behavior gaps for targeted remediation/claim
gating, not reproduced incidents or findings assigned a new security severity.
Do not wait for the entire composability refactor to test and fix a validated
existing defect. Bind any overlapping imported scan finding by source identity in
the existing security-remediation owner; this paper creates no duplicate finding ID.

RT01 also has a concrete prerequisite-ordering gap: the CLI checks for `pg_restore`,
creates its temporary dump and downloads it only inside the action called after
schema reset ([closure](../../mailctl/restore.go:390)). The targeted fix must stage
and validate the exact admitted dump, tool/profile and required local resources
before irreversible reset; failure there must leave the schema untouched. Successful
preflight does not guarantee later execution or eliminate crash recovery. Keep the
verified artifact bound through execution and retain an explicit interrupted-restore
state/recovery path for failures after reset. Exact independent dump trust/format
validation and installed-schema containment remain owning freeze work.

## Proposed dependency and publication rules

1. Bind an operation to one immutable recovery-point identity and its approved
   destination/profile. Read a mutable latest pointer only to select that identity;
   subsequent fetches cannot mix runs. Dump, configuration, manifests, wrapped key
   dependencies and data streams belong to one declared recoverable closure.
2. Register recovery-source read protections before consumption. Retention consults
   them under the same admission protocol as replication and publication. Protect
   non-content-addressed metadata as well as blobs. A reference to an expired index
   is not a recoverable point merely because all data hashes remain in S3.
3. Replica progress is per destination: queued, copying, verifying, verified or
   failed/unknown, with exact expected/verified counts. These are proposed states,
   not today's stored schema. Reused same-size bytes must still have trusted
   source-bound digest evidence; a HEAD alone is not enough. Publication follows
   the same accepted immutable seal, never an independently altered manifest.
4. Existing process-local replica goroutines are not durable receipts. Restart must
   reconcile exact accepted work and destination state. No latest publication on
   failed verification. Concurrent newer publication must not be overwritten by
   an older worker; freeze the authoritative sequence/CAS mechanism for the
   admitted adapter. Adapters without it cannot offer ordered latest semantics;
   immutable verified point selection remains the authority.
5. Selected restore writes only through inactive domain-owned staging with RR3
   protections. Do not borrow RT01 schema reset or RT03 direct Mail PUT as a Drive
   importer. Dedup requires the complete destination store/scope/generation/key,
   not just the digest. Unknown same-key DELETE outcomes continue to block reuse.
6. Retention first stops new selection of an expired point, while keeping its
   discoverable retirement/cleanup receipt and already admitted readers protected.
   Physical cleanup follows reconciliation of those readers and backend constraints;
   UI distinguishes retired, deletion pending, retained and deletion verified.
   Keep minimal control-plane tombstones required for retries/audit; never delete
   audit or protection records by cascading the run row. No policy-duration or
   automatic deletion decision is added by this ordering proposal.

Use the [joint resource envelope](composable-joint-resource-envelope.md): replica
streams, whole metadata buffers, repeated verification reads and restore temporary
dumps must be counted. Per-file streaming does not make metadata buffers bounded.
Freeze parser byte/cardinality limits, cancellation/response-loss behavior and
updater/restore admission together; no production limits are inferred here.

## Ordered implementation packet and independent oracles

All RT-T names are proposed selectors, not existing executable tests or results.
Implement under the existing backup/restore/CLI owners after separate authorization.

| Order / proposed case | Injection and required outcome |
|---|---|
| 1 / RT-T01 Prerequisite failure | Gateway HTTP 200 with nonempty blob errors, explicit failed/unknown status, and hard transport failure: zero schema-reset/pg_restore execution calls. With RT-T07 preflight complete, the positive path preserves blob completion → reset → pg_restore execution order. Include existing-target refusal and full/config/blobs separation. |
| 1 / RT-T07 Pre-destructive artifact preflight | Missing/incompatible restore tool, unreadable/corrupt/wrong-point dump, insufficient admitted staging space: zero reset/pg_restore execution calls. Positive path stages and verifies one immutable dump before reset and executes those same bytes. Substitute/truncate the staged file or fail after reset: reject changed bytes, expose interrupted recovery, never claim rollback or completed restore. |
| 2 / RT-T02 Source/destination identity | Replace source between verification and copy; same-size corrupt target; short read; late PUT completion; duplicate/invalid hashes. No verified/published claim for invalid bytes; preserve unresolved target effects and other operations' bytes. Selected profile proves owned staging before canonical promotion. |
| 3 / RT-T03 Pinned point | Change latest during manifest/config/dump fetch and retire the selected point during a restore. One immutable closure is consumed or admission fails. Already admitted readers remain protected; stale/new selection cannot silently redirect to another point. |
| 4 / RT-T04 Replica qualification | Same-size corrupt existing replica, failed blob write, metadata corruption and latest-copy error: primary receipt remains independent and replica is not verified. Reconcile success only after independent reconstruction. Race old/new workers; stale publication cannot regress current selection. |
| 5 / RT-T05 Retention outcomes | Denied/WORM-protected DELETE, network response loss, partial index deletion and DB-record failure. Show exact retained/pending/unknown counts; restart does not lose work or report bytes reclaimed from row deletion. Holds protect restore/replica metadata and never extend to unrelated deletion targets. |
| 6 / RT-T06 Import and authority | On a populated installation the selected-copy path never calls schema reset/pg_restore, revives source jobs or exposes ordinary content. Stage-only operator cannot inspect/publish; current-authorized publish is one receipt with complete graph/bytes. This composes existing IR/RR cases rather than inventing new privilege. |

For each case retain input hashes, exact selector, fixture/adapter identity,
boundary trace, expected artifact inventory and an independent read/reconstruction
oracle. Missing/skipped/flaky cases remain unavailable evidence. Use deterministic
fakes for ordering and controlled adapters for delayed effects; neither replaces
independent disaster recovery or backend retention evidence.

Existing CLI test bodies read at 290–405, not run:
`TestGatewayRestore200WithErrors`, `TestOrchestrateRestore_FullRestoresBlobsBeforePgRestore`,
`TestOrchestrateRestore_ResetFailureStopsBeforePgRestore` in
[CLI tests](../../mailctl/restore_test.go). The partial-response test verifies error
array decoding with successful transport; the orchestration samples cover happy
ordering and reset failure, not that combined partial-result prerequisite. Other
restore test names were discovered without reading their bodies:
`TestRestoreMissingBlobsRejectsCorruptDestinationWrite` and
`TestRestoreMissingBlobsPropagatesSourceAndDestinationBoundaries` in
[restore tests](../../mailserver/internal/restore/manifest_restore_test.go).
These are starting points only; their names do not establish RT-T coverage.

## Exact read scope and unresolved closure

Root inspected `mailctl/restore.go` in full (1–443); backup `retention.go` (1–134)
and `store.go` (1–32) in full; backup `engine.go` 1–110,388–458,550–629;
restore `engine.go` 1–140,225–392; setup handler 240–339 (EOF); CLI tests 290–405.
B1 snapshot, B2 inactive
restore, RR records and BP map were read in full. File hashes are in the
input receipt;
hashes bind bytes, not broader inspection or runtime coverage.

Unclosed: full setup/route/socket authority chain, driver versioning/lifecycle/WORM
and request-cessation semantics, dump download/authentication/helpers, deployed
schema/migration/trigger chronology, explicit admin deletion, source trust custody,
all restore readers/dispatchers and companion Drive paths. Read source-owner DOX
and close these before implementation freeze. The new document is not a full
first-boot security audit or proof that a completed job can recover all apps.

Task `sj-plan-storage-tails-20260907` is documentation only; no tests, services,
temporary builds, databases, object stores or Git operations were performed.
