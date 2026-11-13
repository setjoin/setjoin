# Joint resource envelope — EN-T10 / D5

Date: 2026-09-07. Status: proposed qualification protocol; admission values are not
production defaults, measured capacity or implementation approval.
Owner: Office + Drive/Backup + updater; existing domain coordinators retain authority.
Authority: CP0 freeze slice,
[snapshot contract](composable-backup-snapshot-contract.md),
[Office session contract](composable-office-session-contract.md).

## Problem and boundary

Individually bounded operations can collectively exhaust database connections,
temporary disk, memory or object streams. Qualify their overlap on one recorded
host/profile; do not add four independently measured maxima or claim that a preview
timeout reserves memory. Keep admission/budget projections shared, but permissions,
leases, receipts, cleanup and irreversible decisions with their existing owners.
This is not a new universal scheduler, quota authority, plugin resource grant or
replacement for Connectivity QoS. Never shorten existing lock-through-I/O sections
solely to improve a benchmark; their replacement needs the object-participation gate.

## Observed cost anchors — bounded source reads

| Input / inspected extent | Current fact | Budget consequence |
|---|---|---|
| [main.go](../../mailserver/cmd/mailserverd/main.go:319), 300–365 | Request pool plus separate worker/owner pools when configured DSNs differ; both extra calls receive `DBMaxConns`. | Count actual pool instances/roles across processes. Sharing a pool is not three reservations; three created pools are not one ceiling. |
| [pool.go](../../shared/pgxutil/pool.go:42), full file | `OpenPool` assigns MaxConns, minimum roughly one quarter (at least1), and nonpositive argument fallback20. | Client pools, PgBouncer backends and PostgreSQL server slots are distinct resources. Do not infer the server ceiling from the helper. |
| [config.go](../../mailserver/internal/config/config.go:586), 575–595 | Mailserver post-processing sets zero `DBMaxConns` to50. | This default differs from the helper fallback; neither is a verified whole-installation connection budget. |
| [WOPI handler](../../mailserver/internal/office/handler.go:195), 1–95 and 190–290 | 200 MiB request cap; 4 MiB buffer plus copied chunk; per-chunk staging then scoped commit/promotion and cleanup, followed by final save reducer. | A 64 MiB save is below this transport cap, not automatically below policy/quota limits. Count chunk copies, adapter buffers, overlapping requests and canonical staging; the cap is not a process-wide memory reservation. |
| [preview.go](../../mailserver/internal/drive/preview.go:42), 1–230 | 15s ticker, batch5, serial render loop per observed worker; 2min command-timeout constant; source temp file, output directory, then whole-PDF `os.ReadFile` and sequential chunk PUTs. | Batch5 is not five concurrent converters. Multiple instances need counting. Reserve source+output disk and PDF memory; converter/SDK overhead and command-timeout enforcement require further tracing. |
| [backup engine](../../mailserver/internal/backup/engine.go:198), 150–280 | Snapshot materializes live Mail blob references into a slice; copy loop streams each blob and then rereads destination for size/hash verification. | Inventory memory grows with count; readback costs I/O. This is not Drive/full-backup coverage or proof of process-wide single-copy concurrency. |
| [recovery capture](../../mailctl/backup_recovery.go:435), 435–565 | Direct connection and read-only repeatable-read transaction; exported snapshot, materialized inventories/config and `pg_dump` subprocess before the shown function tail. | Count exporter and dump connection/process/disk separately; imported snapshot depends on exporter lifetime. Remainder/caller cleanup and total duration are not independently re-audited here. |

Input hashes and read scopes belong in the companion receipt. No live configuration,
credential, customer data, physical host capacity or actual allocation was inspected.
Remaining inventory includes transitive WOPI staging/proof/cleanup costs, updater artifact unpack/
rollback paths, backend multipart buffers, PostgreSQL/PgBouncer settings, other
workers and subprocess limits. Unknown participants cannot be assigned zero cost.

## Single profile record to freeze

Bind source/schema/fixture digests, host OS/architecture, RAM and CPU limits,
filesystem/mount topology and usable capacity, backend identity/digest, effective
pool/worker counts and configuration fingerprints. Never retain secret values.
Two directories on one filesystem share a budget. Local S3 on that filesystem
also consumes it; remote capacity is a separate budget, not free staging space.
Record compressed, expanded, retained-old and rollback bytes separately.

| Resource | Proposed admission calculation / acceptance |
|---|---|
| Memory | Baseline committed allowance + sum of concurrent per-operation peaks + explicit headroom must fit admitted memory. Include child processes, PDF buffers, inventories, SDK multipart buffers and OS/backend costs. Derive peaks from bounded inputs and measurement, not file size alone. |
| Disk, per filesystem | Measured available bytes already exclude materialized data, including retained old artifacts. Subtract only existing reservations for additional, not-yet-materialized bytes; the remainder must cover new peak incremental bytes plus that filesystem's floor. Track remaining reservation as materialization progresses atomically, without counting both the written bytes and their original full reservation. Count coexistence of source/output/staging/unpack/rollback; do not credit deletion before verified. Same physical bytes count once, distinct copies separately. |
| Database | Enumerate client-pool instance ceilings and backend/direct slots independently. Reserve control/reconciliation and normal request progress; auxiliary pools cannot bypass the aggregate backend limit. Include dump/export connections and restart overlap. |
| Object streams | Bound simultaneous GET/PUT/verification/multipart operations per endpoint and adapter, including SDK retries. Byte-rate/latency budget is distinct from open-stream count. Preserve unknown external-effect obligations after request cancellation. |
| CPU/processes | Count converter and decompressor subprocesses alongside gateway/database/store. Bound queue depth and conversion slots; no unbounded goroutine/process creation as overflow. |
| Time | Separate admission wait, snapshot/barrier hold, command deadline, observer wait and recovery duration. Use durable approved deadlines where required; restart does not reset them. KMS one-hour policy is not a benchmark setting. |

Admission is atomic against the relevant shared budget and current profile generation;
a UI free-space sample is advisory. Exact record/helper ownership and serialization
must be allocated before implementation. Reserving capacity does not authorize an
operation. Unknown cost/profile mismatch refuses **new optional admission**, while
existing accepted obligations remain accounted for and reconciled safely.

Disk-accounting examples (synthetic GiB): with 10 available, an existing 4 GiB
reservation already materialized by 2 leaves 2 unmaterialized; admitting a new
3 GiB peak with a 1 GiB floor checks `10 - 2 >= 3 + 1`. A retained 2 GiB rollback
file already on disk is included in the measured 10 available and is not subtracted
again. If two new directories share that filesystem and need 3 and 4 GiB peaks,
check their combined demand: `10 - 2 >= 3 + 4 + 1`; do not admit each against a
separate fictitious 10 GiB budget. Unknown pending deletion never increases free
capacity in these calculations.

## Finite first rehearsal — explicit proposed numbers

The following values define a small synthetic workload, not a claimed minimum host,
deployment preset or SLA. Run only after a resource preflight establishes room for
it without degrading the local Mac; native Linux/large workloads follow runner policy.

| Dimension | Initial fixture / reason |
|---|---|
| Overlap | One accepted Office save, one selected-backup copy, one preview conversion and one updater artifact stage; one independent second-scope request stream. This is the minimum four-way overlap, not the supported maximum. |
| Office input | One 64 MiB synthetic document body, with exact-key response-loss variant separately from no-key replay. Fix actual backend-qualified format and deterministic content; compressed file size does not bound converter output. |
| Backup inventory | 1,024 references over 256 distinct 4 MiB synthetic objects (1 GiB physical source payload); repeated references exercise dedup/accounting. Verify actual distinct counts, not iterations. This is a future selected-backup fixture, not supported by today's Mail-only list by assumption. |
| Preview | One 16 MiB source with a fixture-enforced 64 MiB output ceiling; overflow must refuse/abort safely. The ceiling is proposed harness/input qualification, not an existing product limiter. |
| Updater | One 128 MiB transport artifact with 256 MiB expanded fixture bound; retained prior artifact/rollback requirements add their actual sizes. No real update or activation during this document task. |
| Samples | Two warmups and 20 measured overlaps plus 20 same-profile baseline samples; capture each raw result. Failed/skipped/retried cases cannot be omitted to improve percentiles. |
| Fault set | Pressure before admission; pressure after acceptance; source/target on same filesystem; exhausted worker/backend pool; delayed GET/PUT/DELETE; duplicate worker; cancellation; restart before/after seal; stale executor and lost response. |

Bind each baseline/overlap pair to identical logical starting data, current-version
heads, pending work, destination dedup state, cache mode and expected read/write/
verification byte counts. Baseline runs the same work without overlap; overlap
requires observed simultaneous occupancy, not merely four launch requests. Restore
disposable fixture state between measured samples and allocate fresh operation keys
for fresh work. Retries within a sample retain their original key. Warmups must not
prepopulate a measured destination or turn a new save into replay. Explicit warm/
already-copied/replay scenarios form separate named cohorts, not faster samples in
the fresh-work distribution. Record fixture reset receipt and actual bytes per sample;
unmatched initial state or missing overlap makes the sample invalid, not passing.

These numbers make the fixture reproducible without pretending to know its RAM,
latency or throughput. Freeze real per-resource reservations and absolute termination
bounds **before running it**; a missing bound is a preflight failure. Use the snapshot
contract's30s/5s/120s synthetic lease/heartbeat/observer clocks only for its own
state-machine cases, not as universal conversion/copy deadlines. Qualification
must also include an independently specified cardinality/file-size scale ladder;
passing this fixture never permits10,000-user or HA claims.

## Proposed outcomes and test oracles

| Case | Required independently observed outcome |
|---|---|
| JE-T01 preflight | Missing inventory, cost bound, filesystem identity or backend slot budget refuses new work before irreversible effects; show exact limiting resource and safe action, not generic failure. |
| JE-T02 overlap | Record peak RSS/child memory, filesystem bytes/reservations, pool waits/backend slots, stream count, CPU and progress. Persisted Office version, backup inventory/digests and updater stage receipt match intended inputs. Preview status alone is not byte verification. |
| JE-T03 pressure after acceptance | Stop/postpone new optional work at its safe boundary; preserve accepted save, pins, unknown-delete reservations, seal/publication and rollback bytes. Never drop pins or kill an accepted operation merely to meet a memory graph. |
| JE-T04 restart | Rebuild reservations from durable obligations before admitting more work; stale workers cannot release another generation's resources. One immutable seal/result, no duplicated quota or invisible permanent pause. |
| JE-T05 fairness/recovery | Independent authorized scope continues within its predeclared bound; backlog eventually drains within its own qualified bound. Admission fairness must not invent cross-tenant visibility or privileged reserve access. |
| JE-T06 refusal and UI | UI/CLI show waiting/running/reconciling/blocked separately, actual retained bytes and unresolved outcomes; estimates are labelled. Observer timeout leaves execution status unchanged. |

JE IDs are proposed cases, not installed selectors. Before code approval assign
exact test paths, metrics collection, diagnostic thresholds, profile values and
reviewed reservation owner; before rollout retain source-bound measurements and
independent outcome checks. Do not introduce a new public configuration schema by
copying the conceptual columns. Current evidence is source inspection only.
