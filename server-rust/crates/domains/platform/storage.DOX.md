# Storage execution (#459)

Parent: [Platform](DOX.md). HTTP adapter: `bins/gateway/src/platform_jobs.rs`;
process owner: `bins/gateway/src/platform_storage.rs`.

Storage metadata, blob catalog repair and migration jobs are server-wide objects.
Go gates status with Mail-console permissions and mutations with `system.config`;
a domain-scoped holder passed those gates. Owner-approved security fix 2026-11-05 (#539): scan start,
reconcile, migration start and migration cancel now also need an organization-wide `system.config`
grant (`setjoin_platform::storage_org_wide`, SQL `admin_org_wide_grant`); a domain-scoped or
OU/set-confined holder gets the bare 403 and a `console.denied` row. Reads keep Go's gates and (#542) also need an organization-wide grant of a gate permission (`storage_read_org_wide`; mutants `storage-read-scoped-*`, `scripts/test-secfix11-mutants.py`). The
`*-scoped` goldens of those four routes are pinned in `platform/divergences.json` with reviewed
`platform/security/` expectations; mutants `storage-scoped-grant-{scan,reconcile,migrate,cancel}`
(`scripts/test-secfix10-mutants.py`). Request bodies never supply ownership.
The sealed actor binds request transactions and operation receipts. Background
maintenance uses `DB_WORKER_DSN` (fallback `DB_DSN`), never pooled `SET ROLE`.

Each request write is one receipted statement because each Go transaction is that
single statement: scan admission, blob reimport and reimport-count update. There
is no new audit row, notification or reducer. Reconciliation deliberately keeps
Go's separate commits and best-effort errors, so one failed blob does not undo
successful earlier imports. An unknown COMMIT returns the opaque operation for
lookup and never claims success.

Status derives the master address from shared S3 configuration, replacing an
explicit S3 port with 9333. The master client has Go's 30-second timeout and
accepts valid JSON even on a non-2xx HTTP status. A missing/bad cluster document
answers Go's 503; directory errors leave version/topology/volumes empty. Legacy
map topology is projected; the newer `DataCenters` array is ignored as in Go.

DR admission detaches from the request and starts one two-hour task. It loads
all blob keys, walks the bucket, saves progress every 1,000 objects (clearing the
batch even if persistence failed), reports remaining keys as missing and compares
refcounts with attachment counts. SQL counter values are explicitly bigint at
the driver boundary. Go's list-error/completed-scan behavior and JSON null detail
append are preserved. Late SQL cursor errors retain decoded prefix rows and do not
fail the scan, matching Go's omitted Rows.Err checks. Reconcile requires completed
status, HEADs only nonempty orphan keys, defaults empty content type to application/octet-stream, and counts
a conflict/no-op INSERT as reimported, including on repeat.

The process registry covers pending admissions and live tasks. Shutdown closes
admission first, cancels service-owned work and waits for observed exits before
closing dependencies. Its 20-second drain timeout retains ownership and waits;
the executable's outer 60-second overrun terminates the process. A failed or
interrupted scan can retain its running row, as frozen Go does. HTTP inventory
ownership prevents Go from admitting a second copy of these on-demand jobs.

Oracle: `setjoin-gateway --test platform_storage_runtime`; existing nine-route
regressions: `--test platform_jobs_storage`. Use the documented disposable DSNs,
`REQUIRE_DB=1` and `--test-threads=1`. The shared Platform runner records the real
covered Go process behind the front door, fake S3 and (for status) master on
127.0.0.1:9333. Replay needs no Go upstream and asserts F08 proxy count zero.
Goldens under `tests/conformance/platform/goldens/storage-*` are create-only;
row companions observe committed mutations. Route mutants change real responses.

## Migration owner

The process `Runtime` owns starts, cancellation and startup observation. Admission
inserts source/target/status in one actor-receipted statement. Each run uses the
shared S3 transport posture with Go's `STORAGE_ACCESS_KEY`/`STORAGE_SECRET_KEY`
source credentials; target creation uses the `STORAGE_*` configuration. Provider
labels and case-sensitive target validation match Go.

Backfill streams the `ref_count > 0` catalog in sha order on a separate worker
connection from its progress writes. Verified existing targets are skipped only
after a size+SHA-256 read-back. Source bytes stream through a private 0600 staging
file, keeping memory bounded; target writes are durable/atomic through the
foundation store. Source and target integrity failures withhold cutover and
remove unverified objects best effort. Progress is saved every 1,000 successful
copies; Go's successful-skip branch omits that periodic write. Final total equals
successful copies, including when other objects failed. Errors are enumerated in
logs, never written to `error_message`. Success rests at `cutover`, without a
completed timestamp, dual-write path or driver switch (Go has none).

Cancel checks the DB read model, then joins only a run registered in this process.
Missing rows are 404; terminal/cutover and unowned transitional rows are 409, with
no status mutation. The run selects/persists its own `cancelled` outcome. A 10-second
join expiry is 503 and retains the live run and transitional row. Service shutdown
selects `failed`, rather than an admin cancellation. Local filesystem calls are
joined: dropping an async filesystem future can leave blocking work running.
Cooperative network waits observe cancellation, and row boundaries stop accepted
work. Cancellation racing a selected cutover is a 409 after the join.

Startup `recover` reads transitional rows before HTTP admission and logs them;
without Go's future exclusivity attestation it never reclaims another executor's
job. These are on-demand jobs admitted by the transferred HTTP routes, rather
than independently scheduled singleton workers; Go's idle process registry and
read-only startup observer may remain until Go deletion.

The migration recorder mounts an owned workdir at `/gofree-plat3b-target`; both
implementations write the same host `mailblobs` directory. `common::go_oracle`
supports per-case `--workdir` and a read-only owned-container descriptor probe.
The FIFO drain case observes an actual blocked target reader, records Go's 503
and unchanged row at response time, then releases it and observes terminal state.
Fixture cleanup joins native jobs even when comparisons fail.

Target query bytes preserve invalid UTF-8 through Go-compatible quoted errors. The AWS
backup target defaults to us-east-1 regardless of AWS_REGION; OSS signs with an empty
region. AWS requests use SDK operation query tags. A nonempty HTTP AWS endpoint
cannot copy the unseekable migration stream (the Go SDK checksum error); existing
verified targets still skip successfully before this failure. HTTPS retains streaming.

The late-cursor-error oracle temporarily replaces the assigned database's blobs table
with an ordered view that raises on a later row. Cleanup restores the table before
other fixture teardown. No production schema changes are needed.
