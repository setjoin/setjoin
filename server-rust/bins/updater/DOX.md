# Updater/recovery process (#358–#359)

`setjoin-updater` is the privileged standalone updater; it is never linked into
the server. `main.rs` wires `run`, `recover`, `verify`, initial layout adoption,
and the inactive-only installer handover. Recovery and update execution are native;
managed Office app execution remains owned by Platform #300. Never swap from Go
while an update is active: the journal formats are deliberately incompatible.

## Signed metadata and immutable cohorts

`verify` uses `setjoin-release-format` for canonical Ed25519 verification. Its
production default is the two-signature floor. Explicit clock, threshold,
metadata checkpoint, channel/version/target and test-root options support offline
diagnostics and immutable Go replay. No signing keys are accepted.

Parity: Go's run daemon does not reverify signatures. Its root-owned publisher
store has already passed trust policy; run binds the reducer-authorized release
ID and canonical digest and rechecks freshness on every use. `stage.rs` preserves
that boundary. The store, release directory and inventory must be root-owned,
real, non-group/world-writable, bounded single-link regular files. Only the eight
required core/evidence targets, migration and compatible sidecar targets install.
Per-artifact size/SHA-256 and migration checksums are verified. Webmail uses the
unmodified `tar` crate with traversal/link/special-node/mode/entry/expansion limits.
Staging checks free space, writes a Go-compatible content digest/evidence, makes
the tree immutable, fsyncs and renames it. A repeat verifies the entire installed
tree. Activation fsyncs `previous` before atomically changing `current`; adopted
legacy evidence remains usable as a complete previous cohort.

## Run and authority

`run` takes Go's core flags: state-dir, release-store, dsn-file, execution-config,
owner-dsn-file, recovery-access-key-file, recovery-secret-key-file,
recovery-hmac-key-file, probe-credential-file, executor-id, poll-interval and once.
Configuration paths/defaults and camelCase version-1 execution JSON mirror Go.
Absent/disabled config observes without claiming. Enabled execution requires the
`setjoin_updater` credential and a distinct migration owner; secrets are private
LoadCredential files. Recovery HMAC key bytes are never trimmed. Cleartext S3 is
restricted to Go's exact loopback hosts. `setjoin-backup` supplies authenticated
recovery-set/component verification; intent identity, timeline, digest and
freshness must agree. No backup is created or restored by run.

`control.rs` owns a dedicated session and installation advisory lock, never a
request pool or SET ROLE. Claim/progress/complete/recovery-identity calls are
single existing security-definer reducers. They own state, audit and notify
atomically. No user-data query or new business reducer is introduced. Owner-only
signed DDL preserves Go's one-transaction-per-migration schema/evidence contract;
ambiguous completion requires exact durable checksum evidence before success.
Feature-registry contracts bind preflight, commit and rollback to live mode,
catalog digest and the previous binary's compatibility evidence.

The Rust-only versioned hash-chain journal uses `rust-events.jsonl`,
`rust-tip.json` and `rust-last-terminal.json` with a private `executor.lock`.
Completed boundaries are fsynced before reducer acknowledgment. Restart reconciles
local evidence to the DB before the next host action. Torn/corrupt logs,
authority drift, ahead-of-journal generations and foreign Go journals fail closed.
Terminal state is compacted only after DB reconciliation; only reconciled terminal
journals rotate for a later approved intent. Polling is bounded; SIGTERM/SIGINT
cancels active work, closes dedicated DB sessions and lets restart reconcile.

Fixed core unit names and stop/start order mirror Go. Only root's process PATH
selects systemctl/curl, as Go exec does; child environments are fixed. Health,
login, SMTP STARTTLS and IMAP TLS probes address fixed loopback endpoints only.
Go's loopback certificate-name exception is preserved using rustls/ring; handshake
signatures remain checked. No shell, request-selected command or URL is executed.
Step failures before maintenance fail the intent; after maintenance they attempt
the complete previous cohort and otherwise mark recovery_required. Failed or
unknown outcomes never report success.

## Verification and recordings

`cargo test --locked -p setjoin-updater -p setjoin-release-format -- --test-threads=1`
replays the immutable manifest corpus through the executable and checks exact
accept/reject, canonical bytes, digest and signer IDs, including tamper/wrong keys.
`manifest-policy.json` adds nine frozen-Go cases for wrong key ID, wrong public
key under the right ID, tampered content, metadata rollback/equivocation,
channel/architecture denial and the production threshold. Its test-only recorder
is `tests/record_manifest_test.go.txt`, overlaid as
`mailserver/internal/updater/testutil/rel2_manifest_record_test.go`; run
`go test -overlay=<mapping.json> ./internal/updater/testutil -run
'^TestREL2ManifestPolicyRecord$' -count=1` in the CI image's `/src/mailserver`,
with REL2_RECORD_DIR pointing to an empty writable directory and GOFREE_GO_SOURCE
set to the full frozen commit. Production Go files are untouched.
`tests/installer.rs` runs the process installer oracle in the CI image. It needs
Docker, `setjoin-ci-linux-tc:local-amd64`, PostgreSQL 17, pgTAP, Python, curl and
OpenSSL; no missing prerequisite is skipped. The container has no published ports
and starts its own private PG17 cluster at 127.0.0.1:55452, database
`gofree_e2e_rel3` when run from Cargo, with the canonical schema loader. It sets only its own updater
role password and hosts fake fixed loopback application peers and S3 recovery
objects. No shared-cluster role/password changes are needed. Append-only intent
history survives until the private cluster is destroyed; shell traps stop/reap
Postgres and remove its exact temporary directory.

`tests/goldens/installer*.json` record frozen Go at its full source commit via the
same process fixture. It covers signed artifacts and a real schema migration,
core stop/switch/start/check, durable terminal result, installed inventory and
repeat without another state bump or service restart. Additional recordings kill
and reap the process group after activation before its host-action acknowledgment,
reject a same-size tampered artifact before maintenance, preserve Go's nested
block-comment SQL false rejection and recovery_required evidence, and roll back
a failed login check to a verified complete previous cohort. The fixture serializes
fixed ports/DB changes with a process flock. Generated release IDs are normalized
only in terminal result fields. All five recordings are replayed in one fresh
private cluster; no persistent host PostgreSQL or listening ports are required.

Parity bug: Go `migration.go:181` ends a block comment at the first `*/`, so a
valid nested comment containing COMMIT is falsely rejected. The maintained
sqlparser tokenizer adapter deliberately exposes the same tail keywords. Go's
redundant nil-evidence rollback error is likewise retained in the recorded result. Record with a Go updater
built from that source in the CI image (shared module cache), then run
`REL2_RECORD_DIR=<empty directory> GOFREE_GO_SOURCE=<full commit>` and
`bash tests/installer.sh <go-updater> --go` from the repository root using the
full `server-rust/bins/updater/tests/installer.sh` path. Recorder uses exclusive
file creation; immutable goldens are never edited by hand. Normal Rust replay
requires no Go compiler or Go process.

## Operator recovery (#359)

`recover [--install-root PATH --state-dir PATH --evidence-dir PATH --dsn-file PATH]
status [--json] | evidence [--reason TEXT] | activate-previous --reason TEXT [--force]`
uses the installed paths by default. Status/evidence inspect without owning the
executor lock. Activation requires root and an authored recovery state or explicit
force with a real terminal on stdin (`isatty(0)`; see SECURITY.md). Reasons
are 8..1024 trimmed bytes without control characters. Evidence is mode 0600,
exclusive-created, content-addressed with a UTC timestamp, and file/directory fsynced.
It observes exactly setjoin-auth, setjoin and setjoin-updater.

Activation snapshots, stops the updater, locks and rechecks the local tip, then
holds the DB installation lock for authored recovery. Core stop/start/readiness
and complete-cohort validation reuse run's fixed adapters. A failure before target
activation reconciles the unchanged current cohort. The rolled_back journal event
precedes upgrade_intent_recover; a lost DB result remains visibly pending until
recovery replays that same event and compacts only after confirmation. Repeat
restarts the updater and returns the prior evidence path without switching again.
Updater restart is attempted on every exit after a successful stop.

`tests/recovery.rs` replays Go status/evidence and forced rollback. The test-only
`record_recovery_main.go.txt` overlay binds only the frozen CLI's fixed paths to
private fixture paths. `tests/recovery_install.rs` loads the canonical schema in a
private CI-image cluster (gofree_e2e_rel3, REQUIRE_DB=1), induces recovery_required
through the real updater, then compares recovery DB state, audit, evidence and
repeat against `goldens/recovery-authored.json`. Normal replay runs no Go process.


## Installer handover and release inputs (#359)

`install.sh` builds/reuses `server-rust/setjoin-updater`, runs `check-swap` before
schema or runtime changes, renders the unchanged `setjoin-updater.service` name
with `ExecStart=/usr/libexec/setjoin-updater run ...`, and invokes the native
`install` command before copying the core binaries. `check-swap` is an early
admission check without changing transaction evidence or executables; `install` repeats admission while holding the executor
file lock and DB installation advisory lock. The idle updater is stopped before
acquiring its DB lock. Active/queued/recovery-required DB states, active or
unreconciled journals, torn/checksum-invalid/foreign/mixed journal data and missing
existing-install credentials refuse with an operator reason. A first-ever install
may omit the DB credential only when no updater or transaction evidence exists.

Go journals are validated in their original field order with the shared
`marshal_go` and SHA-256 implementation, including raw ordered evidence. Only a
reconciled inactive tip matching DB identity/generation/state admits the handover.
The complete Go journal is copied/fsynced under private `journal/go-terminal/`
before removing its live files; no Go transaction is resumed or translated into
Rust. `executor.lock` keeps its inode. Native journals remain native.

The command preflights every fixed destination, preserves changed executables and
the unit as `*.prev`, and atomically/fsyncs each file replacement. Ordinary I/O
failure restores captured files before restarting the old updater; a failed restore
leaves it stopped and names manual matching-`*.prev` recovery. A host crash during
installation can require that same whole-release restoration. Successful installation
leaves the updater stopped for the installer's normal dependency-ordered restart.
`setjoin-recovery` is a root-owned two-line compatibility entrypoint that execs the
fixed `/usr/libexec/setjoin-updater recover` (never `$0`-relative); no second Rust/Go recovery binary ships.
Whole-release rollback restores the matching updater, recovery entrypoint and unit
from `*.prev` only with no update active; keep archived journal evidence.

Until #300, the frozen Go updater artifact is installed only as the fixed
`/usr/libexec/setjoin-office-app-runner`. `run --office-app-execution` supervises
that companion with `--office-app-only`, the app worker DSN/manifest/state paths,
executor and polling interval; it receives no core updater/store/owner arguments.
Core execution never returns to Go. The companion is terminated/reaped with the
Rust parent and a stopped companion fails the service. The `--office-app-only`
shape forwards to that same named owner; it cannot accept core-update arguments.

`adopt-current-layout` records the complete flat cohort plus a config digest,
uses the embedded canonical schema version, fsyncs an immutable release and advances
`current`. Repeats of adopted cohorts validate content; orphaned flat `*.prev` files are quarantined,
never promoted into a complete rollback cohort. Its immutable Go recording is
`goldens/adoption.json`. Frozen Go's existing-managed adoption branch only parses
its manifest and ignores manifest.digest and installed.evidence.json; Rust no longer
does (see SECURITY.md). The frozen-Go recording of that gap was removed.

`package-server-release.sh` now takes eight inputs: architecture, Go binary dir,
Rust gateway, Rust mailctl, Rust asrbotd, Rust updater, webmail build and output.
Only Go mailserverd/authserverd and the temporary Office-runner source remain Go
binary inputs; Go recovery is not required or staged. `build.sh` stages the native
updater at its canonical Rust path. Floor builds discover this existing workspace
binary automatically. `test-package-server-release.py` checks all three machine
headers and source-build staging; it still packages committed HEAD only.

The strict process suite uses the assigned DSNs/REQUIRE_DB=1, serial test threads,
and only disposable `gofree-rel3-*` containers. The private Postgres cluster contains
only gofree_e2e_rel3. `recovery_install` compares one real notification and audit
against separate immutable Go effect recordings, drops a committed reducer response
at the PgWire boundary, checks visible pending reconciliation and an idempotent
retry, then tests active DB refusal, terminal Go archive, native entrypoint and
matching executable/unit `*.prev` restoration. `swap.rs` covers active local locks,
Go active/recovery-required journals, first install and invalid destination refusal.
`office.rs` tests the closed companion argument boundary. Normal replay needs no Go.

## Security divergences from frozen Go

Owner-approved security fixes (2026-11-05, tickets #506, #505, #507) live in
[SECURITY.md](SECURITY.md): managed adoption authenticity, recovery tty guard,
recovery wrapper path, ownership checks, `sslmode`, debug-only verify flags and the
raise-only `--minimum-threshold`. `scripts/test-updater-secfix-mutants.py` restores
each gap and requires its test to fail.
