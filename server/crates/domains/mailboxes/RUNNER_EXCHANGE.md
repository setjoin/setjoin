# Mailboxes: job runner and Exchange replacement

Detailed runner and Exchange contracts indexed by [DOX.md](DOX.md).

## Job runner (#431)

Gateway `src/migration_runner/` ports Go's `migration.Orchestrator` (in-process goroutines, not a
named worker). `Orchestrator::{start_job,cancel_job,pause_job,resume_job}` keep Go's per-job
control block (cancel, one-slot pause and resume tokens); `run_job` calls `migration_orchestrate`
for every state change (one reducer call each, errors ignored as Go does), reads the job and
profiles on the worker credential (`DB_WORKER_DSN`), imports through `import_message` (or
`migration_apply_mail_object` when `feature.mail_migration_source_identity` is on) after a
content-addressed S3 put, and reuses `mimeutil::ImportFields::parse` (#425) for the headers.
`imap.rs` is Go's `IMAPConnector` (LOGIN, LIST, EXAMINE, `UID FETCH (RFC822 FLAGS)` pages of 100,
modified UTF-7, folder tags incl. the i18n table) over a small protocol client; `Dialer` applies
`ssrf.DialContextWithPrivatePolicy` to every resolved answer (`private_policy::dial_allowed`).
- Enable: `RUST_WORKERS_ON=migration-runner` requires `GO_WORKERS_OFF=migration-runner` (the
  operator's attestation that Go's runner serves no start/retry/resume route); without the runner
  start/control/test dependencies fail locally after admission. Startup fails jobs a restart left running
  (`migration_recover_stuck`). Terminal `migration.completed`/`migration.failed` events (from
  `orchestrate` and from recovery) go through the shared webhook dispatcher (#457), as Go's
  `dispatchTerminalEvent` does: not when the reducer already enrolled them in the publication
  outbox, a mailbox-scoped job to the mailbox's subscribers, any other to the user's
  (`tests/migration_terminal_recorded.rs`). Go's own `RecoverStuckJobs`
  still fails every running job when a Go process restarts: keep the two on separate hosts' lifetimes.
- IMAP, EWS, M365 and compound/upload phases run in Rust (#446); there is no provider-specific
  Go fallback. Microsoft I/O, callback and auxiliary transactions: [MICROSOFT.md](MICROSOFT.md).
- Go quirks mirrored: `start` inserts every job under the admin's own user id, so the one-active-job
  index refuses all but the first target (`failed to create job for ...`); a retry of a terminal job
  fails the `start` phase (ignored) yet keeps running and leaves the status; a retry of a completed
  or cancelled job (config NULLed) fails with `connector: decrypt job config: migration: ciphertext
  too short`; a pause of a running job parks it for good (Go sends on an unbuffered `pauseAck` nobody
  reads, `shouldPause` is never set); cancel/pause of a job that is not running is a 500, resume of
  one starts it, retry of a missing job is a 202.
- Oracle: `bins/gateway/tests/migration_runner{.rs,_oracle/}` with the scripted source
  `tests/common/fake_imap.rs` and the fake S3 of `drive_workers_oracle`. Record mode needs
  `172.17.0.1 gofree-mbox6-imap.test` in `/etc/hosts` (Go refuses loopback and wants a named private
  host); replay dials the fake directly through `Dialer::custom`, so it needs no hosts entry.
  `migration_runner_startup.rs` checks the guard and native dispatch, including absent-runner admission.

## Exchange replacement (#294)

`src/exchange.rs` and gateway `src/exchange.rs` own this slice. Registry,
project list and run list use the worker credential, as Go's administrator
handler does. Live `exchange.assessment.read` grants precede reads; the registry
is installation-wide, project/run lists apply the live admin domain scope in
SQL. Go ignores unused query parameters and lists foreign project runs as `[]`.
The HTTP oracle (`bins/gateway/tests/exchange{.rs,_oracle/}`) records frozen Go
through the front door, then replays with no Go upstream, comparing response
bytes/headers, committed rows, audit and both Exchange notification channels.
Per-route status mutants alter the actual response. `exchange_startup` exercises
the executable's native dispatch, all-Go switch and inventory rollback.

The core writes call Go's existing reducers, once per receipted command on the
worker credential: `exchange_assessment_project_create_idempotent`,
`exchange_assessment_run_create_idempotent`, `exchange_assessment_run_transition`,
`exchange_assessment_decision_set`, `exchange_assessment_attestation_create`,
`exchange_assessment_claim_resolve` and `exchange_assessment_delete_request`.
The actor is the verified context (`$2`); request IDs name targets. No new reducer
or inline business write is introduced. Unknown commits return the shared 503
operation-lookup response. Create-project/run use canonical UUID headers and the
SHA-256 of Go's typed JSON field order. Raw attestation JSON stays raw through the
SQL binding (including number spellings). Bodies are strict single objects with
Go's null and case-folded field behavior, bounded at 1 MiB.

Every sensitive Exchange permission (including the audit GET) also requires Go's
fresh AAL2 recipe: signed `iat` within five minutes, at most 30 seconds future,
`acr=aal2`, a nonempty JTI, `mfa` and two distinct known factors, at most 16 distinct
nonempty AMR values. Write middleware checks `audit_policy`'s `exchange` reason
area first and durably audits a missing header. Reads need no reason header.
Error bodies use the shared Go-ordered problem helper and primary language tag.
Parity quirks and permanent corpus instructions: [Exchange oracle](../../../tests/conformance/exchange/README.md).

Bundle upload and publication use the same worker-scoped authorization-before-
replay query and existing `exchange_assessment_artifact_commit` /
`exchange_assessment_publish_signed` reducers. S3 puts precede the transaction;
a known rollback removes the new object, an unknown commit retains it. Uploads
are bounded at 64 MiB; the caller's SHA-256 must match. Replay bypasses body
consumption and storage, matching Go. Publication signs the snapshot digest
with the continuity Ed25519 key before encrypting a receipt artifact.
`src/exchange_artifact.rs` preserves Go's EK01 envelope and ordered receipt JSON:
ring supplies AES-GCM, HKDF, Ed25519 and randomness; RustCrypto supplies SM4-GCM.
Hybrid uses AES, as Go does. Master key input is the configured ASCII bytes.

Gateway `src/exchange_deletion.rs` runs already-authorized deletion work globally
on `DB_WORKER_DSN` (fallback `DB_DSN`), including when the feature is off. It starts
only with both `RUST_WORKERS_ON=exchange-assessment-deletion` and matching
`GO_WORKERS_OFF`. An immediate sweep, then each minute, handles at most twenty
requests in ID order. Deletes occur in artifact ID order; any removal failure
leaves that request pending and the sweep continues. It signs the exact ordered
subject and calls existing `exchange_assessment_delete_finalize` once; backup
closure stays `backup_expiry_pending`. Shutdown cancels and joins the task.

HEAD responses preserve Go's 2 KiB header inference boundary: large read bodies
produce no Content-Length. Decoder refusals preserve Go's anonymous struct/type
names, including `int` registry/catalog versions, and malformed-byte context.

Shared MIME bytes (#348): implementation moved verbatim to [setjoin-mime](../../mime/DOX.md); `setjoin_mailboxes::mimeutil` remains the same public API. The existing recorded vectors remain this family's compatibility check.
