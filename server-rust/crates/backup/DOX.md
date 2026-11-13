# Backup infrastructure (#355)

Shared operator/worker backup formats and streaming object transport. This crate
has no HTTP route authority. Local CLI credentials and worker credentials remain
separate. S3 uses SigV4, native trust roots and streaming files; dump data is never
buffered in memory. Temporary files are private, create-only and removed on drop.
The dump HMAC canonical form is frozen Go's ordered JSON, including an empty MAC
field while signing. Every object key has its own authenticated sidecar.

## Server worker

`worker::Engine` runs in setjoin-gateway when BACKUP_PROVIDER/BACKUP_BUCKET are
configured and the private hex Ed25519 seed is valid. Startup requires
`GO_WORKERS_OFF` to contain `backup-engine`, `DB_DIRECT_DSN` for backup_run LISTEN,
and DB_DSN (DB_WORKER_DSN takes precedence for global inventory/bookkeeping).
`RUST_BACKUP_ENGINE_ENABLED=false` disables Rust; rollback must also remove the
Go off-switch. Invalid signing keys disable backups as Go does. Process-local
session workers retain their independent ownership.

Startup reclaims stranded running rows and drains pending runs. Each notification
CAS-claims pending -> running. Every live blob is read and SHA-256 verified before
skip and after copy. Copies stream primary -> backup without a local spool. The
config export preserves the encrypted flag and raw JSONB text. Manifests use Go's
ordered JSON and Ed25519 format; backup-manifest.json is the last commit point.
Terminal bookkeeping preserves Go's independent autocommit statements, including
its stranded-running behavior on terminal-write failure. Cancellation joins the
listener and drops in-flight I/O; restart reclaims interrupted work.

GFS retains newest runs per distinct calendar day, ISO week and month. Invalid
stamps are kept. Pruning removes incremental/config objects before the immutable
index, and deletes the row only after all object removals succeed. Blobs and latest
pointers are never retention targets.

## Recorded seams

`bins/mailctl/tests/backup_oracle.py` tests real pg_dump/pg_restore processes,
authenticated SigV4 peers, independently verified HMAC envelopes, Unix control
requests and table/sequence/ACL round trips. The portable Go archive uses standard
worker/app roles; the Rust round trip additionally exercises the full schema.
Child argv and /proc are inspected without putting credentials in evidence.

Full-schema restore requires PostgreSQL `max_locks_per_transaction >= 256` for
the atomic schema reset; the oracle fails before snapshots or mutations when
the selected server is below that setting. Configure and restart a disposable
server before replay. `MAILCTL_BACKUP_ROUNDTRIP_DB_DSN` optionally selects a
separate loopback disposable database for `roundtrip-go`, `roundtrip-rust` and
`roundtrip-env-password` only; it needs the full schema and standard roles.
All other cases retain `TEST_DB_DSN`. `backup_preflight.py` checks fail-fast
diagnostics and database selection at the subprocess/tool seam; Cargo runs it
alongside the live oracle. The installer and checked-in Compose files do not
configure this setting, leaving external PostgreSQL provisioning responsible.

`backup_worker.py` launches the gateway executable and compares rows, object
operations and bodies with frozen Go. It independently verifies signing keys,
Ed25519 signatures, config digests and blob content before normalizing clocks.
Bucket-region discovery is SDK transport metadata and is excluded from the object
operation transcript. Go recording alone uses the gofree_record-tag adapter at
`mailserver/internal/backup/backup_oracle_record_test.go`; ordinary replay needs
no Go. Python 3, PostgreSQL client tools and OpenSSL are mandatory.

Destructive harnesses snapshot only the explicit disposable TEST_DB_DSN and
restore it on exit. Cleanup drops objects in separate transactions to bound shared
Postgres relation locks; product restore retains Go's atomic locked schema reset.
Failed cleanup retains its private original dump and reports the exact path.

Application recovery sets retain Go's camelCase envelope and field order.
Components include the database, restore list, blob inventory and configuration;
verification hashes all stored bytes and referenced blobs. The authenticated
manifest is the final commit point; eligibility also binds installation, timeline,
requested locator and maximum 24-hour freshness. The CLI owns the exported
snapshot, API workflow and private key acquisition; this foundation owns formats
and object verification. Recovery process oracle: mailctl/tests/recovery_oracle.py.

Worker replicas run as joined Rust tasks after primary publication. Failure is
logged and never changes the completed primary run; shutdown cancels and joins
replicas. Provider selection preserves S3/backup_s3, OSS4 signatures and POSIX's
confined two-byte shard layout, private same-directory staging, fsync and rename.
Worker network endpoints enforce Go's TLS rule (HTTP only for loopback); standalone
mailctl's provider flag remains informational and uses S3, as frozen Go does.
Worker oracles independently authenticate AWS/OSS signatures and verify Ed25519
index signatures. Replica effects and retention may interleave, so their ordered
streams are compared separately after the primary manifest commit.

`restore-auth` process cases reject dump substitution, sidecar substitution,
wrong locator and wrong HMAC key before any pg_restore child. Both dump and
restore child argv and /proc are audited in live round trips, including an
already credential-free DSN with PGPASSWORD. The worker corpus also proves
verified skip, corruption repair and failure before manifest publication.
Run all DB-backed lanes serially: Cargo releases its build lock during tests,
and the process-oracle flock coordinates only these Python harnesses, not the
workspace's other DB fixtures. Do not overlap an ad hoc replay with the Rust gate.

The gateway process replay `backup_keeps_go_parity_with_recovery_cleanup_enabled`
sets both backup-engine and mail-recovery-cleanup in the Rust worker list and
Go off-switch. It requires the same frozen backup tick effects and clean shutdown
while the Blobs cleanup task runs independently. Select this combination manually
with MAILCTL_WORKER_WITH_RECOVERY=1 and MAILCTL_WORKER_CASE=worker in backup_worker.py.

Storage migration transport compatibility (#459): `Store::with_aws_operation_query`
opts into Go AWS SDK operation tags (including signing their query string).
`with_signing_region` preserves an explicitly empty OSS signing region. Existing
backup callers keep their default profile. The Platform owner rejects Go's
unseekable HTTP AWS upload at the same point, after target read-back and before
consuming the lazy source; private staging must not turn it into a successful copy.

`platform_storage_runtime::backup_defaults_preserve_signed_object_io` verifies the
existing S3/backup_s3 profiles through real signed PUT/GET/HEAD/DELETE requests;
the strict peer rejects a migration operation tag at that same boundary.
