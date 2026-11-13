# Blobs: receipts, protected audits and WORM retry qualification

Moved verbatim from [DOX.md](DOX.md) to keep it under the child budget.

## Foundation receipts and protected audits

The shared [executor contract](../../pg/DOX.md#rust-operation-receipts-257265)
owns V276's `rust_operation_receipts`, `ReceiptCommand` static family/command
labels, `run_receipted_command` and `lookup_command`. Every F16 mutator uses its
existing reducer name as command and `F16` as family. Record only successful
transaction attempts, including reducer no-ops; a new attempt has a new operation
ID. Failed decoding, receipt insertion or command execution rolls back together.
Unknown retains the original ID for authenticated lookup; never replay it.
The JMAP pilot's audit-row operation ID remains intact.

Golden normalization excludes only the Rust system-metadata receipt table from
business row-effect comparison. Existing explicit row projections already omit
it; response, business rows, audit, state and NOTIFY stay unchanged. The frozen
Go recordings are immutable. This is the orchestrator's prescribed foundation
metadata addition, not an accepted business-behavior divergence.

The gateway's request and worker executors bind `DB_ENCRYPTION_KEY` and
`AUDIT_HMAC_KEY` through the [named audit allowlist](../../pg/DOX.md#protected-audit-gucs).
The scoped executor attaches trusted configuration to the verified transaction
context and installs only those transaction-local settings. Request-controlled
SET/set_config stays refused; pool reuse cannot carry another transaction's key.
Recovery cleanup's `WorkerDatabase` also receives the trusted keys: its expiration
reducer writes a protected core audit before the separate batch-selection and
S3 phases, preserving Go's transaction boundaries. The executable one-tick test
checks the configured V3 checksum as well as the original business/I/O golden.

Focused read verification (#419): `cargo test --locked -p setjoin-gateway --test
attachment_transfer --test blob_download --test blob_read_conditions --
--test-threads=1`, with the disposable schema, request/worker/direct DSNs and
`REQUIRE_DB=1`. Each supplemental golden has an exact case selector. The default
adequacy/isolation/inventory/budget guards are required; full Rust and adequacy
execution/coverage remain integration lanes.


## WORM retry handoff qualification (#419)

The existing #301 PUT producer and #411 `blob-cleanup` consumer share the bounded
process-local retention ledger. Enable `RUST_WORKERS_ON=blob-cleanup` with
`GO_WORKERS_OFF=blob-cleanup`; Go's ticker cannot drain Rust's ledger. Restart
loss/arbitrary eviction remain Go parity (known #432), not a persistence redesign.
`tests/blob_retention_recorded.rs` records actual frozen Go PUT plus four cleanup
steps/ticks through `drain/blobs3_retention_tick_test.go.txt`, then replays native
PUT with no Go upstream and real `BlobCleanup::tick`. The S3 peer independently
verifies SigV4 (including Go's signed empty-copy form and streaming chunks),
canonical copy/temp deletion, mode, 30-day retain-until and bypass header. It
refuses retention twice, accepts the third attempt and observes no later calls.
Full blob/charge/usage/queue rows, email state, audit and NOTIFY stay compared;
only declared actor/hash/temp/timestamp fields and Rust receipt metadata normalize.
The missing-tick mutant must fail the same S3 observation. HTTP PUT recordings
also cover governance/compliance and minio-go's ten-attempt 5xx refusal.
Record only the positive worker selector with
`GOFREE_RECORD_BLOBS3_RETENTION=1 GOFREE_GO_SOURCE=<frozen-sha>`; ordinary replay
leaves that variable unset. Run `cargo test --locked -p setjoin-gateway --test
blob_retention_recorded --test blob_upload --test blob_cleanup_recorded --test
blob_cleanup_startup -- --test-threads=1` with the assigned disposable DSNs and
`REQUIRE_DB=1`. This is the worker seed/PUT/tick seam; the existing HTTP corpus
owns the complete PUT wire envelope. eDiscovery S3 SetLegalHold/release remains
owned by F04 Compliance #289 and still forwards; F16 PutObjectRetention is separate.
