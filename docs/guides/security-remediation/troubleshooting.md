# Security-program troubleshooting

Run `coverage explain CODE` for an offline explanation. Never bypass HOLD by
editing retained evidence or retrying a start under a new identity.

`coverage explain` covers `C0`, `HOLD`, and the `E_SECURITY_PROGRAM_*` catalog
below only; the checker's `E_SEC_REM_*` codes (and the checker's exit-3
reopened/HOLD, which carries no code) are documented with remedies and exit
codes in the [error catalog](error-catalog.md), alongside the dispatcher codes'
exit-code table. Captured diagnostics for both tools are in
[fixtures](fixtures.md).

- `E_SECURITY_PROGRAM_DX_INCOMPLETE`: finish the named T7-DX gates.
- `E_SECURITY_PROGRAM_USAGE`: use the diagnostic's `helpCommands` and exact `rerun.argv`.
- `E_SECURITY_PROGRAM_NOT_PUBLISHED`: run the check command before a separately
  authorized publication.
- `E_SECURITY_PROGRAM_PATH_TOKEN_UNKNOWN`: copy a current token from `coverage list --paths`.
- `E_SECURITY_PROGRAM_ATTEMPT_UNKNOWN`: run `coverage resume` and use its exact attempt ID.
- `E_SECURITY_PROGRAM_LIVE_LEASE`: attach to the existing owner or wait; never replace it.
- `E_SECURITY_PROGRAM_LEASE_EXPIRED`: reconcile the expired owner's attempt before adopting a lease.
- `E_SECURITY_PROGRAM_ORPHANED_START`: reconcile the persisted start; never retry it blindly.
- `E_SECURITY_PROGRAM_COMPLETION_UNKNOWN`: reconcile the existing scan; never launch again.
- `E_SECURITY_PROGRAM_SOURCE_CHANGED`: create a new reviewed epoch; do not reuse
  prior authority.
- `E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED`: run `coverage migrate --check` with a supported target.
- `E_SECURITY_PROGRAM_MIGRATION_ATTEMPT_ACTIVE`: resolve the unfinished attempt before migration.
- `E_SECURITY_PROGRAM_APPROVAL_REQUIRED`: obtain the named separate approval; no flag bypass exists.
- `E_SECURITY_PROGRAM_BUNDLE_UNAVAILABLE`: restore the retained bundle without changing its receipt.
- `E_SECURITY_PROGRAM_BENCHMARK_TARGET_MISSED`: retain the red run and diagnose the control-plane regression; direct automation exits nonzero.
- `E_SECURITY_PROGRAM_BUNDLE_INSIDE_WORKTREE`: use the approved external migration path.
- `E_SECURITY_PROGRAM_EVIDENCE_INVALID`: quarantine the artifact and reconcile from retained authority.
- `E_SECURITY_PROGRAM_OUTPUT_PRIVACY`: replace private paths or payloads with logical references.
- `E_SECURITY_PROGRAM_SCAN_UNAVAILABLE`: stop; the scanner transition is not admitted yet.
- `E_SECURITY_PROGRAM_C0_COUNT_MISMATCH`: reconcile the frozen inventory totals with the approved C0 decision.
- `E_SECURITY_PROGRAM_C0_OWNERSHIP_MISMATCH`: repair the S01-S30/shard partition so it is the exact authorized union.
- `E_SECURITY_PROGRAM_INTERNAL`: retain the stable diagnostic and rerun the offline doctor; do not infer success.
- `E_SECURITY_PROGRAM_PUBLICATION_BUSY`: reconcile the active or crash-retained publication lock before retrying.
- `E_SECURITY_PROGRAM_PLATFORM_UNSUPPORTED`: use the named macOS arm64 or Ubuntu x86_64 read environment.
- `E_SECURITY_PROGRAM_PREREQUISITE_BLOCKED`: run the exact read-only next command and resolve the persisted prerequisite.

Escalations contain only stable IDs, source keys, hashes, error codes, and logical
artifact references—never credentials, finding prose, or private bundle paths.
