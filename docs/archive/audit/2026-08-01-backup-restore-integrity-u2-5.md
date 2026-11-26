# U2.5 backup/restore integrity audit — 2026-08-01

Scope was limited to the prerequisite named by the transactional-updater plan:
iterator and close/process errors, commit ordering, PostgreSQL dump validation,
blob destination integrity, destination confinement, and protected-config
round-trip behavior.

## Closed findings

- Blob reuse and writes now require full destination SHA-256 verification, not
  existence or equal size.
- Backup and restore cursors propagate scan and terminal iterator errors.
- Custom dumps are non-empty and accepted by `pg_restore --list`; process,
  writer, sync, and close failures are fatal.
- Restore validates manifest counts, duplicates, metadata, and hashes before
  atomic configuration replacement or blob commitment.
- POSIX storage rejects traversal/canonicalization aliases, writes temporary
  objects in the destination directory, fsyncs file and directory, then renames.
- Protected configuration retains its ciphertext envelope and encrypted marker
  in the restore quarantine for explicit key rotation; it is not activated under
  the target deployment key.

Regression evidence is owned by `scripts/audit-backup-integrity.sh`, the named
Go tests under `internal/{backup,restore,storage}`, and the canonical test lane.
The local audit has no open integrity finding. Disposable-Ubuntu
backup→isolated-restore proof is deliberately tracked as the U3 runtime gate,
not claimed by this local audit.
