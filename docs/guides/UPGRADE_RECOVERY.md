# Transactional upgrade recovery

This is the canonical break-glass guide for the root-owned Setjoin updater. It
distinguishes executable rollback from data recovery. Never restore PostgreSQL,
blob storage, or a whole-machine snapshot merely because a new binary failed:
that can destroy mail accepted after the recovery point.

The installed read-only copy is
`/opt/setjoin/current/share/docs/UPGRADE_RECOVERY.md`. U2 now requires exactly
one recovery-guide artifact in every signed release, verifies its digest, and
installs it at that fixed path. Production execution remains off until the
remaining disposable-Ubuntu and U3 recovery-point gates pass.

## Evidence to preserve first

Do not delete, truncate, edit, or copy over these paths:

- `/var/lib/setjoin-updater/journal/events.jsonl`
- `/var/lib/setjoin-updater/journal/snapshot.json`
- `/var/lib/setjoin-updater/releases/<release-id>/manifest.json`
- `/opt/setjoin/releases/<release-id>/{manifest.json,manifest.digest,installed.evidence.json,adoption.json}`
- `/var/lib/setjoin-updater/recovery-evidence/*.json`
- the PostgreSQL `upgrade_intents` and `upgrade_intent_events` rows
- `journalctl -u setjoin-updater` and the affected Setjoin units

Record the intent ID, release ID, manifest digest, lease ID, state generation,
last local hash, current/previous release targets, database schema version, and
the application recovery-set ID. Do not include DSNs, credentials, entitlement
documents, message content, or customer data in an ordinary support bundle.

## Entry states and fixed actions

| Entry | Meaning | Safe action | Exit |
|---|---|---|---|
| `claimed`, `preflight`, `recovery_point`, `staged` | No irreversible maintenance boundary has completed | Restore DB connectivity and free space, verify the signed release tree and journal, then restart `setjoin-updater`; an explicit cancel may finish as `cancelled` | Resume to the next exact generation, `failed`, or `cancelled` |
| `maintenance`, `migrations`, `switched`, `readiness`, `committed` | The installation is inside a fenced change; old and new components may no longer be freely mixed | Keep public writes fenced. Restore the failed dependency, then let the same lease resume. If the release's executable rollback rail remains compatible, activate only the verified previous release | `verified`, `rolled_back`, or `recovery_required` |
| `rolling_back` | Executable artifacts are being returned to the verified previous release; customer data is not being restored | Resume the same rollback transaction and fixed health gates. Do not start an unrelated install | `rolled_back` or `recovery_required` |
| `failed` | Failure occurred before the maintenance boundary | Correct the named preflight fault. Preserve the terminal evidence; request a new intent rather than rewriting the old one | New intent only after the one-active slot is free |
| `rolled_back` | Previous executable release is active and passed its declared gates | Verify mail receive/send/fetch and worker health; retain both release trees and evidence until the incident closes | Normal service on previous release |
| `recovery_required` | Both forward activation and executable rollback are unavailable or unsafe | Stop automated retries. Follow the recovery-required categories below. Data restore requires an explicit incident, current evidence, and operator decision | A new immutable recovery event plus validated service state; never an edited old event |
| journal checksum/torn-write/unknown-version error | Local execution evidence cannot be trusted | Keep the files read-only, stop the updater, compare the database intent/event chain and signed support evidence. Do not hand-edit JSON | Vendor-supported journal repair or proven clean recovery path |
| missing or digest-mismatched release tree | Intent no longer binds to available immutable bytes | Restore the exact signed release tree from the authorized Community/Enterprise source or offline bundle | Exact release ID and manifest digest verify again |

## Recovery-required categories

Before manual action, use only the fixed helper (the compatibility wrapper
forwards these exact verbs):

```bash
sudo /usr/libexec/setjoin-recovery status --json
sudo /usr/libexec/setjoin-recovery evidence \
  --reason "capture evidence before recovery"
sudo /usr/libexec/setjoin-recovery activate-previous \
  --reason "new release failed readiness"
```

Do not pass artifact paths or unit names; the helper has no such inputs.
`activate-previous` stops the updater to acquire the same installation lock,
switches only the recorded complete `previous` cohort, starts fixed core units,
requires their readiness, appends a new local event, and calls the narrow
`upgrade_intent_recover` reducer. A repeated exact invocation returns the
existing evidence rather than switching again. If the local event was fsynced
but the database response was lost, status reports
`database_reconciliation_required`; the same command replays the exact reducer
evidence and does not switch the release a second time. Updater restart failures
are returned to the operator rather than hidden.

### Migration or readiness timeout

Keep the current maintenance fence. Check the exact failed gate and schema
version. If the signed compatibility attestation permits the previous binaries
against the current schema, use executable rollback. Otherwise restore service
dependencies and resume forward. Do not apply ad-hoc SQL or run a different
`mailctl` binary.

### Rollback activation or health failure

Do not restore data automatically. Preserve both release trees and the journal,
then determine whether a fixed unit/configuration dependency caused both health
failures. A release switch can be retried only with the same verified targets
and lease evidence.

### Disk full or filesystem I/O failure

Stop retry loops. Preserve the journal filesystem and free space outside the
protected current/previous/staged releases and application recovery point.
Never delete the recovery point or previous verified release first. Replace or
repair failing storage before resuming.

### Application data recovery

Application recovery is a separate, destructive incident. It requires a
complete recovery-set manifest covering PostgreSQL, blobs, and protected
configuration, plus isolated restore evidence when available. Establish the
cutoff and account for mail accepted after that point before any restore.

Hypervisor, Proxmox, VMware, cloud, LVM, ZFS, and Btrfs snapshots are optional
platform evidence. They do not substitute for the application recovery set and
must not be reported as verified unless a provider adapter queried the exact
snapshot identity. A manual operator attestation is displayed as an attestation,
not machine verification.

## Client-assisted continuity

Client upload is unavailable until the separately gated U5–U8 continuity rail
is complete. A future recovery incident may accept only signed server receipts,
encrypted raw MIME from an opted-in native cache, a proven newer server
timeline, explicit user/operator authorization, quarantine validation, and an
idempotent reducer. Never ask users to drag arbitrary mail files into an upgrade
screen.

## Verification before leaving recovery

Verify the journal chain, manifest digest, one-active-intent invariant, database
schema compatibility, gateway/auth readiness, mail send/receive/fetch, required
workers, and the immutable audit/event generations. Record whether the outcome
was forward verified, executable rollback, or explicit data recovery. A service
restart alone is not proof.
