# Client-assisted mail recovery

Client-assisted recovery is a last-resort, consented way to recover eligible
mail after a complete server rollback. It does not make clients authoritative,
does not upload automatically, and does not replace application recovery sets
or isolated restore proof.

All three feature flags seed OFF:

- `feature.client_recovery_receipts` issues signed, account-bound receipts;
- `feature.client_recovery_cache` permits opted-in encrypted native retention;
- `feature.client_recovery_ingest` exposes evidence, incident, upload, and
  quarantine flows.

Do not enable any of them while a required row in
`docs/verification/2026-08-02-transactional-continuity-u5-u8.md` is OPEN.

## What can be recovered

Only exact raw MIME plus every referenced attachment/inline byte is eligible.
The server signs installation, account, original message ID, eligibility
(`received` or terminally sent), content hashes, timeline, state watermark,
boot epoch, time, and key ID. Metadata-only cache
rows, render-derived bodies, drafts, scheduled mail, and non-terminal outbound
mail are ineligible. Shared-mailbox upload requires current `full_access` or
ownership on every request.

The native setting is a separate informed opt-in and defaults OFF. The coverage
counter includes only artifacts whose signed receipt and exact bytes committed
atomically in the encrypted vault. Turning the setting on never opens intake;
turning it off never uploads anything.

## Incident flow

1. A signed client token demonstrates a newer timeline/state than the restored
   server. Time movement alone is only a warning and cannot open intake.
2. An unscoped `system.recovery` administrator selects exact mailbox evidence,
   enters a reason, uses fresh two-factor authorization, bounds expiry to at
   most seven days, and normally requires a second administrator.
3. The affected user sees only approved incidents for mailboxes they own or
   fully access. They choose each encrypted copy to offer. Uploads resume at
   server-acknowledged 256 KiB offsets and can be cancelled.
4. The server verifies the signed receipt, sizes, hashes, installation,
   timeline, account, user, and consent; then assembles into quarantine.
   ClamAV is mandatory and fails closed.
   Admission is also cumulatively bounded at 8 sessions/16 GiB per device,
   16/32 GiB per mailbox, 256/256 GiB per incident, and 4096/1 TiB per
   installation. An aborted or terminal session still reserves its declared
   bytes while any staged chunk awaits verified cleanup.
5. The Admin Mail Recovery page reviews sanitized headers, digest, provenance,
   malware result, replay/fork/tamper state, and reason. A fork needs both user
   consent and explicit admin `accept_fork` resolution.
6. The trusted reducer inserts a new copy with Inbox and
   `Recovered from device`, preserves original raw bytes, records provenance,
   clears authentication claims, and writes state/audit/notify in one
   transaction. It never invokes SMTP, rules, vacation replies, calendar
   processing, or identity linking.

## Temporary production-shaped rehearsal

Use one unique lowercase prefix. The controller has start/resume/status/cleanup
paths, so later rehearsals do not repeat manual host preparation:

```bash
export RUN_PREFIX=sj-continuity-$(date +%Y%m%d)
export REWIND_ATTEMPT=attempt-1
bash scripts/transactional-upgrade-rehearsal.sh provision
bash scripts/transactional-upgrade-rehearsal.sh updater
bash scripts/transactional-upgrade-rehearsal.sh rewind
bash scripts/transactional-upgrade-rehearsal.sh deterministic
bash scripts/transactional-upgrade-rehearsal.sh status
bash scripts/transactional-upgrade-rehearsal.sh cleanup
```

`resume-provision` is only for the guarded pre-install/install checkpoint. A
failed rewind keeps its successful provisioning/updater state; retry it with a
new lowercase `REWIND_ATTEMPT` (and use the same value for status/cleanup).
Cleanup uses an exact container/network allowlist derived from `RUN_PREFIX` and
the attempt namespace; it never performs a broad name match.

Portable rewind and both simulator rows are CLOSED. When the two physical-device
rows and operator-timing row are also closed, `full` runs A/B provisioning, the
real updater success/rollback and rewind rehearsals, deterministic U5–U7 tests,
and the final hardware gate in order:

```bash
RUN_PREFIX="$RUN_PREFIX" bash scripts/transactional-upgrade-rehearsal.sh full
```

Until then it intentionally stops at the first OPEN release row and preserves
the environment for diagnosis. Always finish with the exact-prefix `cleanup`
action; an updater cleanup failure is not masked.

## Production lifecycle lessons

The single-node installer installs `setjoinctl` for the production equivalents:

```bash
setjoinctl status
setjoinctl restart
setjoinctl stop --allow-updater-stop
setjoinctl start
setjoinctl uninstall --confirm-preserve-data --allow-updater-stop
```

The production controller accepts no caller-supplied service or path. It stops
the updater before core services, starts dependencies before auth/gateway/
updater, and refuses to strand an active transaction. Uninstall removes only
the fixed Setjoin unit registrations and preserves configuration, PostgreSQL,
object data, recovery sets, immutable releases, and updater evidence. There is
no purge verb. Those constraints are the production form of exact-prefix
cleanup and failure-preserved evidence learned from disposable deployments.

## Closure and cleanup

Close the incident after review. Closing aborts incomplete sessions; an
always-running cleanup worker continues when intake is OFF, expires stale
sessions, removes exact quarantine chunk keys idempotently, and keeps terminal
audit evidence. Ordinary service remains available throughout; recovery intake
is never an automatic response to a clock or rewind signal.
