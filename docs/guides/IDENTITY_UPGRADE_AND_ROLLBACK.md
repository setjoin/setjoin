# Identity Model Upgrade and Rollback

Move from legacy identity reads to source-scoped normalized reads with explicit
cohorts. Production enablement is always a separate operator decision.

## Preconditions

- schema V167 or later;
- current database/config backup restored successfully in an isolated database;
- all deterministic tests and identity pgTAP suites pass;
- zero unexplained critical divergence;
- no pending/deferred match candidate for the chosen source;
- recovery and rollback drills completed;
- the source generation and proposed user cohort are recorded; and
- every cohort member has an active authentication link to that source.

Inspect:

```bash
mailctl identity doctor --json
mailctl identity inventory export --output identity-inventory.json
mailctl identity upgrade status --json
mailctl identity source list --json
mailctl identity conflict list --json
```

Run the checksum-bound preflight and retain its 0600 artifact:

```bash
mailctl identity upgrade preflight \
  --output identity-preflight.json \
  --json
```

Stop on exit 4. Correct every named blocker, rerun preflight, and use only the
new artifact's `sha256`; generated time is excluded from that stable checksum.

## Restart-safe backfill

Plan and start are separate operations:

```bash
mailctl identity upgrade backfill plan --json

mailctl identity upgrade backfill start \
  --preflight-checksum "$PREFLIGHT_SHA256" \
  --idempotency-key "$UUID" \
  --reason "Approved V167 normalized identity backfill" \
  --json

mailctl identity job watch "$JOB_ID" --timeout 30m --json
mailctl identity job results "$JOB_ID" --limit 500 --json
```

Plan exits 2 when person work exists and 4 when safety blocks it. Start exits 0
only after durable acceptance. Each database batch is at most 500 people;
progress and exact per-person results settle atomically. A terminal
`completed_with_failures` exits 1 and must be reviewed before shadow/canary.

## Feature gates

The migrations seed these OFF:

```text
feature.identity_model_v2
feature.identity_normalized_reads
feature.identity_transitions
```

Do not turn them on during package installation, schema migration, backup,
restore, or source configuration.

## Invalid source isolation and binary rollback

The normalized identity runtime isolates an active AD or LDAP source whose
runtime configuration is invalid or cannot be decrypted. Healthy sources keep
running, while the invalid source remains stored but does not sync. After every
upgrade or configuration-key change, check the gateway logs for:

```text
identity source runtime source isolated
```

Treat each occurrence as an operator action: correct the source configuration
or mark that source inactive, then confirm a later reconciliation starts it
without the isolation message. The diagnostic names the source and bounded
error but does not include its bind secret.

This is also a binary-rollback precondition, not a schema-version boundary. The
release containing this guide is the first release with per-source isolation;
an earlier release fails gateway startup when any active source has an invalid
runtime envelope instead of isolating only that source. Before rolling back the
binary, use the current running version to correct or deactivate every isolated
source; otherwise the older gateway can refuse startup even though the database
schema is compatible.

## Canary one source

Before canary, prove at least seven completed source syncs whose successful
observation rail spans at least 24 hours, with no non-terminal batch and zero
critical, missing-projection, or undispositioned ambiguity. The gate evaluates
the whole completed observation rail (not only the newest seven), so the default
15-minute connector cadence can qualify after 24 hours:

```bash
mailctl identity upgrade shadow --source "$SOURCE_KEY" --json
mailctl identity upgrade canary plan --source "$SOURCE_KEY" --json
```

Then, after explicitly enabling the master model for an authorized rehearsal,
select 1–500 active linked users and use the exact current source generation:

```bash
mailctl identity upgrade canary enable \
  --source "oidc:SOURCE_DIGEST" \
  --expected-generation "$GENERATION" \
  --users "42,84" \
  --reason "Approved normalized-read canary" \
  --json
```

The reducer rejects stale generations, unlinked users, empty/oversized cohorts,
and sources with critical divergence. It increments the source generation and
stores exact cohort membership.

Verify each cohort member can authenticate through the selected provider and
that non-cohort/unknown subjects still follow the legacy path. Watch metrics for
at least the agreed observation window.

To remove one source cohort without global rollback:

```bash
mailctl identity upgrade canary disable \
  --source "oidc:SOURCE_DIGEST" \
  --expected-generation "$NEW_GENERATION" \
  --reason "End normalized-read canary" \
  --json
```

Disable returns the source to `shadow` and clears its cohort.

## Global rollback

Rollback is safe to invoke when normalized behavior is suspect:

```bash
mailctl identity upgrade rollback \
  --reason "Critical divergence during canary" \
  --json
```

It atomically:

- disables the master, normalized-read, and transition flags;
- returns every source to `shadow`;
- increments changed source generations;
- clears all read cohorts;
- appends one immutable global rollback event with the exact actor, audited
  reason, and bounded changed-source/cohort counts, even when every source was
  already in shadow mode;
- preserves normalized links, tombstones, grants, events, and reports; and
- leaves already accepted post-commit effects draining.

Verify `rolledBack=true`, all three flags OFF, `cohortMembers=0`, and
`schemaPreserved=true`. In the Audit inventory, verify one source-null
`source_updated` event whose `reason` exactly matches the command and whose
metadata contains `operation=global_rollback`.

## Restore drill

Restore the pre-cutover backup to an isolated database, apply the current binary,
and verify:

- schema/reducer manifest;
- source/link counts;
- all flags OFF;
- legacy login;
- normalized shadow comparison; and
- transition reports and pending effects.

Never roll schema backward by deleting V153–V172 tables. Operational rollback is
a read/admission rollback, not evidence destruction.

## Retirement boundary

Legacy user columns and singleton connector configuration are retained for at
least one release rollback window. Removal requires a separate plan proving:

- no code or database reader remains;
- every supported source is normalized;
- restore from a pre-cutover backup succeeds;
- rollback no longer depends on the legacy projection; and
- retention/compliance owners approve evidence changes.

`mailctl identity upgrade retirement-check --json` collects these facts and
always reports `destructiveMigrationIncluded=false`. It exits 4 until every
runtime dependency and the separate code-graph/restore proof pass; it never
drops a column or disables rollback by itself.
