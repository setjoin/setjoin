# Drive ACL operations

This runbook is for an isolated rehearsal or an explicitly approved ACL pilot.
All four production behavior flags are seeded OFF. Do not enable them merely to
diagnose an incident.

## Safety boundary

- Use `DB_OWNER_DSN` only for reviewed schema/owner work and `DB_WORKER_DSN`
  only for named workers. Never `SET ROLE` on a pooled request connection.
- Freeze ACL writes before repair. Keep canonical reads on when narrowing ACLs
  have ever been used; turning reads off must not restore legacy space-wide
  visibility.
- Diagnostics may record counts, booleans, versions, plan hashes, correlation
  IDs, and bounded hashes of opaque IDs. Do not record paths, filenames,
  content, email/UPN, tokens, DSNs, or raw principal IDs.
- Chat/Meet bindings, Guest caps, classification, export controls, WORM, and
  legal hold remain outer restrictions. ACL repair cannot override them.

## Read-only diagnosis

Confirm schema and flags without changing them:

```sql
SELECT max(version) AS schema_version FROM schema_migrations;
SELECT key,enabled FROM feature_toggles
 WHERE key IN (
   'feature.drive_node_acl_reads',
   'feature.drive_node_acl_writes',
   'feature.drive_access_governance',
   'feature.drive_emergency_access'
 ) ORDER BY key;
```

For the affected opaque space ID, collect bounded facts:

```sql
SELECT count(*) AS nodes FROM drive_nodes WHERE space_id=$1;
SELECT count(*) AS closure_rows FROM drive_node_closure WHERE space_id=$1;
SELECT epoch FROM drive_acl_generations WHERE space_id=$1;
SELECT state,count(*) FROM drive_acl_grants WHERE space_id=$1 GROUP BY state;
SELECT reason,count(*) FROM drive_access_invalidations
 WHERE space_id=$1 GROUP BY reason ORDER BY reason;
SELECT mismatch_class,count(*) FROM drive_acl_shadow_mismatches
 WHERE space_id=$1 GROUP BY mismatch_class ORDER BY mismatch_class;
```

Run exact authorization only for the approved synthetic or affected opaque
principal/node pair. Compare the legacy/canonical shadow record; do not dump an
entire visible tree into a ticket.

## Triage map

| Symptom | Check | Bounded response |
|---|---|---|
| unexpected denial after group change | group generation and exact invalidation | refresh membership evidence, then full reconcile the affected principal |
| possible overexposure | ACL epoch, active grants, inheritance breaks | disable writes, quarantine client cache, keep canonical reads enforced |
| stale native cache | invalidation cursor/floor and visibility snapshot epoch | run full reconcile; wipe unauthorized cached objects |
| closure mismatch or cycle alarm | closure counts plus migration/repair dry run | freeze writes; rebuild only in isolated transaction and verify before unfreezing |
| stuck approval/lease | request state, expiry, consumed uses | expire/revoke through reducers; never update terminal state directly |
| rollback request after narrowing | cutover evidence and affected spaces | refuse widening; retain canonical reads or quarantine narrowed spaces read-only |

## Dry run, repair, verify

1. Set `feature.drive_node_acl_writes` OFF through the normal operator control.
   Confirm new grant, revoke, and inheritance mutations fail closed.
2. Take a recovery point using the standard backup procedure. This is not
   permission to restore over current data.
3. Run the relevant repair in dry-run mode or an isolated transaction. Record
   only row counts and hashes. Stop on any cross-space row or unexpected fan-out.
4. Apply the one reviewed reducer/repair operation. Do not directly edit grant,
   closure, approval, lease, audit, or invalidation authority rows.
5. Verify exact allow and deny fixtures, ACL epoch advancement, invalidation,
   audit-chain continuity, and managed-client quarantine behavior.
6. Re-enable writes only when shadow mismatch is zero for the reviewed pilot
   and the client compatibility gate is satisfied.

The deterministic local authority gate is:

```bash
RUN_PREFIX=driveacl-ops bash scripts/drive-acl-smoke.sh all
bash scripts/benchmark-drive-acl.sh
```

The smoke uses a scratch database and cleans its exact resource. Set
`KEEP_ON_FAIL=1` only for an isolated developer database; the retained artifact
under `test-results/drive-acl-smoke/<prefix>/` is synthetic and redacted.

For a disposable full-install rehearsal, `scripts/ga-fresh-install-smoke.sh`
supports `KEEP_ON_FAIL=1` followed by `RESUME_INSTALL=1`; resume preserves the
same generated test secrets and schema instead of starting over. On a Docker-
hosted Ubuntu test container, `PRELOAD_HOST_EGRESS=1` (default) may stream the
exact pinned Egress digest from the host image cache into nested Podman. A cache
miss falls back to the registry, and no configuration, secret, or customer data
is cached. Cleanup remains exact-prefix only.

## Rollback and OFF-state proof

Safe rollout order is schema → shadow → canonical reads → writes → governance.
Rollback reverses behavior flags only while preserving evidence and narrowed
authorization:

1. turn emergency/governance issuance OFF;
2. turn ACL writes OFF;
3. keep ACL reads ON for every space that has a narrowing grant, inheritance
   break, or ACL-governed move;
4. quarantine incompatible clients and mark affected spaces read-only;
5. prove no legacy adapter restores broader access;
6. leave all seed defaults OFF after the disposable rehearsal.

Never drop V184+ Drive ACL tables or erase grant, epoch, invalidation, approval, audit, or
cutover evidence as a rollback mechanism. Production enablement requires a
separate operator-approved pilot; engineering verification alone is not rollout
authorization.
