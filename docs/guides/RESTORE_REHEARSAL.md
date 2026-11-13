# Isolated application restore rehearsal

This runbook proves that one Setjoin recovery set can restore. It does not create
the recovery set and it is not a platform-snapshot check. The resulting proof is
separate evidence: a successful backup never implies a successful restore.

## Non-negotiable isolation

Use a newly created PostgreSQL **cluster** (not another database or schema in the
production cluster), a separate blob bucket or prefix, and setup-mode services
with no production DSN, SMTP route, push credential, federation peer, webhook,
LiveKit room, or client endpoint. Compare PostgreSQL system identifiers and stop
if the target matches production. Give the target a unique opaque ID; it must not
equal the source installation UUID.

Keep all recovery keys and object-store credentials in regular mode-0600 files or
the deployment secret store. Do not put them in argv, documentation output,
screenshots, diagnostics, or the recovery manifest.

## Create and authenticate the set

On the source installation, use the exact command documented in
[Upgrade](UPGRADE.md):

```bash
mailctl backup create --pre-upgrade \
  --recovery-key-file /etc/setjoin/recovery-set.key \
  --protected-key-file /etc/setjoin/db-encryption.key \
  --reason "create recovery point before restore rehearsal" --json
```

Copy only the returned recovery-set UUID and the required secrets through the
approved secret-transfer path. On the isolated operator host, authenticate all
DB/list/blob/config objects before touching the target:

```bash
mailctl backup verify --pre-upgrade \
  --recovery-key-file /run/setjoin-rehearsal/recovery-set.key \
  --protected-key-file /run/setjoin-rehearsal/db-encryption.key \
  --reason "verify recovery set in isolated rehearsal" \
  11111111-1111-4111-8111-111111111111 --json
```

Do not continue unless this returns exit 0, the expected recovery-set UUID, and
`status: verified`. The verifier reads and hashes every referenced blob; a
present or same-sized object is not sufficient.

## Restore into the new target

1. Record the source and target PostgreSQL system identifiers using
   `SELECT system_identifier FROM pg_control_system();`; they must differ.
2. Provision the standard Setjoin owner, worker, updater, and app roles on the
   target, then restore the manifest-bound custom dump with `pg_restore`.
3. Restore configuration with its encrypted marker preserved and make the
   protected configuration key available only to the isolated services.
4. Restore every manifest-bound blob into the isolated namespace. Do not point
   the target at the production bucket, even read-only.
5. Start the target in setup mode with outbound SMTP, push, webhooks,
   federation, and public listeners disabled.

## Required proof checks

All checks are mandatory and must refer to the same recovery-set UUID:

- schema version and ownership match the manifest and `mailctl schema check`;
- user, mailbox, blob, and blob-byte counts match the manifest;
- every opaque representative user/mailbox ID exists;
- representative mail rows are readable and representative blob bytes hash to
  the manifest identity;
- encrypted protected configuration decrypts and retains its `encrypted` flag;
- one designated rehearsal account can sign in through the isolated endpoint;
- readiness is green while production endpoints remain unreachable/absent.

Record only booleans, opaque IDs, counts, timestamps, and digests. Never attach
addresses, MIME, configuration values, tokens, DSNs, or raw logs. The source
Admin Updates screen records the proof through the bounded
`POST /api/admin/system/upgrades/restore-proofs` API after all checks pass.

## Destroy or retain explicitly

After evidence capture, destroy the disposable PostgreSQL cluster, blob
namespace, setup-mode services, and temporary key files. If an investigation
requires retention, record its owner, expiry, network isolation, and deletion
ticket. A restore proof older than 90 days is shown as stale-warning evidence;
it is not silently treated as a current rehearsal.

The repository contract smoke is `bash scripts/check-upgrade-contracts.sh`. The
reusable disposable runtime entry is `scripts/transactional-updater-rehearsal.sh`
after provisioning one or more named nodes with
`scripts/unified-deployment-readiness.sh`; `PROVISION_ENVS="a b"` selects the
minimal two-node source/isolated-target topology and `RESUME_INSTALL=1` is the
guarded retry path for an interrupted disposable install. The 2026-08-01 Ubuntu
run completed every check above under recovery set
`740e89ee-41b1-4862-9128-18f1ebd941bc`; its sanitized durable record is
`docs/verification/2026-08-01-transactional-updater-u3-u4-local.md`.
