# Mailserver Upgrade Runbook

## Pre-upgrade

1. **Create one application recovery set:** configure backup-store credentials
   outside argv, then run the command below. It asks the gateway to produce an
   immutable blob/config inventory, exports one PostgreSQL repeatable-read
   snapshot with `pg_dump --snapshot`, rejects component drift, verifies every
   object hash, records the protected-key fingerprint, and writes the HMACed
   recovery manifest last as the sole commit point.

   ```bash
   export BACKUP_BUCKET=setjoin-backup
   export BACKUP_ENDPOINT=https://backup.example.test
   export BACKUP_ACCESS_KEY_FILE=/etc/setjoin/backup-access-key
   export BACKUP_SECRET_KEY_FILE=/etc/setjoin/backup-secret-key
   mailctl backup create --pre-upgrade \
     --recovery-key-file /etc/setjoin/recovery-set.key \
     --protected-key-file /etc/setjoin/db-encryption.key \
     --reason "create recovery point before Setjoin upgrade" --json
   ```

   The current CLI also accepts the legacy `BACKUP_ACCESS_KEY` and
   `BACKUP_SECRET_KEY` environment variables; never place secrets in shell
   history. Retain the returned recovery-set UUID and digest.
2. **Re-verify the exact set before confirmation:**

   ```bash
   mailctl backup verify --pre-upgrade \
     --recovery-key-file /etc/setjoin/recovery-set.key \
     --protected-key-file /etc/setjoin/db-encryption.key \
     --reason "verify recovery point before Setjoin upgrade" \
     11111111-1111-4111-8111-111111111111 --json
   ```

   Exit `0` with `status=verified` is the install gate; exit `2` means the set
   is incomplete, stale, corrupt, or bound to another installation/timeline.
3. **Keep the legacy paths in their honest scope:** `mailctl backup run` captures
   gateway-managed blobs/config only; `mailctl backup-db` is a database-only
   operator dump. Neither is a unified point-in-time recovery set or restore
   proof.
4. **Do not treat `deploy/scripts/backup.sh` as a complete application backup.**
   It is a database-only emergency dump and does not capture SeaweedFS/S3 mail or
   attachment blobs. The two legacy backup paths above are also separate evidence,
   not a unified point-in-time recovery set or restore proof.
5. **Rehearse separately:** a successful recovery set is not a restore proof.
   Follow [Restore rehearsal](RESTORE_REHEARSAL.md) on a newly created isolated
   PostgreSQL cluster and blob namespace. A proof older than 90 days warns by
   default; it does not rewrite a successful backup as failed.
6. **Notify users:** send the maintenance-window notice.
7. **Check current version:** `curl -s http://localhost:80/admin/system/version`
   (requires admin auth) or check the build hash.

## Choose the installed layout first

Run `test -L /opt/setjoin/current && echo managed || echo legacy`.

- `managed`: binaries and Webmail run from the immutable `current` release.
  Positional artifact-copy upgrades are disabled. The Admin **Server updates**
  screen may display signed releases, recovery evidence, confirmation, and
  durable progress. Host execution still fails closed while
  `feature.transactional_upgrades_execution` is OFF or any runtime/recovery gate
  is open. The fixed recovery verbs below remain the only break-glass surface.
- `legacy`: the older flat-layout procedure below remains available. A normal
  installer re-run adopts a complete flat cohort before switching its units.

## Legacy flat-layout manual upgrade

The managed-layout Admin Portal is the release-first authorization and observation
surface for transactional server upgrades. Its root-owned updater executes only
when the signed catalog, verified recovery evidence, database feature flag, and
root-owned execution config all permit it; installations seed those gates OFF.
The legacy procedure below is therefore only for a host where
`/opt/setjoin/current` does not exist. The retired System-page binary-path handler
is never an alternative execution authority.

1. Go to **Admin → System → Gateway**
2. Note the current **Version** hash
3. On your build machine, build BOTH: `cd mailserver && go build -o mailserverd ./cmd/mailserverd` and `cd ../mailctl && go build -o mailctl ./`
4. SCP both: `scp mailserver/mailserverd mailctl/mailctl user@host:/tmp/`
5. On the server: `sudo /opt/setjoin/deploy/scripts/upgrade.sh /tmp/mailserverd /tmp/mailctl` (arg 2 lets it apply pending schema migrations before start)
6. Refresh the System page — **Version** hash should update.
7. Check **Health** — all services must be green.

## Upgrade via CLI

Build AND ship a **matching `mailctl`** alongside the gateway. The new gateway
**refuses to start if the database schema is behind the version it ships** (it
embeds the forward migrations), and `upgrade.sh` applies the pending migrations
*before* starting — using the `mailctl` you pass as arg 2. A stale `mailctl` would
apply the wrong migration set, so always ship the one from the same build.

```bash
# Build BOTH binaries from the same commit
cd mailserver && CGO_ENABLED=0 go build -o mailserverd -ldflags="-s -w" ./cmd/mailserverd
cd ../mailctl  && CGO_ENABLED=0 go build -o mailctl ./

# Deploy both; pass mailctl as arg 2 so upgrade.sh can apply schema migrations
scp mailserver/mailserverd mailctl/mailctl user@mail.company.com:/tmp/
ssh user@mail.company.com \
  'sudo /opt/setjoin/deploy/scripts/upgrade.sh /tmp/mailserverd /tmp/mailctl'
```

If you ship only `mailserverd` (no arg 2) and the schema is behind, the new
gateway **will not start** — `upgrade.sh` rolls back to the previous binary and
tells you to apply migrations with a matching `mailctl` first.

## Database schema migrations

The gateway embeds the forward migrations (`mailserver/sql/dbschema/V<NNN>__*.sql`)
and **refuses to start** unless `MAX(schema_migrations.version)` is at least the
highest it ships. `upgrade.sh` applies them automatically before start. To check
or apply by hand (uses `DB_DIRECT_DSN` for DDL, falling back to `DB_DSN` — both
live in `/etc/setjoin/config.env`):

```bash
# Pre-check drift before the window (exit 1 = behind; add --json for scripts)
DB_DIRECT_DSN="$(grep ^DB_DIRECT_DSN= /etc/setjoin/config.env | cut -d= -f2-)" \
  mailctl schema check

# Apply pending forward migrations (each in its own transaction)
DB_DIRECT_DSN="..." mailctl schema apply --yes
```

The forward migrations are backward-compatible with the previous binary (so the
rollback below stays safe). One of them (`V004`) enables RLS in FORCE mode — that
is **inert** for the gateway's current DB role and only becomes live at the
separate, hand-authorized `DB_DSN`→`setjoin_app` cut-over; applying it here does
not turn enforcement on. It does take a brief `ACCESS EXCLUSIVE` lock on two
tables, but `upgrade.sh` has already stopped the gateway by then.

## Identity-model upgrade (V153–V172)

The identity migrations are expand-only. Applying them creates normalized
sources, immutable subject links, lifecycle authority, source-scoped
provenance, durable transitions, cutover controls, and bounded operator jobs;
it does not enable the new readers or transitions.

Before and after the binary/schema upgrade:

```bash
mailctl identity doctor --json
mailctl identity inventory export \
  --output identity-inventory.json
mailctl identity upgrade status --json
mailctl identity upgrade preflight \
  --output identity-upgrade-preflight.json
```

Treat any inventory blocker, partial federation pair, missing LDAP immutable
anchor, source-generation mismatch, or unexplained shadow divergence as a stop
condition. If the preflight reports legacy people to migrate, use the bounded
`identity upgrade backfill plan|start` workflow and inspect the durable job
results before considering a source for shadow/canary admission. Keep these
toggles OFF during ordinary upgrade:

- `feature.identity_model_v2`
- `feature.identity_normalized_reads`
- `feature.identity_transitions`

Canary and transition procedures are separate operator decisions documented in
[Identity upgrade and rollback](IDENTITY_UPGRADE_AND_ROLLBACK.md) and
[Identity transitions](IDENTITY_TRANSITION.md). Do not combine schema rollout
with source activation, canary enablement, or a lifecycle transition.

## Rollback

The copy-based command below applies only to the current **legacy flat layout**.
If `/opt/setjoin/current` exists, the installation has been adopted by the
transactional updater: do not copy `mailserverd.prev`, do not overwrite the
`current` link, and use the updater-managed recovery command documented by
`/opt/setjoin/current/share/docs/UPGRADE_RECOVERY.md`, the manifest-verified guide
installed with that release.

The managed-layout commands accept no release path, unit, URL, shell command, or
database-restore verb:

```bash
sudo /opt/setjoin/deploy/scripts/upgrade.sh status
sudo /opt/setjoin/deploy/scripts/upgrade.sh evidence \
  --reason "capture evidence before recovery"
sudo /opt/setjoin/deploy/scripts/upgrade.sh activate-previous \
  --reason "new release failed readiness"
```

`activate-previous` is admitted automatically only for an updater-authored
`recovery_required` transaction. Outside that state it additionally requires
`--force` from a local TTY. It snapshots fixed evidence before mutation, uses
only the complete `previous` cohort, runs the fixed gateway/auth readiness
checks, and reconciles the immutable transaction when one exists. It never
restores PostgreSQL or blobs. Every managed activation and rollback revalidates
the manifest-bound expanded installation tree; a changed or mixed cohort fails
closed before the symlink moves.

On a legacy flat-layout install, if the health check at `/ready` fails after upgrade:

```bash
sudo cp /opt/setjoin/mailserverd.prev /opt/setjoin/mailserverd
sudo systemctl restart setjoin
```

Verify: `systemctl status setjoin && curl -skf https://127.0.0.1/ready` — probe
the HTTPS listener (`-k` for the self-signed cert). In the default single-node
install `:80` only serves a 301 redirect, which `curl -f` counts as success, so
an `http://localhost:80/ready` probe proves nothing.

If only normalized identity behavior needs to be withdrawn, do not downgrade
the schema or delete evidence:

```bash
mailctl identity upgrade rollback \
  --reason "rollback normalized identity reads"
mailctl identity upgrade status --json
```

This disables identity read/transition admission and returns sources to shadow
mode. Already-committed transition effects continue draining; legacy columns
remain the rollback projection for the release window.

## Production service lifecycle

Use the installer-owned fixed-scope controller for ordinary start, stop, and
restart operations. It owns dependency order and cannot be pointed at an
arbitrary unit or path:

```bash
sudo setjoinctl status
sudo setjoinctl restart
sudo setjoinctl stop
sudo setjoinctl start
```

When transactional execution is enabled, stop/restart refuses unless the
operator has proved no transaction is active and explicitly adds
`--allow-updater-stop`. Reversible service removal is:

```bash
sudo setjoinctl uninstall --confirm-preserve-data
```

It removes only the fixed Setjoin systemd registrations and preserves config,
PostgreSQL, object data, recovery sets, immutable releases, and updater
evidence. There is no purge verb. This is the production counterpart of the
temporary environment's exact-prefix cleanup and failure-preserved diagnosis.
See [Single-node setup](SINGLE_NODE_SETUP.md) and
[Client-assisted mail recovery](CLIENT_ASSISTED_MAIL_RECOVERY.md).

## Monitoring after upgrade

```bash
# Watch logs for 5 minutes
journalctl -u setjoin -f --since "1 min ago"

# Check key metrics (METRICS_TOKEN required — /metrics is 401 without it
# unless METRICS_ALLOW_UNAUTHENTICATED=1 is set; see config.env.sample)
curl -s -H "Authorization: Bearer $METRICS_TOKEN" http://localhost:80/metrics | grep -E "gateway_requests_total|gateway_active_connections|gateway_goroutines_total"

# Check health
systemctl status setjoin
```

## Version history

| Date | Version | Git Hash | Notes |
|---|---|---|---|
| current | - | - | - |

Update this table after each successful upgrade.
