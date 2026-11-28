# deploy — deployment templates and scripts (DOX child)

Owns systemd unit/socket/path templates, single-node installer (`scripts/install.sh`), upgrader (`scripts/upgrade.sh`), lifecycle controller (`scripts/setjoin-lifecycle.sh` → `/usr/local/sbin/setjoinctl`), sidecar templates (LiveKit SFU, Valkey, Egress, FunASR, ASR bot), HAProxy/PgBouncer/Pgpool templates, and monitoring dashboards (`grafana/`, `zabbix/`).

Root `AGENTS.md` rules apply unchanged. Preserve credential-separated allowlist env files (`gateway.env`, `federation.env`, `storage.env`, `smtp.env`, `tls.env`; never inject `config.env` or `DB_OWNER_DSN` into internet-facing units), migration-before-reducer ordering (`mailctl schema apply --yes` before reducer reload), and atomic `*.prev` / cohort rollback guarantees.

## DOX sections

- [Ownership and installer contracts](DOX.md#ownership-and-installer-contracts)
- [Rust operator CLI and backup transfer (#355)](DOX.md#rust-operator-cli-and-backup-transfer-355)
- [Native federation deployment (#347)](DOX.md#native-federation-deployment-347)
- [Native HTTPS deployment (#413)](DOX.md#native-https-deployment-413)
- [Native updater/recovery installation (#359)](DOX.md#native-updaterrecovery-installation-359)
- [Native SMTP deployment (#501 / #526)](DOX.md#native-smtp-deployment-501--526)
- [Native IMAP deployment (#202)](DOX.md#native-imap-deployment-202)

## Verification

- `bash scripts/guards/check-deploy-doc-currency.sh` (and `--self-test`)
- `bash scripts/guards/check-upgrade-contracts.sh`
- `bash scripts/guards/check-installer-migration-order.sh`
- `bash deploy/scripts/test-livekit-render.sh`

## Child DOX Index

None.
