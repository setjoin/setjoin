#!/bin/bash
set -euo pipefail
# Mailserver backup — pg_dump to a local file.
# Usage: ./backup.sh
#
# ER5 occ_46ce8465c8d98fd05faf7cf4 (insecure-permissions.database-backup): a raw
# pg_dump is a complete copy of every mailbox, credential hash and secret
# column, so it is world-readable only until someone reads it. The dump is
# therefore written under umask 077 (mode 0600, group/other stripped) — the same
# 0600 discipline mailctl backup-db applies to its dumps and credential files —
# published atomically (temp name → mv) so a failed run never leaves a
# truncated file that looks restorable, and credentials travel via the
# PGPASSWORD environment only, never argv, and are never echoed.
umask 077

TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
BACKUP_DIR="${DATA_DIR:-/var/lib/setjoin}/backups"
mkdir -p "$BACKUP_DIR"

# Connection overrides; defaults preserve the historical local shape. The role
# must be able to read every table (its owner, or a role granted read access) —
# never a superuser "because it's easier".
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"
DB_NAME="${DB_NAME:-mailserver}"

tmp="$BACKUP_DIR/.pg-$TIMESTAMP.sql.gz.partial"
trap 'rm -f "$tmp"' EXIT

PGPASSWORD="${DB_PASSWORD:-mail}" pg_dump -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -d "$DB_NAME" \
  --no-owner --clean --if-exists | gzip >"$tmp"
mv "$tmp" "$BACKUP_DIR/pg-$TIMESTAMP.sql.gz"
trap - EXIT

# Retain last 7 daily backups
find "$BACKUP_DIR" -name "pg-*.sql.gz" -mtime +7 -delete

SIZE="$(du -h "$BACKUP_DIR/pg-$TIMESTAMP.sql.gz" | cut -f1)"
echo "Backup: $BACKUP_DIR/pg-$TIMESTAMP.sql.gz ($SIZE)"
