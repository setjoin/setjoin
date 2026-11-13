#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mode="${1:-quick}"
case "$mode" in
  quick|full) ;;
  *) echo "usage: $0 [quick|full]" >&2; exit 2 ;;
esac

go test ./mailserver/internal/migration ./mailserver/internal/imap
bash scripts/load-test-schema.sh
pg_prove -h "${PGHOST:-127.0.0.1}" -p "${PGPORT:-5432}" \
  -U "${PGUSER:-mail}" -d "${PGDATABASE:-mailserver_test}" \
  mailserver/sql/tests/migration_source_identity.pg \
  mailserver/sql/tests/imap_membership_uid.pg

if [[ "$mode" == full ]]; then
  go test -race ./mailserver/internal/migration ./mailserver/internal/imap
  bash scripts/e2e.sh imap
fi

for key in feature.mail_migration_source_identity feature.imap_membership_uid; do
  value="$(psql -h "${PGHOST:-127.0.0.1}" -p "${PGPORT:-5432}" \
    -U "${PGUSER:-mail}" -d "${PGDATABASE:-mailserver_test}" -Atqc \
    "SELECT enabled FROM feature_toggles WHERE key='$key'")"
  [[ "$value" == f ]] || { echo "$key must remain OFF" >&2; exit 1; }
done

echo "mail interoperability $mode verification passed"
