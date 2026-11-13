#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mode="${1:-quick}"
case "$mode" in quick|full) ;; *) echo "usage: $0 [quick|full]" >&2; exit 2 ;; esac

bash scripts/check-mailbox-lifecycle-contracts.sh
go test ./mailserver/internal/admin ./mailserver/internal/mailboxlifecycle ./mailctl
bash scripts/load-test-schema.sh
pg_prove -h "${PGHOST:-127.0.0.1}" -p "${PGPORT:-5432}" \
  -U "${PGUSER:-mail}" -d "${PGDATABASE:-mailserver_test}" \
  mailserver/sql/tests/mailbox_lifecycle_retention.pg \
  mailserver/sql/tests/mailbox_lifecycle_effects.pg \
  mailserver/sql/tests/mailbox_purge_worker.pg

flag="$(psql -h "${PGHOST:-127.0.0.1}" -p "${PGPORT:-5432}" -U "${PGUSER:-mail}" \
  -d "${PGDATABASE:-mailserver_test}" -Atqc "SELECT enabled FROM feature_toggles WHERE key='feature.mailbox_lifecycle_retention'")"
[[ "$flag" == f ]] || { echo "feature.mailbox_lifecycle_retention must remain OFF" >&2; exit 1; }

if [[ "$mode" == full ]]; then
  go test -race ./mailserver/internal/admin ./mailserver/internal/mailboxlifecycle ./mailctl
  (cd mailserver/webmail && npm test -- --run \
    'src/routes/admin/(mail)/users/users-protection.test.ts' \
    'src/routes/admin/(mail)/users/users-workflows.test.ts')
fi

echo "mailbox lifecycle $mode verification passed"
