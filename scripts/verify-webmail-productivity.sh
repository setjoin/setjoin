#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mode="${1:-quick}"
case "$mode" in
  list)
    printf '%s\n' \
      'quick    Go + web + database deterministic gate; all feature flags remain OFF' \
      'db       fresh-schema reducer/pgTAP and OFF-flag gate' \
      'web      focused browser-unit/component/type/localization gate' \
      'security authorization, egress, registry/error, and namespace contract gate' \
      'full     quick + Go race + complete route/OpenAPI/visibility inventory'
    exit 0
    ;;
  quick|db|web|security|full) ;;
  *) echo "usage: $0 [list|quick|db|web|security|full]" >&2; exit 2 ;;
esac

run_go() {
  go test ./mailserver/internal/jmap ./mailserver/internal/mailwork ./mailserver/internal/user ./mailserver/internal/admin ./shared/webhook
}

run_web() {
  (cd mailserver/webmail && npm test -- --run \
    src/lib/stores/searchQuery.test.ts \
    src/lib/search/searchIntent.test.ts \
    src/lib/components/mail/SearchIntentRail.test.ts \
    src/lib/mail/mailWork.test.ts \
    src/lib/components/mail/MailRow.test.ts \
    src/lib/components/mail/MessageList.test.ts \
    src/lib/components/mail/MailWorkRail.test.ts \
    src/lib/stores/composeStore.svelte.test.ts \
    src/lib/components/ComposeScreen.test.ts \
    'src/routes/admin/(system)/webhooks/webhooks.test.ts')
  (cd mailserver/webmail && npm run check)
}

run_db() {
  bash scripts/load-test-schema.sh
  pg_prove -h "${PGHOST:-127.0.0.1}" -p "${PGPORT:-5432}" \
    -U "${PGUSER:-mail}" -d "${PGDATABASE:-mailserver_test}" \
    mailserver/sql/tests/sender_control_center.pg \
    mailserver/sql/tests/mail_work.pg \
    mailserver/sql/tests/mail_comments.pg \
    mailserver/sql/tests/mail_work_notifications.pg \
    mailserver/sql/tests/mail_work_business_time.pg \
    mailserver/sql/tests/mail_work_digest_delivery.pg \
    mailserver/sql/tests/mail_work_internal_actions.pg \
    mailserver/sql/tests/mail_drafts.pg

  for key in feature.mail_search_builder feature.sender_control_center feature.shared_mail_work \
    feature.shared_mail_comments feature.shared_mail_notifications feature.shared_mail_analytics \
    feature.shared_mail_integrations feature.shared_mail_drafts; do
    value="$(psql -h "${PGHOST:-127.0.0.1}" -p "${PGPORT:-5432}" -U "${PGUSER:-mail}" \
      -d "${PGDATABASE:-mailserver_test}" -Atqc "SELECT enabled FROM feature_toggles WHERE key='$key'")"
    [[ "$value" == f ]] || { echo "$key must remain OFF" >&2; exit 1; }
  done
}

run_security() {
  go test ./shared/reducererr ./shared/toggle ./shared/webhook ./mailserver/internal/jmap ./mailserver/internal/mailwork ./mailserver/internal/admin
  bash scripts/check-api-namespace.sh
  rg -q "message bodies, comments, recipients, subjects" docs/guides/SHARED_MAIL_PRODUCTIVITY.md
  rg -q "unknown event type" mailserver/internal/admin/admin_webhooks.go
  rg -q "duplicate event type" mailserver/internal/admin/admin_webhooks.go
}

case "$mode" in
  db) run_db ;;
  web) run_web ;;
  security) run_security ;;
  quick) run_go; run_web; run_db ;;
  full)
    run_go
    run_web
    run_db
    run_security
    go test -race ./mailserver/internal/jmap ./mailserver/internal/mailwork ./mailserver/internal/user
    bash scripts/verify-architecture-r2.sh route
    ;;
esac

echo "webmail productivity $mode verification passed"
