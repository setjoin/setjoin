#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

# Direct destructive SQL is intentionally centralized in reviewed reducers.
expected_reducers=$'sql/reducers/content_purge.sql\nsql/reducers/jmap_email.sql\nsql/reducers/mailbox_purge_execute.sql\nsql/reducers/retention.sql\nsql/reducers/rust_admin_mailbox_delete.sql\nsql/reducers/rust_admin_user_delete.sql\nsql/reducers/rust_mailsec_quarantine.sql\nsql/reducers/scim_delete_group.sql\nsql/reducers/scim_delete_user.sql\nsql/reducers/transition_message_location.sql'
actual_reducers="$(grep -rliE 'DELETE[[:space:]]+FROM[[:space:]]+(users|mailboxes|messages|aliases)\b' \
  --include='*.sql' sql/reducers | sort || true)"
if [[ "$actual_reducers" != "$expected_reducers" ]]; then
  echo "mailbox lifecycle guard: unexpected destructive reducer" >&2
  diff -u <(printf '%s\n' "$expected_reducers") <(printf '%s\n' "$actual_reducers") || true
  exit 1
fi

grep -q 'direct user deletion is disabled' server/bins/gateway/src/admin_users_lifecycle.rs
grep -q 'direct mailbox deletion is disabled' server/bins/gateway/src/mailboxes.rs
grep -q 'retained mailbox requires approved purge' sql/dbschema/V199__mailbox_lifecycle_retention.sql
grep -q "'feature.mailbox_lifecycle_retention',false" sql/dbschema/V199__mailbox_lifecycle_retention.sql

echo "mailbox lifecycle contracts: ok"
