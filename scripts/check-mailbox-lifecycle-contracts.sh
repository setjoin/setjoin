#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Direct destructive SQL is intentionally centralized in reviewed reducers.
expected_reducers=$'mailserver/sql/reducers/content_purge.sql\nmailserver/sql/reducers/jmap_email.sql\nmailserver/sql/reducers/mailbox_purge_execute.sql\nmailserver/sql/reducers/retention.sql\nmailserver/sql/reducers/rust_admin_mailbox_delete.sql\nmailserver/sql/reducers/rust_admin_user_delete.sql\nmailserver/sql/reducers/rust_mailsec_quarantine.sql\nmailserver/sql/reducers/scim_delete_group.sql\nmailserver/sql/reducers/scim_delete_user.sql\nmailserver/sql/reducers/transition_message_location.sql'
actual_reducers="$(grep -rliE 'DELETE[[:space:]]+FROM[[:space:]]+(users|mailboxes|messages|aliases)\b' \
  --include='*.sql' mailserver/sql/reducers | sort || true)"
if [[ "$actual_reducers" != "$expected_reducers" ]]; then
  echo "mailbox lifecycle guard: unexpected destructive reducer" >&2
  diff -u <(printf '%s\n' "$expected_reducers") <(printf '%s\n' "$actual_reducers") || true
  exit 1
fi

grep -q 'direct user deletion is disabled' server-rust/bins/gateway/src/admin_users_lifecycle.rs
grep -q 'direct mailbox deletion is disabled' server-rust/bins/gateway/src/mailboxes.rs
grep -q 'retained mailbox requires approved purge' mailserver/sql/dbschema/V199__mailbox_lifecycle_retention.sql
grep -q "'feature.mailbox_lifecycle_retention',false" mailserver/sql/dbschema/V199__mailbox_lifecycle_retention.sql

echo "mailbox lifecycle contracts: ok"
