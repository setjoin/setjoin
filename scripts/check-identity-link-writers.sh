#!/usr/bin/env bash
# Guard the complete reducer writer inventory for user_identity_links.
# Both qualified and unqualified table names are recognized. Migrations and
# pgTAP fixtures are outside REDUCERS by construction.
set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
REDUCERS="${REDUCERS:-$ROOT/mailserver/sql/reducers}"

expected=$'identity_auth_jit\nidentity_auth_link\nidentity_auth_unlink\nidentity_legacy_backfill\nidentity_match_decide\nidentity_source_entry_apply\nidentity_transition_execute\nidentity_transition_rollback\nldap_sync_anchor_link'

writers() {
  perl -0ne '
    if (/\b(?:INSERT\s+INTO|UPDATE)\s+(?:public\.)?user_identity_links\b/is) {
      ($name = $ARGV) =~ s{.*/}{};
      $name =~ s{\.sql$}{};
      print "$name\n";
    }
  ' "$REDUCERS"/*.sql | sort -u
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  REDUCERS="$tmp"
  while IFS= read -r name; do
    printf 'UPDATE user_identity_links SET state=state;\n' >"$tmp/$name.sql"
  done <<<"$expected"
  printf 'INSERT INTO public.user_identity_links DEFAULT VALUES;\n' >"$tmp/ninth_writer.sql"
  if [[ "$(writers)" != "$expected"$'\n''ninth_writer' ]]; then
    echo "identity-link writer guard self-test could not detect qualified writer" >&2
    exit 1
  fi
  rm "$tmp/ninth_writer.sql"
  [[ "$(writers)" == "$expected" ]]
  echo "identity-link writer guard self-test passed"
  exit 0
fi

actual="$(writers)"
if [[ "$actual" != "$expected" ]]; then
  echo "identity-link reducer writer inventory changed." >&2
  echo "Expected:" >&2
  printf '%s\n' "$expected" >&2
  echo "Actual:" >&2
  printf '%s\n' "$actual" >&2
  echo "Review docs/standards/IDENTITY_CONCURRENCY.md and update this guard only after the new writer is proven safe." >&2
  exit 1
fi

echo "identity-link reducer writer inventory: OK"
