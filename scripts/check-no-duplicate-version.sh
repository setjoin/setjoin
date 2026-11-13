#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-no-duplicate-version.sh — migration version-suffix dedup guard.
#
# The schema corpus is "Flyway-compatible" (mailserver/sql/AGENTS.md): two
# migration files sharing a `V<NNN>` version prefix are a HARD `flyway validate`
# error, and under the test loader (scripts/load-test-schema.sh) their apply
# order is decided by `LC_ALL=C sort` — which we pin precisely so a same-version
# pair never depends on filesystem/collation luck. This guard scans BOTH
# migration trees (D3) and FAILS CI the instant a NEW duplicate `V<NNN>` prefix
# appears. The next free version must be used instead (mailserver next-free V092).
#
# Four pre-existing mailserver pairs are FROZEN (shipped migrations can't be
# renamed) and live on an explicit, commented allowlist below. The guard fails
# only on a FIFTH (or any duplicate in the currently-clean authserver tree).
#
# Greppy + fast, in the genre of scripts/check-account-scope.sh /
# check-identity-predicate.sh.
#
# Usage: scripts/check-no-duplicate-version.sh   (exit 0 = clean, 1 = a new dup).
# Wired into scripts/test.sh; self-tested by scripts/check-no-duplicate-version-selftest.sh.
# MIGRATION_DIRS may be overridden (space-separated absolute dirs) by the self-test.
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

MIGRATION_DIRS="${MIGRATION_DIRS:-$ROOT/mailserver/sql/dbschema $ROOT/authserver/sql/migrations}"

# ── Allowlist (FROZEN pre-existing mailserver same-version pairs) ─────────────
# Format: one "V<NNN>" token per line. These four suffixes name two shipped
# migration files each; the migrations are frozen (can't be renamed) so they are
# tolerated. Any version NOT on this list that names ≥2 files fails the guard.
#   V026 → antiphish.sql            + scim_provisioning.sql
#   V027 → ediscovery_cases.sql     + oidc_client_type.sql
#   V051 → external_sender_config.sql + user_signatures.sql
#   V060 → common_passwords.sql     + mam_policy_engine.sql
ALLOWLIST="V026 V027 V051 V060"

is_allowlisted() {
  local v="$1" a
  for a in $ALLOWLIST; do [ "$v" = "$a" ] && return 0; done
  return 1
}

echo "==> migration version-suffix dedup guard (no new duplicate V<NNN>)"

fail=0
for dir in $MIGRATION_DIRS; do
  [ -d "$dir" ] || continue
  # Enumerate the version prefix of every V<NNN>__*.sql file, find any that
  # names two or more files.
  dups="$(
    # Controlled migration filenames are intentionally parsed as a sorted listing.
    # shellcheck disable=SC2010
    ls "$dir" 2>/dev/null \
      | grep -E '^V[0-9]+__.*\.sql$' \
      | sed -E 's/^(V[0-9]+)__.*/\1/' \
      | LC_ALL=C sort \
      | uniq -d
  )"
  for v in $dups; do
    if is_allowlisted "$v"; then
      continue
    fi
    fail=1
    echo ""
    echo "  DUPLICATE migration version: $v names >1 file in"
    echo "    $dir"
    # shellcheck disable=SC2010
    ls "$dir" | grep -E "^${v}__.*\.sql$" | sed 's/^/      /'
    echo "  → two files at the same version are a flyway-validate error and make"
    echo "    the loader's apply order ambiguous. Rename one to the next free"
    echo "    version (mailserver next-free V092). If this MUST be an allowed pair"
    echo "    (a frozen shipped migration), add '$v' to ALLOWLIST in"
    echo "    scripts/check-no-duplicate-version.sh with a one-line reason."
  done
done

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "==> dedup guard FAILED — a new duplicate migration version was introduced."
  exit 1
fi

echo "    no new duplicate versions (4 frozen mailserver pairs allowlisted; authserver clean)."
