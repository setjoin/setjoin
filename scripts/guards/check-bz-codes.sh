#!/usr/bin/env bash
# check-bz-codes.sh — every reducer BZ error code must be registered in
# docs/reducer-error-codes.md. Catches the drift where a new
# `RAISE EXCEPTION ... USING ERRCODE='BZxxx'` ships without a registry entry
# (BZ060–BZ069 sat undocumented until 2026-07-05). The registry is the one place
# the ~92 codes' meaning + HINT type + owning reducer are cross-referenced; an
# undocumented code is an untyped error the gateway can't project cleanly.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
DOC=docs/reducer-error-codes.md

used=$(mktemp); doc=$(mktemp)
trap 'rm -f "$used" "$doc"' EXIT

# Codes actually raised in reducers.
grep -rhoE "ERRCODE[[:space:]]*=[[:space:]]*'BZ[0-9]+'" mailserver/sql/reducers/*.sql \
  | grep -oE 'BZ[0-9]+' | sort -u > "$used"

# Codes documented anywhere in the registry — a `**BZxxx**` table row OR a
# `### BZxxx {#BZxxx}` heading+table (both forms are used). Any structural mention
# counts as documented; the guard only asserts used ⊆ documented, so over-counting
# the doc side is safe (a stray "BZ0xx" prose token can't cause a false failure).
grep -oE 'BZ[0-9]+' "$DOC" | sort -u > "$doc"

missing=$(comm -23 "$used" "$doc")
if [ -n "$missing" ]; then
  echo "==> BZ error-code guard: reducer codes missing from $DOC:" >&2
  echo "$missing" | sed 's/^/    /' >&2
  echo "    Add a table row for each: | **BZxxx** | \`type\` | description | \`file.sql\` | \`hint\` |" >&2
  exit 1
fi
echo "bz-codes guard: clean ($(wc -l < "$used" | tr -d ' ') reducer codes, all documented)."
