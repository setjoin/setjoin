#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-audit-chain-parity.sh — audit-chain hand-clone parity guard
# (arch review #A7).
#
# WHY THIS EXISTS. mailserver/sql/reducers/chat_access_audit.sql self-labels
# itself a "hand-transcribed clone of drive_access_audit.sql … HIGHEST-RISK
# uncoded step, full adversarial review required." The writer + verifier
# mechanics (the hash-chain compute-on-write / recompute-on-read pair) are
# duplicated TOKEN-FOR-TOKEN between the two files, differing only in five
# documented substitutions:
#   · the scope table       (chat_audit_log ↔ drive_audit_log)
#   · the scope column      (channel_id ↔ space_id)
#   · the action-catalog fn (chat_audit_actions() ↔ drive_audit_actions())
#   · the BZ error code     (BZ191 ↔ BZ141)
#   · the advisory-lock prefix string (chat_audit_ ↔ drive_audit_)
# The conservative choice (per the arch-review ledger — NOT a risky merge of
# compliance-critical audit infrastructure, which a future pillar's clone #3
# will extend the same way) is a byte-parity guard: normalize both sides by
# name and strip comments/whitespace, then require the two bodies to be
# IDENTICAL. If they diverge, "full adversarial review required" stops being
# a prose warning nobody re-checks and starts being a CI failure that names
# the exact line drifted.
#
# WHAT IT CHECKS. Four function bodies, two clone pairs:
#   writer:   chat_access_audit()        vs drive_access_audit()
#   verifier: verify_chat_audit_chain()  vs verify_drive_audit_chain()
# Each side is extracted from its CREATE OR REPLACE FUNCTION statement
# (inclusive) through its closing `$$;` / `$$ LANGUAGE ...;`, comments and
# blank lines stripped, whitespace collapsed, then SIX documented tokens are
# substituted for common placeholders (longest-token-first, so a substring
# like `chat_audit_` never partially eats a superstring like
# `chat_audit_actions` or `verify_chat_audit_chain` before that superstring
# gets its own substitution): the five from the header list above, plus the
# bare domain word itself (`chat`/`drive`) as it survives standalone in the
# RAISE EXCEPTION message text ('unknown chat audit action %' / 'unknown
# drive audit action %') once every chat_*/drive_*-prefixed identifier has
# already been consumed by its own more specific substitution — applied last
# and un-anchored deliberately (no portable \b/\< in BSD sed, the shell this
# repo runs on; verified by grep that no OTHER bare occurrence of either word
# survives comment-stripping, so a plain substring replace is safe here).
# The normalized chat body and the normalized drive body must then be
# byte-identical.
#
# NOT in scope: `mailserver/sql/reducers/audit_write.sql` (the
# admin_audit_log "global variant" the arch-review ledger also names) — it
# chains via a DB TRIGGER (`trg_admin_audit_checksum`), a structurally
# different mechanism from drive/chat's explicit compute-and-INSERT, so the
# same five-token substitution set does not apply. Not this guard's job to
# invent a second normalization scheme for a different shape; noted here so
# the exclusion is a decision, not an oversight.
#
# This guard does NOT rewrite or merge the reducers — per the ledger, a
# merge of compliance-critical audit infrastructure is the risky move; this
# is the conservative belt.
#
# Usage: scripts/check-audit-chain-parity.sh   (exit 0 = both clone pairs
#        byte-identical after normalization, 1 = a real divergence, named
#        with a unified diff of the normalized bodies).
# Self-test: scripts/check-audit-chain-parity-selftest.sh (run first by
# run-guards.sh).
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

export LC_ALL=C

CHAT_FILE="${AUDIT_PARITY_CHAT_FILE:-$ROOT/mailserver/sql/reducers/chat_access_audit.sql}"
DRIVE_FILE="${AUDIT_PARITY_DRIVE_FILE:-$ROOT/mailserver/sql/reducers/drive_access_audit.sql}"

echo "==> audit-chain hand-clone parity guard (#A7)"

fail=0

for f in "$CHAT_FILE" "$DRIVE_FILE"; do
  if [ ! -f "$f" ]; then
    echo "  [AUDIT-PARITY] file not found: $f" >&2
    exit 1
  fi
done

# extract_fn <file> <function-name> — prints the CREATE OR REPLACE FUNCTION
# statement for <function-name>, from its CREATE line (anchored — so
# `chat_access_audit` never accidentally matches the `verify_chat_audit_chain`
# line) through its closing `$$;` or `$$ LANGUAGE ...;` line, inclusive.
extract_fn() {
  local file="$1" name="$2"
  awk -v name="$name" '
    $0 ~ ("^CREATE OR REPLACE FUNCTION " name "\\(") { grabbing = 1 }
    grabbing { print }
    grabbing && ($0 ~ /^\$\$;[[:space:]]*$/ || $0 ~ /^\$\$ LANGUAGE.*;[[:space:]]*$/) { exit }
  ' "$file"
}

# normalize <substitution-sed-script> — reads stdin, strips `--` line
# comments and blank lines, collapses whitespace, trims, then applies the
# caller's token substitutions (longest-token-first, passed as a sed -e
# script so the caller controls order).
normalize() {
  local subs="$1"
  sed -E 's/--.*$//' \
    | sed -E '/^[[:space:]]*$/d' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/[[:space:]]+/ /g' \
    | sed -E "$subs"
}

# Longest-token-first substitution scripts (see header: a shorter token like
# `chat_audit_` is a prefix of `chat_audit_log`/`chat_audit_actions`/
# `verify_chat_audit_chain`'s tail — those superstrings MUST be replaced
# first, or the shorter substitution would eat part of them).
CHAT_SUBS='
s/verify_chat_audit_chain/__VERIFIER_FN__/g;
s/chat_audit_actions/__ACTION_CATALOG_FN__/g;
s/chat_audit_log/__AUDIT_TABLE__/g;
s/chat_access_audit/__WRITER_FN__/g;
s/chat_audit_/__LOCK_PREFIX__/g;
s/channel_id/__SCOPE_COL__/g;
s/BZ191/__BZ_CODE__/g;
s/chat/__DOMAIN__/g;
'
DRIVE_SUBS='
s/verify_drive_audit_chain/__VERIFIER_FN__/g;
s/drive_audit_actions/__ACTION_CATALOG_FN__/g;
s/drive_audit_log/__AUDIT_TABLE__/g;
s/drive_access_audit/__WRITER_FN__/g;
s/drive_audit_/__LOCK_PREFIX__/g;
s/space_id/__SCOPE_COL__/g;
s/BZ141/__BZ_CODE__/g;
s/drive/__DOMAIN__/g;
'

check_pair() { # <label> <chat-fn-name> <drive-fn-name>
  local label="$1" chat_fn="$2" drive_fn="$3"
  local chat_raw drive_raw chat_norm drive_norm

  chat_raw="$(extract_fn "$CHAT_FILE" "$chat_fn")"
  drive_raw="$(extract_fn "$DRIVE_FILE" "$drive_fn")"

  if [ -z "$chat_raw" ]; then
    echo "  [AUDIT-PARITY] $label: could not find $chat_fn() in $CHAT_FILE (renamed/deleted?)." >&2
    fail=1
    return
  fi
  if [ -z "$drive_raw" ]; then
    echo "  [AUDIT-PARITY] $label: could not find $drive_fn() in $DRIVE_FILE (renamed/deleted?)." >&2
    fail=1
    return
  fi

  chat_norm="$(printf '%s\n' "$chat_raw" | normalize "$CHAT_SUBS")"
  drive_norm="$(printf '%s\n' "$drive_raw" | normalize "$DRIVE_SUBS")"

  if [ "$chat_norm" != "$drive_norm" ]; then
    echo "  [AUDIT-PARITY] $label: $chat_fn() and $drive_fn() have DIVERGED beyond the five documented substitutions (table/scope-column/action-catalog-fn/BZ-code/lock-prefix)." >&2
    echo "                 → either the clone drifted (fix it to restore parity) or a NEW legitimate difference was introduced (extend the substitution set in this guard, with a comment explaining why)." >&2
    diff -u <(printf '%s\n' "$drive_norm") <(printf '%s\n' "$chat_norm") | sed 's/^/    /' >&2
  else
    echo "  ok: $label ($chat_fn <-> $drive_fn) — byte-identical after normalization"
  fi
}

check_pair "writer"   "chat_access_audit"        "drive_access_audit"
check_pair "verifier" "verify_chat_audit_chain"   "verify_drive_audit_chain"

echo ""
if [ "$fail" -ne 0 ]; then
  echo "audit-chain parity guard FAILED — see above."
  exit 1
fi
echo "    audit-chain parity guard: clean (chat_access_audit.sql is a faithful clone of drive_access_audit.sql)."
