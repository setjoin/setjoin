#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-identity-predicate.sh — definition guard for the address-aware identity
# predicate twins (shared/identity plan, retired-docs:superpowers/plans/archive/2026-06-18-
# shared-identity-seam.md → Concern B; ADR-004 §3 address-aware identity).
#
# "Which person is this address?" is resolved by ONE matching rule — a person is
# their FULL address set (`users.email` ∪ `aliases.email` ∪ `users.ad_upn`,
# case-folded, enabled-only). That rule lives in TWO twin copies, one per server,
# because the PROJECTION differs (authserver needs the full Identity row for JIT,
# mailserver needs (user_id, primary_mailbox, domain_id)) — but the PREDICATE
# (who matches) MUST agree. If the predicate drifts you get split-brain identity:
# auth logs you in, mail can't find your mailbox (silent lockout / orphan). The
# two twins:
#
#   - mailserver/sql/reducers/resolve_identity.sql        (the reducer twin)
#   - authserver/internal/connector/connector.go:ResolveIdentitySQL (the Go twin)
#
# This is a DEFINITION guard (it compares the RULE TEXT), not result-set sampling
# (which only catches drift a fixture happens to exercise). It extracts the
# WHERE/predicate from each twin, NORMALIZES away the cosmetic differences —
#   · the bound-address token: `$1` (Go) ⇄ `p_address` (reducer)        → :ADDR
#   · the mailboxes-table alias: `mb` (Go) ⇄ `m` (reducer)              → MB
#   · whitespace / newlines / tabs                                      → collapsed
#   · the reducer-only `AND :ADDR IS NOT NULL` null-guard               → dropped
# — and asserts the two normalized predicates are EQUAL. It fails CI the instant
# they diverge (a 4th OR branch, a changed case-fold, a different join, …).
#
# WHY a definition guard and not the view yet: the union is worth single-sourcing
# into a `resolvable_identity` SQL view only once the MATCHING RULE itself changes
# (a NameID/`sub` normalization landing) — see the plan's view-now-vs-drift-guard
# fork. Until then the two guarded twins are the cheaper, lower-risk seam. A
# normalization change to the rule is the documented trigger to flip to the view;
# this guard firing on an *intended* change is that signal.
#
# Greppy + fast, in the genre of scripts/check-account-scope.sh.
#
# Usage: scripts/check-identity-predicate.sh   (exit 0 = twins agree, 1 = drift).
# Wired into scripts/test.sh; self-tested by scripts/check-identity-predicate-selftest.sh.
# REDUCER_FILE / CONNECTOR_FILE may be overridden (used by the self-test).
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

REDUCER_FILE="${REDUCER_FILE:-$ROOT/mailserver/sql/reducers/resolve_identity.sql}"
CONNECTOR_FILE="${CONNECTOR_FILE:-$ROOT/authserver/internal/connector/connector.go}"

echo "==> identity-predicate definition guard (resolve_identity twins, ADR-004)"

# extract_reducer_predicate <file> — the WHERE…) body of resolve_identity's SELECT.
# The reducer predicate runs from the `WHERE u.enabled` line up to (not incl.) the
# `ORDER BY` / `LIMIT` line. We print those lines verbatim for normalize() to fold.
extract_reducer_predicate() {
  awk '
    /^[ \t]*WHERE[ \t]+u\.enabled/ { grab = 1 }
    grab && /^[ \t]*(ORDER[ \t]+BY|LIMIT)([ \t]|$)/ { grab = 0 }
    grab { print }
  ' "$1"
}

# extract_connector_predicate <file> — the WHERE…) body of the ResolveIdentitySQL
# Go const. Runs from `WHERE u.enabled` up to (not incl.) the `LIMIT` line.
extract_connector_predicate() {
  awk '
    /^[ \t]*WHERE[ \t]+u\.enabled/ { grab = 1 }
    grab && /^[ \t]*LIMIT([ \t]|$)/ { grab = 0 }
    grab { print }
  ' "$1"
}

# normalize — read the raw predicate on stdin, emit ONE normalized line.
# Steps (order matters):
#   1. collapse all whitespace → single spaces (so token regexes are line-blind)
#   2. drop the leading WHERE keyword  (keep the predicate body only)
#   3. bound-address token → :ADDR     ($1 and p_address are the same input)
#   4. mailboxes alias → MB            (discover `(FROM|JOIN) mailboxes <alias>`,
#                                       canonicalize the declaration AND every
#                                       `<alias>.` reference token-wise to `MB` —
#                                       definition-accurate, not a blind m/mb swap)
#   5. drop the `AND :ADDR IS NOT NULL` reducer-only null-guard
#   6. trim
# Token-boundary-safe replacement is done by replace_tok(): POSIX awk gsub() has
# NO backreference support in the replacement string, so we hand-roll a
# match()/substr() loop that respects identifier boundaries.
normalize() {
  awk '
    # is the char at string[pos] (1-based) a SQL identifier char?
    function isidc(s, pos,    c) {
      if (pos < 1 || pos > length(s)) return 0
      c = substr(s, pos, 1)
      return (c ~ /[A-Za-z0-9_]/)
    }
    # replace every WHOLE-identifier occurrence of <tok> in <s> with <rep>.
    # tok is treated as a literal identifier; a match counts only when neither
    # the preceding nor following char is an identifier char (so "u" never hits
    # "ad_upn", "m" never hits "email", etc.).
    function replace_tok(s, tok, rep,    out, n, start, idx, before, after) {
      out = ""; n = length(tok)
      start = 1
      while ((idx = index(substr(s, start), tok)) > 0) {
        idx += start - 1                       # absolute position in s
        before = idx - 1
        after = idx + n
        if (!isidc(s, before) && !isidc(s, after)) {
          out = out substr(s, start, idx - start) rep
          start = after
        } else {
          out = out substr(s, start, idx - start + 1)
          start = idx + 1
        }
      }
      out = out substr(s, start)
      return out
    }
    { lines[NR] = $0 }
    END {
      blob = ""
      for (i = 1; i <= NR; i++) blob = blob " " lines[i]

      # 1. collapse whitespace to single spaces.
      gsub(/[ \t\n]+/, " ", blob)
      sub(/^ +/, "", blob); sub(/ +$/, "", blob)

      # 2. drop the leading WHERE keyword.
      sub(/^[Ww][Hh][Ee][Rr][Ee] +/, "", blob)

      # 3. bound-address token. $1 (Go) and p_address (reducer) are one input.
      #    $1 has no identifier-char neighbours issue ("$" is not [A-Za-z0-9_]),
      #    so a plain gsub is safe; p_address goes through the boundary-safe path.
      gsub(/\$1/, ":ADDR", blob)
      blob = replace_tok(blob, "p_address", ":ADDR")

      # 4. discover the mailboxes alias(es): `(FROM|JOIN) mailboxes [AS] <alias>`.
      ma = blob
      while (match(ma, /(FROM|JOIN) mailboxes (AS )?[A-Za-z_][A-Za-z0-9_]*/)) {
        seg = substr(ma, RSTART, RLENGTH)
        al = seg
        sub(/^(FROM|JOIN) mailboxes /, "", al)
        sub(/^AS /, "", al)
        if (al ~ /^[A-Za-z_][A-Za-z0-9_]*$/) mbalias[al] = 1
        ma = substr(ma, RSTART + RLENGTH)
      }
      # Canonicalize the declaration (`mailboxes <alias>` → `mailboxes MB`) and
      # every `<alias>` reference to `MB`. replace_tok keeps it boundary-safe.
      for (al in mbalias) {
        blob = replace_tok(blob, "mailboxes " al, "mailboxes MB")
        blob = replace_tok(blob, al, "MB")
      }

      # 5. drop the reducer-only null-guard `AND :ADDR IS NOT NULL`.
      gsub(/AND :ADDR IS NOT NULL */, "", blob)

      # 6. collapse any whitespace introduced above, trim.
      gsub(/  +/, " ", blob)
      sub(/^ +/, "", blob); sub(/ +$/, "", blob)
      print blob
    }
  '
}

if [ ! -f "$REDUCER_FILE" ]; then
  echo "  identity-predicate guard: reducer twin not found: $REDUCER_FILE"
  exit 1
fi
if [ ! -f "$CONNECTOR_FILE" ]; then
  echo "  identity-predicate guard: connector twin not found: $CONNECTOR_FILE"
  exit 1
fi

red_raw="$(extract_reducer_predicate "$REDUCER_FILE")"
con_raw="$(extract_connector_predicate "$CONNECTOR_FILE")"

if [ -z "$red_raw" ]; then
  echo "  identity-predicate guard: could not extract the reducer predicate from"
  echo "    $REDUCER_FILE — the WHERE u.enabled … (ORDER BY|LIMIT) shape changed."
  echo "    Update extract_reducer_predicate() in scripts/check-identity-predicate.sh."
  exit 1
fi
if [ -z "$con_raw" ]; then
  echo "  identity-predicate guard: could not extract the connector predicate from"
  echo "    $CONNECTOR_FILE — the WHERE u.enabled … LIMIT shape changed."
  echo "    Update extract_connector_predicate() in scripts/check-identity-predicate.sh."
  exit 1
fi

red_norm="$(printf '%s\n' "$red_raw" | normalize)"
con_norm="$(printf '%s\n' "$con_raw" | normalize)"

if [ "$red_norm" != "$con_norm" ]; then
  echo ""
  echo "  identity-predicate DRIFT — the two address-resolution twins disagree."
  echo "  Their matching predicate MUST stay structurally identical (shared/identity"
  echo "  plan, 2026-06-18). A divergence is split-brain identity: auth resolves a"
  echo "  person the mailserver can't (silent lockout / duplicate JIT)."
  echo ""
  echo "  reducer  (resolve_identity.sql), normalized:"
  echo "      $red_norm"
  echo "  connector (connector.go:ResolveIdentitySQL), normalized:"
  echo "      $con_norm"
  echo ""
  echo "  → make the WHERE predicates match (cosmetic \$1/p_address, m/mb, whitespace,"
  echo "    and the reducer's IS NOT NULL null-guard are normalized away — anything"
  echo "    still differing is a REAL rule divergence). If the change is intentional"
  echo "    (a normalization-rule change), that is the trigger to merge the union into"
  echo "    a single resolvable_identity view — see the plan's view-now fork."
  exit 1
fi

echo "    identity-predicate twins agree (normalized): $red_norm"
