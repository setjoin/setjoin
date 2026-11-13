#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-reach-coverage.sh — cross-tenant admin REACH-CHECK coverage guard.
#
# WHY THIS EXISTS. Admin handlers that accept a caller-supplied target user
# or member ID and operate on that user's data MUST route through one of the
# reach-check reducers — admin_can_reach / admin_can_manage /
# admin_protection_check / admin_scope_within — to enforce OU-scope for
# scoped admins.  Missing this check lets a scoped admin (e.g. helpdesk for
# OU-A) mutate data for users outside their OU.  This is the machine-checked
# backstop for that safety claim (memory: coverage-claims-need-a-machine-guard).
#
# WHAT IT DOES. Scans each non-test *.go file in the admin package for Go
# function bodies that:
#   (a) contain a cross-tenant signal — the caller supplied a target user/
#       member ID to operate on (PathValue("userId"), req.UserID, req.MemberID),
#       AND
#   (b) do NOT contain a reach-check call (admin_can_reach(, admin_can_manage(,
#       admin_protection_check(, admin_scope_within().
# Each such function must be in scripts/reach-coverage-allowlist.txt with
#   <basename>TAB<CLASS>TAB<unique lowercase substring>TAB<reason>
# where CLASS ∈ WRAPPED|SUPER-ONLY|DOMAIN-ONLY|READ-ONLY and the unique
# substring appears in the lowercased function body (to identify the handler).
# Unclassified → FAIL naming the file+line.
#
# DETECTION GRANULARITY. Analysis is per function body, bounded by a `^func `
# declaration and the matching closing `}` at column 0 — the invariant
# maintained by gofmt.  This is precise enough to allow a file that has one
# DOMAIN-ONLY and one WRAPPED handler, classifying only the former.
#
# KNOWN GAPS.
#   · Only detects user-ID signals expressed as PathValue("userId"), req.UserID,
#     or req.MemberID.  Handlers that parse a user ID from PathValue("id") (a
#     generic resource-ID path param) are NOT caught — they require a different
#     approach (e.g. SQL-table analysis via check-gateway-ownership.sh).
#     Affected: admin_app_entitlements.go (Set/List), admin_users.go — the
#     latter has reach checks and the former has domain-scope only; both are
#     acknowledged gaps in the OU-scope roadmap.
#   · A file where an allowlist entry's unique substring accidentally matches
#     another function's body will silently pass that other function. Choose
#     substrings that are unique to the handler being classified.
#
# ponytail: per-function analysis via ^func/^} gofmt invariant; good enough
#   for well-formatted Go.  Upgrade to full AST parse if false-negatives emerge.
#
# Usage: scripts/check-reach-coverage.sh             (exit 0 = clean, 1 = gaps)
#        scripts/check-reach-coverage.sh -selftest    (proves the guard fires)
# Wired via the guard manifest (scripts/run-guards.sh — globbed with every scripts/check-*.sh
# by scripts/test.sh and CI).
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

export LC_ALL=C

# ── Self-test ──────────────────────────────────────────────────────────────
if [ "${1:-}" = "-selftest" ]; then
  SELF_GUARD="$(cd "$(dirname "$0")" && pwd)/check-reach-coverage.sh"
  SELF_WORK="$(mktemp -d)"
  trap 'rm -rf "$SELF_WORK"' EXIT

  # Wrapped handler: has admin_can_reach — must PASS.
  cat > "$SELF_WORK/wrapped.go" <<'GO'
package admin

import "net/http"

func (h *H) ManageUser(w http.ResponseWriter, r *http.Request) {
	userID, _ := strconv.ParseInt(r.PathValue("userId"), 10, 64)
	var ok bool
	h.pool.QueryRow(ctx, `SELECT admin_can_reach($1, $2)`, actor, userID).Scan(&ok)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// ... safe to operate on userID now
}
GO

  # Unwrapped handler: has cross-tenant signal, no reach check — must FAIL.
  cat > "$SELF_WORK/unwrapped.go" <<'GO'
package admin

import "net/http"

func (h *H) ResetUserModel(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userId")
	h.pool.Exec(ctx, `DELETE FROM user_spam_model WHERE user_id = $1`, userID)
	w.WriteHeader(http.StatusOK)
}
GO

  ALLOW_EMPTY="$SELF_WORK/allow-empty.txt"
  : > "$ALLOW_EMPTY"

  ALLOW_CLASSIFIED="$SELF_WORK/allow-classified.txt"
  printf 'unwrapped.go\tDOMAIN-ONLY\tresetusermodel\tselftest: classified handler\n' > "$ALLOW_CLASSIFIED"

  pass=0; sfail=0
  ok()  { echo "  ok: $1";   pass=$((pass+1)); }
  bad() { echo "  FAIL: $1"; sfail=$((sfail+1)); }

  echo "==> reach-coverage guard self-test"

  # (A) Only the wrapped handler, empty allowlist → guard PASSES.
  mkdir -p "$SELF_WORK/only_wrapped"
  cp "$SELF_WORK/wrapped.go" "$SELF_WORK/only_wrapped/"
  rc_wrapped=0
  out_wrapped="$(GATEWAY_DIR="$SELF_WORK/only_wrapped" REACH_ALLOWLIST_FILE="$ALLOW_EMPTY" bash "$SELF_GUARD" 2>&1)" \
    || rc_wrapped=$?
  if [ "$rc_wrapped" -eq 0 ]; then
    ok "(A) wrapped handler — guard passes"
  else
    bad "(A) wrapped handler — guard FAILED (false-negative on wrapped handler):"
    printf '%s\n' "$out_wrapped" | sed 's/^/        /'
  fi

  # (B) Only the unwrapped handler, empty allowlist → guard FAILS naming it.
  mkdir -p "$SELF_WORK/only_unwrapped"
  cp "$SELF_WORK/unwrapped.go" "$SELF_WORK/only_unwrapped/"
  rc_unwrapped=0
  out_unwrapped="$(GATEWAY_DIR="$SELF_WORK/only_unwrapped" REACH_ALLOWLIST_FILE="$ALLOW_EMPTY" bash "$SELF_GUARD" 2>&1)" \
    || rc_unwrapped=$?
  if [ "$rc_unwrapped" -ne 0 ]; then
    ok "(B) unwrapped handler — guard fires (exit $rc_unwrapped)"
  else
    bad "(B) unwrapped handler — guard DID NOT fire (false-negative!)"
  fi
  if printf '%s' "$out_unwrapped" | grep -qi 'unwrapped.go'; then
    ok "(B) unwrapped handler — named in output"
  else
    bad "(B) unwrapped handler — NOT named in output"
  fi

  # (C) Unwrapped handler, classified allowlist → guard PASSES.
  rc_classified=0
  out_classified="$(GATEWAY_DIR="$SELF_WORK/only_unwrapped" REACH_ALLOWLIST_FILE="$ALLOW_CLASSIFIED" bash "$SELF_GUARD" 2>&1)" \
    || rc_classified=$?
  if [ "$rc_classified" -eq 0 ]; then
    ok "(C) unwrapped + classified allowlist — guard passes"
  else
    bad "(C) unwrapped + classified allowlist — guard FAILED:"
    printf '%s\n' "$out_classified" | sed 's/^/        /'
  fi

  # (D) Both files, empty allowlist → guard fires on unwrapped but not on wrapped.
  rc_both=0
  out_both="$(GATEWAY_DIR="$SELF_WORK" REACH_ALLOWLIST_FILE="$ALLOW_EMPTY" bash "$SELF_GUARD" 2>&1)" \
    || rc_both=$?
  if [ "$rc_both" -ne 0 ]; then
    ok "(D) both files, empty allowlist — guard fires"
  else
    bad "(D) both files, empty allowlist — guard DID NOT fire"
  fi
  if printf '%s' "$out_both" | grep -qi 'unwrapped.go'; then
    ok "(D) unwrapped.go named; wrapped.go not named"
  else
    bad "(D) unwrapped.go not named in output"
  fi

  echo ""
  if [ "$sfail" -ne 0 ]; then
    echo "reach-coverage guard self-test FAILED ($sfail/$((pass+sfail)) checks failed)."
    exit 1
  fi
  echo "reach-coverage guard self-test: all $pass checks passed (guard fires and is precise)."
  exit 0
fi
# ── End self-test ──────────────────────────────────────────────────────────

# GATEWAY_DIR / REACH_ALLOWLIST_FILE may be overridden (used by -selftest above
# and integration tests).  Defaults point at the real admin handler tree.
GATEWAY="${GATEWAY_DIR:-$ROOT/mailserver/internal/admin}"
ALLOWLIST_FILE="${REACH_ALLOWLIST_FILE:-$(dirname "$0")/reach-coverage-allowlist.txt}"

echo "==> admin reach-check coverage guard: cross-tenant handler → reach-check or allowlist"

if [ ! -f "$ALLOWLIST_FILE" ]; then
  echo "  [REACH] allowlist not found: $ALLOWLIST_FILE" >&2
  exit 1
fi

# Load allowlist once: blank/comment lines stripped.
ALLOW_LINES="$(grep -vE '^[[:space:]]*(#|$)' "$ALLOWLIST_FILE" || true)"

# is_allowlisted <basename> <lowercased-function-body>
# Allowlist format: <basename>TAB<CLASS>TAB<unique lowercase substring>TABreason
# Entry matches when basename equals the file and unique substring is found in
# the lowercased function body.
is_allowlisted() {
  local base="$1" body_low="$2" line akey asub
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    akey="${line%%	*}"                        # field 1: basename
    asub="${line#*	}"; asub="${asub#*	}"     # skip CLASS (field 2)
    asub="${asub%%	*}"                        # field 3: unique substring
    [ "$akey" = "$base" ] || continue
    case "$body_low" in *"$asub"*) return 0 ;; esac
  done <<< "$ALLOW_LINES"
  return 1
}

fail=0
report() { echo "  $1"; fail=1; }

TMP_HITS="$(mktemp)"
trap 'rm -f "$TMP_HITS"' EXIT

# ── Extract function bodies via awk. ──────────────────────────────────────
# Uses the gofmt invariant: top-level Go functions are delimited by
# `^func ` (at column 0) through the closing `^}` (at column 0).  For each
# function body that has a cross-tenant signal (PathValue("userId"), req.UserID,
# req.MemberID) AND no reach-check call, emit: "FILE:STARTLINE<TAB>lowercase_body".
# The closing `^}` itself is included so the function name in the opening
# declaration and the body are both in the emitted text.
# The sorted expansion deliberately supplies one awk input argument per source file.
# shellcheck disable=SC2046
awk '
  BEGIN { in_func=0; buf=""; fstart=0; fname="" }
  FNR==1 { fname=FILENAME; in_func=0; buf="" }
  /^func / {
    in_func=1
    fstart=FNR
    buf=$0 "\n"
    next
  }
  in_func && /^\}/ {
    buf=buf $0 "\n"
    in_func=0
    emit_if_signal()
    buf=""
    next
  }
  in_func { buf=buf $0 "\n" }
  function has_signal(low,   padded) {
    # Word-bounded matches to avoid false-positives:
    #   req.UserIDs (plural) must NOT match req.userid — pad with a space so
    #   end-of-string is not a false negative, then require a non-word char after.
    padded = low " "
    return (padded ~ /pathvalue\("userid"\)/ ||
            padded ~ /req\.userid[^a-z0-9_]/ ||
            padded ~ /req\.memberid[^a-z0-9_]/)
  }
  function emit_if_signal(   low) {
    low=tolower(buf)
    # Cross-tenant signal: handler receives a caller-supplied target user/member ID.
    if (!has_signal(low)) return
    # Reach check present in the same function body → WRAPPED, skip.
    if (low ~ /admin_can_reach\(/ ||
        low ~ /admin_can_manage\(/ ||
        low ~ /admin_protection_check\(/ ||
        low ~ /admin_scope_within\(/) return
    # Collapse newlines to spaces so the record is a single output line
    # (multi-line bodies break the bash while-read loop).
    gsub(/\n/, " ", low)
    # Needs allowlist or reach check — emit for classification loop below.
    print fname ":" fstart "\t" low
  }
' $(find "$GATEWAY" -maxdepth 1 -name '*.go' ! -name '*_test.go' -type f 2>/dev/null | LC_ALL=C sort) > "$TMP_HITS"

# ── Classification loop ────────────────────────────────────────────────────
while IFS=$'\t' read -r loc body_low; do
  [ -z "$body_low" ] && continue
  base="${loc##*/}"; base="${base%%:*}"
  if is_allowlisted "$base" "$body_low"; then
    continue
  fi
  report "[REACH] ${loc}  cross-tenant admin handler — no reach-check and not in allowlist"
  report "        → add admin_can_reach/admin_can_manage/admin_protection_check/admin_scope_within,"
  report "          or classify in scripts/reach-coverage-allowlist.txt as SUPER-ONLY/DOMAIN-ONLY/READ-ONLY."
done < "$TMP_HITS"

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "admin reach-check coverage guard FAILED — uncovered cross-tenant handler(s) above."
  echo "See retired-docs:superpowers/plans/archive/2026-06-26-rbac-group-user-scope-implementation.md (Task 7)."
  exit 1
fi

echo "    reach-check coverage guard: clean (every cross-tenant admin handler WRAPPED or allowlisted)."
