#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-jit-coverage.sh — JIT activation COVERAGE GUARD (D7 / rbac-jit-activation).
#
# WHY THIS EXISTS. Admin RBAC JIT activation (branch rbac-jit-activation) adds a
# new gate: admin_assignment_active(eligible, activated_until) checks BOTH expiry
# AND whether the user has actually activated their assignment. Every query that
# reads admin_role_assignments WITH an `expires_at IS NULL OR expires_at > now()`
# active-filter and is used for permission / reach ENFORCEMENT must also route
# through admin_assignment_active() — otherwise a dormant (eligible-but-not-
# activated) assignment silently over-grants or under-denies at that site.
# This is the machine-checked backstop for that safety claim (memory:
# coverage-claims-need-a-machine-guard; the RLS-W3 manual sweep missed ~17 files).
#
# WHAT IT DOES. Scans:
#   · mailserver/sql/reducers/*.sql          — PL/pgSQL reducers
#   · mailserver/sql/dbschema/V019__dengbao_sod.sql
#   · mailserver/sql/dbschema/V024__sod_exclusion_perm_span.sql
#   · shared/permissions/resolver.go
#   · authserver/internal/handlers/auth.go
#   · authserver/internal/handlers/session.go
#   · authserver/internal/handlers/impersonation.go
#   · authserver/internal/token/refresh.go
#   · mailserver/internal/admin/admin_roles.go
#   · mailserver/internal/admin/admin_users.go
#   · mailserver/internal/jmap/handler.go
# For each site (SQL file = whole file; Go file = each backtick SQL literal)
# that touches admin_role_assignments AND carries the expires_at active-filter,
# the site must EITHER also contain admin_assignment_active( (WRAPPED), OR be
# in scripts/jit-coverage-allowlist.txt with a CLASS and reason. Unclassified
# unwrapped sites → FAIL naming file:line.
#
# ALLOWLIST FORMAT (jit-coverage-allowlist.txt):
#   <basename>TAB<CLASS>TAB<unique lowercase substring>TABreason
#   CLASS ∈ WRAPPED | IS-ADMIN | POTENTIAL | INCLUDES-ELIGIBLE | SOD | HINT
#   Blank lines and #-comment lines are ignored.
#   For SQL files: basename = the .sql filename; substring found in lowercased file.
#   For Go files:  basename = the .go filename; substring found in lowercased literal.
#
# CLASS SEMANTICS:
#   WRAPPED          — contains admin_assignment_active( (detected automatically).
#   IS-ADMIN         — is_admin claim derivation: intentionally counts eligible so
#                      chain.go runs Resolve; JIT gate lives in admin_effective_authority.
#   POTENTIAL        — target-side or structural: reads eligible assignments to protect
#                      dormant admins or route to a WRAPPED enforcement function.
#   INCLUDES-ELIGIBLE— recertification / audit: deliberately includes eligible rows.
#   SOD              — SoD trigger or precheck: bites on eligible-or-active by design.
#   HINT             — UI manageable-hint only; not enforcement; expires-only acceptable.
#
# SELF-TEST. -selftest builds wrapped + unwrapped SQL fixtures and asserts:
#   (A) wrapped-only + empty allowlist → guard PASSES
#   (B) unwrapped-only + empty allowlist → guard FAILS naming the file
#   (C) unwrapped + classified allowlist → guard PASSES
#   (D) both + empty allowlist → guard fires on unwrapped
#
# Usage: scripts/check-jit-coverage.sh             (exit 0 = clean, 1 = gaps)
#        scripts/check-jit-coverage.sh -selftest    (proves the guard fires)
# Wired via the guard manifest (scripts/run-guards.sh — globbed with every scripts/check-*.sh
# by scripts/test.sh and CI).
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

export LC_ALL=C

# ── Self-test ──────────────────────────────────────────────────────────────
if [ "${1:-}" = "-selftest" ]; then
  SELF_GUARD="$(cd "$(dirname "$0")" && pwd)/check-jit-coverage.sh"
  SELF_WORK="$(mktemp -d)"
  trap 'rm -rf "$SELF_WORK"' EXIT

  # Wrapped site: admin_role_assignments + active-filter + admin_assignment_active → PASS.
  cat > "$SELF_WORK/wrapped.sql" <<'SQL'
-- test fixture: WRAPPED — has admin_assignment_active; guard must pass.
CREATE OR REPLACE FUNCTION admin_test_wrapped(p_user_id bigint)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS(
    SELECT 1 FROM admin_role_assignments ra
     WHERE ra.user_id = p_user_id
       AND (ra.expires_at IS NULL OR ra.expires_at > now())
       AND admin_assignment_active(ra.eligible, ra.activated_until)
  );
$$;
SQL

  # Unwrapped site: admin_role_assignments + active-filter, NO admin_assignment_active → FAIL.
  cat > "$SELF_WORK/unwrapped.sql" <<'SQL'
-- test fixture: UNWRAPPED — missing admin_assignment_active; guard must fire.
CREATE OR REPLACE FUNCTION admin_test_unwrapped(p_user_id bigint)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS(
    SELECT 1 FROM admin_role_assignments ra
     WHERE ra.user_id = p_user_id
       AND (ra.expires_at IS NULL OR ra.expires_at > now())
  );
$$;
SQL

  ALLOW_EMPTY="$SELF_WORK/allow-empty.txt"
  : > "$ALLOW_EMPTY"

  ALLOW_CLASSIFIED="$SELF_WORK/allow-classified.txt"
  printf 'unwrapped.sql\tPOTENTIAL\tadmin_test_unwrapped\tselftest: classified site\n' \
    > "$ALLOW_CLASSIFIED"

  pass=0; sfail=0
  ok()  { echo "  ok: $1";   pass=$((pass+1)); }
  bad() { echo "  FAIL: $1"; sfail=$((sfail+1)); }

  echo "==> JIT-coverage guard self-test"

  # (A) Only the wrapped SQL file, empty allowlist → guard PASSES.
  rc_wrapped=0
  out_wrapped="$(JIT_SCAN_SQL_FILES="$SELF_WORK/wrapped.sql" JIT_SCAN_GO_FILES="" \
    JIT_ALLOWLIST_FILE="$ALLOW_EMPTY" bash "$SELF_GUARD" 2>&1)" || rc_wrapped=$?
  if [ "$rc_wrapped" -eq 0 ]; then
    ok "(A) wrapped SQL — guard passes"
  else
    bad "(A) wrapped SQL — guard FAILED (false-negative on wrapped site):"
    printf '%s\n' "$out_wrapped" | sed 's/^/        /'
  fi

  # (B) Only the unwrapped SQL file, empty allowlist → guard FAILS naming it.
  rc_unwrapped=0
  out_unwrapped="$(JIT_SCAN_SQL_FILES="$SELF_WORK/unwrapped.sql" JIT_SCAN_GO_FILES="" \
    JIT_ALLOWLIST_FILE="$ALLOW_EMPTY" bash "$SELF_GUARD" 2>&1)" || rc_unwrapped=$?
  if [ "$rc_unwrapped" -ne 0 ]; then
    ok "(B) unwrapped SQL — guard fires (exit $rc_unwrapped)"
  else
    bad "(B) unwrapped SQL — guard DID NOT fire (false-negative!)"
  fi
  if printf '%s' "$out_unwrapped" | grep -qi 'unwrapped.sql'; then
    ok "(B) unwrapped SQL — named in output"
  else
    bad "(B) unwrapped SQL — NOT named in output"
  fi

  # (C) Unwrapped SQL + classified allowlist → guard PASSES.
  rc_classified=0
  out_classified="$(JIT_SCAN_SQL_FILES="$SELF_WORK/unwrapped.sql" JIT_SCAN_GO_FILES="" \
    JIT_ALLOWLIST_FILE="$ALLOW_CLASSIFIED" bash "$SELF_GUARD" 2>&1)" || rc_classified=$?
  if [ "$rc_classified" -eq 0 ]; then
    ok "(C) unwrapped + classified allowlist — guard passes"
  else
    bad "(C) unwrapped + classified allowlist — guard FAILED:"
    printf '%s\n' "$out_classified" | sed 's/^/        /'
  fi

  # (D) Both files + empty allowlist → guard fires on unwrapped, not on wrapped.
  rc_both=0
  out_both="$(JIT_SCAN_SQL_FILES="$SELF_WORK/wrapped.sql $SELF_WORK/unwrapped.sql" \
    JIT_SCAN_GO_FILES="" JIT_ALLOWLIST_FILE="$ALLOW_EMPTY" bash "$SELF_GUARD" 2>&1)" \
    || rc_both=$?
  if [ "$rc_both" -ne 0 ]; then
    ok "(D) both files, empty allowlist — guard fires"
  else
    bad "(D) both files, empty allowlist — guard DID NOT fire"
  fi
  if printf '%s' "$out_both" | grep -qi 'unwrapped.sql'; then
    ok "(D) unwrapped.sql named; wrapped.sql not named"
  else
    bad "(D) unwrapped.sql not named in output"
  fi

  echo ""
  if [ "$sfail" -ne 0 ]; then
    echo "JIT-coverage guard self-test FAILED ($sfail/$((pass+sfail)) checks failed)."
    exit 1
  fi
  echo "JIT-coverage guard self-test: all $pass checks passed (guard fires and is precise)."
  exit 0
fi
# ── End self-test ──────────────────────────────────────────────────────────

# JIT_SCAN_SQL_FILES / JIT_SCAN_GO_FILES / JIT_ALLOWLIST_FILE may be overridden
# (used by -selftest above and integration tests). Defaults point at the real tree.

if [ -n "${JIT_ALLOWLIST_FILE+x}" ]; then
  ALLOWLIST_FILE="$JIT_ALLOWLIST_FILE"
else
  ALLOWLIST_FILE="$(dirname "$0")/jit-coverage-allowlist.txt"
fi

echo "==> JIT coverage guard: admin_role_assignments active-filter → admin_assignment_active( or allowlisted"

if [ ! -f "$ALLOWLIST_FILE" ]; then
  echo "  [JIT] allowlist not found: $ALLOWLIST_FILE" >&2
  exit 1
fi

# Load allowlist once: blank/comment lines stripped.
ALLOW_LINES="$(grep -vE '^[[:space:]]*(#|$)' "$ALLOWLIST_FILE" || true)"

# is_allowlisted <basename> <lowercased-body>
# Allowlist format: <basename>TAB<CLASS>TAB<unique lowercase substring>TABreason
# Entry matches when basename equals the file and unique substring is found in
# the lowercased body. Unique substring must not contain shell metacharacters
# (especially $) to avoid pattern-expansion hazards in the case statement.
is_allowlisted() {
  local base="$1" body_low="$2" line akey asub
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    akey="${line%%	*}"                         # field 1: basename
    asub="${line#*	}"; asub="${asub#*	}"      # skip CLASS (field 2)
    asub="${asub%%	*}"                          # field 3: unique substring
    [ "$akey" = "$base" ] || continue
    case "$body_low" in *"$asub"*) return 0 ;; esac
  done <<< "$ALLOW_LINES"
  return 1
}

fail=0
report() { echo "  $1"; fail=1; }

# ── Compute file lists ─────────────────────────────────────────────────────
if [ -n "${JIT_SCAN_SQL_FILES+x}" ]; then
  # Selftest override: caller supplies explicit space-separated list.
  SQL_FILES="$JIT_SCAN_SQL_FILES"
else
  # Default: all reducer SQL files + ALL V0*.sql schema migrations (catches trigger
  # logic in any migration, not just the two SoD ones originally named).
  SQL_FILES="$(find "$ROOT/mailserver/sql/reducers" -name '*.sql' -type f \
    | LC_ALL=C sort | tr '\n' ' ') \
    $(find "$ROOT/mailserver/sql/dbschema" -name 'V0*.sql' -type f \
    | LC_ALL=C sort | tr '\n' ' ')"
fi

if [ -n "${JIT_SCAN_GO_FILES+x}" ]; then
  # Selftest override: caller supplies explicit space-separated list (may be empty).
  GO_FILES="$JIT_SCAN_GO_FILES"
else
  GO_FILES="\
    $ROOT/shared/permissions/resolver.go \
    $ROOT/authserver/internal/handlers/auth.go \
    $ROOT/authserver/internal/handlers/session.go \
    $ROOT/authserver/internal/handlers/impersonation.go \
    $ROOT/authserver/internal/token/refresh.go \
    $ROOT/mailserver/internal/admin/admin_roles.go \
    $ROOT/mailserver/internal/admin/admin_jit.go \
    $ROOT/mailserver/internal/admin/admin_users.go \
    $ROOT/mailserver/internal/jmap/handler.go"
fi

# ── SQL file scan ──────────────────────────────────────────────────────────
# For SQL files the whole file is one logical site (one PL/pgSQL function / trigger).
# A site triggers when the lowercased file contains BOTH:
#   · "admin_role_assignments"
#   · "expires_at is null or expires_at > now()"  (the active-filter)
# WRAPPED: file also contains "admin_assignment_active(" → skip.
# Otherwise: check allowlist; fail if missing.
for f in $SQL_FILES; do
  [ -f "$f" ] || continue
  base="${f##*/}"
  low="$(tr '[:upper:]' '[:lower:]' < "$f" | tr '\n' ' ')"
  case "$low" in *"admin_role_assignments"*) : ;; *) continue ;; esac
  # Active-filter: requires both halves (alias prefix means they're not contiguous).
  case "$low" in *"expires_at is null"*"expires_at > now()"*) : ;; *) continue ;; esac
  # WRAPPED — file also contains the JIT gate call.
  case "$low" in *"admin_assignment_active("*) continue ;; esac
  # Not wrapped — must be in allowlist.
  if is_allowlisted "$base" "$low"; then continue; fi
  report "[JIT] $f"
  report "      admin_role_assignments active-filter without admin_assignment_active( and not in allowlist."
  report "      → add admin_assignment_active() to the query, or classify in scripts/jit-coverage-allowlist.txt."
done

# ── Go file scan (backtick SQL literals) ──────────────────────────────────
# Extracts every backtick-quoted SQL string literal from the named Go files.
# For each literal that has admin_role_assignments AND the active-filter:
#   WRAPPED: literal also has admin_assignment_active( → skip.
#   Otherwise: check allowlist; fail if missing.
# ponytail: handles backtick literals only (raw string literals); double-quoted
#   strings are short identifiers in Go SQL — all real SQL uses backticks here.
#   Upgrade to full AST parse if a backtick-less SQL path is ever added.
TMP_HITS="$(mktemp)"
trap 'rm -f "$TMP_HITS"' EXIT

# shellcheck disable=SC2086
if [ -n "$GO_FILES" ]; then
  awk '
    BEGIN { mode=0; buf=""; startline=0 }
    FNR==1 { fname=FILENAME; mode=0; buf="" }
    {
      line=$0; i=1; n=length(line)
      while (i<=n) {
        c=substr(line,i,1)
        if (mode==1) {
          if (c=="`") { mode=0; emit() }
          else { buf=buf c }
          i++
        } else {
          if (c=="`") { mode=1; buf=""; startline=FNR; i++ }
          else i++
        }
      }
      if (mode==1) buf=buf " "
    }
    function emit(   s, l) {
      s=buf; gsub(/[ \t\r\n]+/," ",s); sub(/^ /,"",s)
      if (s=="") return
      l=tolower(s)
      if (l !~ /admin_role_assignments/) return
      # Active-filter: both halves required; alias prefix means they are not contiguous.
      if (l !~ /expires_at is null/) return
      if (l !~ /expires_at > now\(\)/) return
      print fname ":" startline "\t" l
    }
  ' $GO_FILES > "$TMP_HITS"
fi

while IFS=$'\t' read -r loc body_low; do
  [ -z "$body_low" ] && continue
  base="${loc##*/}"; base="${base%%:*}"
  # WRAPPED — literal contains the JIT gate call.
  case "$body_low" in *"admin_assignment_active("*) continue ;; esac
  if is_allowlisted "$base" "$body_low"; then continue; fi
  report "[JIT] ${loc}"
  report "      admin_role_assignments active-filter in Go SQL literal — not wrapped and not allowlisted."
  report "      → add admin_assignment_active() inside the literal, or classify in scripts/jit-coverage-allowlist.txt."
done < "$TMP_HITS"

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "JIT-coverage guard FAILED — uncovered admin_role_assignments active-filter site(s) above."
  echo "See retired-docs:superpowers/plans/rbac-jit-activation/ and scripts/jit-coverage-allowlist.txt."
  exit 1
fi

echo "    JIT-coverage guard: clean (every active-filter site WRAPPED or allowlisted)."
