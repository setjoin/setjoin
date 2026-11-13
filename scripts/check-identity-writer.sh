#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-identity-writer.sh — SECONDARY net for the identity-address WRITE seam
# (plan retired-docs:superpowers/plans/archive/2026-06-18-ad-writer-canonical-retire-fold-twin.md,
# Decision C). The PRIMARY enforcement is the compile-time CanonicalAddress
# newtype (shared/identity): the provision/UPDATE write boundaries take
# identity.CanonicalAddress for users.email / users.ad_upn, so a raw u.Email /
# u.UPN / operator string fails to COMPILE. This grep is the cheap belt-and-
# suspenders that catches the ONE thing the type can't: a NEW writer that
# hand-rolls `SELECT provision_account(...)` in a raw SQL string (bypassing the
# typed identity.ProvisionAccount seam) and thereby never touches CanonicalAddress
# at all. If you add such a string, route it through identity.ProvisionAccount
# (or canonicalize the address arg) instead.
#
# WHY a grep when the type is sound: the type only binds at the identity.*
# functions. A future dev could re-introduce a raw `pool.Exec("SELECT
# provision_account(... p_email => $1 ...)", rawEmail)` that the compiler accepts
# (Exec args are ...any). This guard fails CI on exactly that pattern, keeping the
# single typed seam the only address-write path.
#
# Scope: the connector + admin + SCIM WRITERS (AD/LDAP sync, admin users, SCIM
# PATCH). Two enforcement bands:
#   1. raw `provision_account(`/`SyncAttrs(` literals that bypass the typed seam;
#   2. hand-rolled raw `UPDATE users SET email` / `INSERT INTO aliases (...email...)`
#      writes the newtype can't reach — gated by a file-level CanonicalizeAddress
#      obligation (see the address-column band below).
# The SSO JIT path (authserver) routes through NormalizeAndValidate already and is
# out of this guard's connector/admin scope by design (see the plan, Decision D).
#
# Usage: scripts/check-identity-writer.sh   (exit 0 = clean, 1 = raw writer found).
# Wired into scripts/test.sh; self-tested by scripts/check-identity-writer-selftest.sh.
# SEARCH_ROOTS may be overridden (used by the self-test).
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

# The writer files that must route address writes through identity.ProvisionAccount
# (the typed seam) rather than a raw `SELECT provision_account(...)` SQL literal.
# scim is included because the SCIM PATCH path hand-rolls a raw `UPDATE users SET
# email = $1` that the typed seam cannot reach (it is not a provision_account
# call); the address-column guard below gates it.
SEARCH_ROOTS="${SEARCH_ROOTS:-$ROOT/mailserver/internal/ad $ROOT/mailserver/internal/ldapsync $ROOT/mailserver/internal/admin $ROOT/mailserver/internal/scim}"

echo "==> identity-writer guard (raw provision_account literal in connector/admin writers)"

# A raw provision_account SQL literal is the bypass: it binds p_email / p_ad_upn
# directly (a ...any Exec arg the compiler can't type-check). The typed seam
# identity.ProvisionAccount lives in shared/identity and is the ONLY allowed home
# of that SQL string — so any OTHER occurrence in the writer tree is a regression.
#
# Match `provision_account(` appearing inside a Go string context — we grep the
# literal token; the typed seam is in shared/identity (not in SEARCH_ROOTS), so a
# hit here is by definition a hand-rolled writer.
hits="$(grep -rnE 'provision_account\(' \
          --include='*.go' \
          $SEARCH_ROOTS 2>/dev/null \
        | grep -v '_test.go' \
        || true)"

if [ -n "$hits" ]; then
  echo ""
  echo "  identity-writer REGRESSION — a raw 'provision_account(' SQL literal was"
  echo "  found in a connector/admin writer. The address-write path MUST go through"
  echo "  the typed identity.ProvisionAccount seam (its Email/ADUPN params are"
  echo "  CanonicalAddress, so the address is provably canonicalized at compile"
  echo "  time). A raw SQL literal binds p_email/p_ad_upn as an untyped Exec arg,"
  echo "  bypassing that guarantee and re-opening the fold-twin drift class."
  echo ""
  echo "$hits" | sed 's/^/      /'
  echo ""
  echo "  → replace the raw call with identity.ProvisionAccount(ctx, pool,"
  echo "    identity.ProvisionAccountParams{Email: identity.CanonicalizeAddress(...), …})."
  exit 1
fi

# Also flag a raw first-arg to ldaputil.SyncAttrs (the UPDATE-path writer): its
# email param is CanonicalAddress, so a raw call won't compile — but if SyncAttrs
# were ever loosened back to string, this catches the regression cheaply.
# Match the ACTUAL call `ldaputil.SyncAttrs(` (a leading `.` makes it a call, not
# the `buildSyncAttrs(` / `buildLDAPSyncAttrs(` helper definitions/uses, which
# contain the substring "SyncAttrs(" but are not the boundary call).
syncattrs_raw="$(grep -rnE '\.SyncAttrs\(' \
                   --include='*.go' \
                   $SEARCH_ROOTS 2>/dev/null \
                 | grep -v '_test.go' \
                 | grep -vE '\.SyncAttrs\(identity\.CanonicalizeAddress\(' \
                 || true)"

if [ -n "$syncattrs_raw" ]; then
  echo ""
  echo "  identity-writer REGRESSION — an ldaputil.SyncAttrs(...) call whose first"
  echo "  (email) arg is NOT identity.CanonicalizeAddress(...). The UPDATE-path"
  echo "  writer's email column must be Go-canonical; route it through the one"
  echo "  canonicalizer."
  echo ""
  echo "$syncattrs_raw" | sed 's/^/      /'
  exit 1
fi

# ── Non-seam (hand-rolled) address writers ──────────────────────────────────
# The CanonicalAddress newtype only gates the provision_account / SyncAttrs
# seams. A handful of writers bind users.email / aliases.email in a RAW SQL
# literal the type can never reach:
#   · SCIM PATCH:    `UPDATE users SET email = $1`   (scim/patch.go)
#   · admin alias:   `INSERT INTO aliases (... email ...)` (admin/admin_users.go)
#   · AD proxy:      `INSERT INTO aliases (... email ...)` (ad/sync.go)
# For these, "canonicalized" is a FILE-LEVEL obligation the grep CAN enforce:
# any file that hand-rolls such a write MUST also call one of the canonical-fold
# minters — identity.CanonicalizeAddress (the sole CanonicalAddress minter) or
# identity.ValidateAndCanonicalizeEmail (the validating mint implemented OVER
# NormalizeAndValidate → CanonicalizeAddress, pinned by
# TestValidateAndCanonicalizeEmail_IsCanonicalizePrefix to produce the exact
# CanonicalizeAddress output) — proving the bound value passed the one fold. A
# file with the raw write but NO fold-minter call is the regression this catches
# — exactly the class B1's fold_stored_address demotion depends on being
# un-writable.
addr_write_files="$(grep -rlE \
        'UPDATE[[:space:]]+users[[:space:]]+SET[[:space:]]+email|INSERT[[:space:]]+INTO[[:space:]]+aliases[[:space:]]*\([^)]*email' \
        --include='*.go' \
        $SEARCH_ROOTS 2>/dev/null \
      | grep -v '_test.go' \
      || true)"

uncanon=""
for f in $addr_write_files; do
  if ! grep -qE 'identity\.(CanonicalizeAddress|ValidateAndCanonicalizeEmail)\(' "$f"; then
    uncanon="$uncanon$f
"
  fi
done

if [ -n "$uncanon" ]; then
  echo ""
  echo "  identity-writer REGRESSION — a hand-rolled users.email / aliases.email"
  echo "  write (raw 'UPDATE users SET email' or 'INSERT INTO aliases (... email ...)')"
  echo "  lives in a file that NEVER calls a canonical-fold minter (identity."
  echo "  CanonicalizeAddress or the stronger identity.ValidateAndCanonicalizeEmail)."
  echo "  These raw writes can't reach the CanonicalAddress newtype, so the"
  echo "  canonical-fold is a file-level obligation here: the bound address MUST be"
  echo "  minted through one of those folds or a non-canonical row (mixed-case /"
  echo "  whitespace) lands and the identity matcher silently match-misses it."
  echo ""
  printf '%s' "$uncanon" | sed 's/^/      /'
  echo ""
  echo "  → wrap the bound email in identity.CanonicalizeAddress(...).String(), or"
  echo "    (operator/admin input) mint it with identity.ValidateAndCanonicalizeEmail."
  exit 1
fi

echo "    identity-writer guard: clean — all address writes route through the typed seam."
