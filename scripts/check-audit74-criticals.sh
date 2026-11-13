#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-audit74-criticals.sh — PERMANENT regression guard for the 10 Critical
# findings from the 2026-06-28 exhaustive audit (wlfnhc08z, 84 findings: 10
# Critical + 74 Important). Queue B item 7
# (retired-docs:superpowers/plans/archive/2026-07-04-queue-b-combined.md §7).
#
# WHY THIS EXISTS. The audit's own JSON manifest
# (.superpowers/sdd/exhaustive-audit-report.json) was git-ignored scratch and
# is permanently gone — see docs/audit/2026-07-04-audit74-manifest-loss.md.
# The 10 Criticals are the one part of that lost report with enough
# surviving specificity (exact file:line + fix description, TODOS.md:358-367)
# to protect mechanically. Nothing currently re-checks that these 10 fixes
# are still in place; a future refactor of any one of these 10 files could
# silently reintroduce the vulnerable pattern with no test catching it (none
# of the 10 had a dedicated regression test named in the audit aftermath —
# several are covered incidentally by unit/handler tests, but none of those
# tests exist BECAUSE of this audit, so nothing asserts "the Critical stays
# fixed" specifically).
#
# WHAT IT DOES. Greps each of the 10 fixed files for a short, literal
# substring that is only present in the FIXED code (not the vulnerable
# code it replaced). Any one of the 10 substrings missing means either the
# fix regressed or the file was rewritten without preserving the fix —
# either way, a human needs to look before this merges. This is a floor,
# not a proof of correctness: a determined rewrite could keep the exact
# substring while reintroducing the bug elsewhere in the same function.
# That is an accepted, explicit limitation of grep-based regression guards
# (same tradeoff as check-rls-coverage.sh, check-sql-injection.sh, etc.).
#
# THE 10 CRITICALS (id — file — fix signature grepped):
#   C1  acme/dns01.go            — cache stores PrivateKey+Certificate, not chain-only
#   C2  blob/handler.go          — Put() hash-verifies BEFORE CopyObject promotes the blob
#   C3  carddav/carddav.go       — scanContact includes InstantMsgs (21-col SELECT/Scan parity)
#   C4a imap/imap.go             — handleAuthenticate guards empty AUTH mechanism args
#   C4b imap/imap.go             — handleConn recovers from a panic (no per-conn crash)
#   C5  ldap/search.go           — Contacts OU search scoped to is_shared = TRUE
#   C6  scim/user.go             — source-scoped COUNT joins users as `u`,
#                                  requires active provision links
#   C7  storage/posix_worm_linux.go — uses the real unix.FS_IOC_{GET,SET}FLAGS constants
#   C8  webdav + caldav          — shared resolver classifies absent/typed-nil
#                                  properties as 404 and CalDAV consumes it
#   C9  authserver webauthn.go   — persistCredential's ON CONFLICT scoped to user_id
#   C10a authserver push.go      — /auth/push/verify refuses the in-band answer
#   C10b authserver device.go    — device-channel completion verifies the enrolled
#                                  device signature over canonical challenge bytes
#
# Self-test: check-audit74-criticals-selftest.sh builds a synthetic scratch
# tree carrying a representative subset of these fix signatures, proves the
# guard FAILS (and names the finding) when one is missing/reverted, and
# PASSES when all are present — then separately confirms the guard is
# currently green against the REAL tree (no AUDIT_ROOT override).
#
# guard scope: grep-only, no DB / no build required.
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

AUDIT_ROOT="${AUDIT_ROOT:-$ROOT}"

# Parallel arrays (bash 3.2-compatible — no associative arrays): id | file
# (relative to AUDIT_ROOT) | literal fix-signature substring | one-line desc.
IDS=(C1 C2 C3 C4a C4b C5 C6a C6b C6c C6d C7 C8a C8b C9 C10a C10b)

FILES=(
  "mailserver/internal/acme/dns01.go"
  "mailserver/internal/blob/handler.go"
  "mailserver/internal/carddav/carddav.go"
  "mailserver/internal/imap/imap.go"
  "mailserver/internal/imap/imap.go"
  "mailserver/internal/ldap/search.go"
  "mailserver/internal/scim/user.go"
  "mailserver/internal/scim/user.go"
  "mailserver/internal/scim/user.go"
  "mailserver/internal/scim/user.go"
  "mailserver/internal/storage/posix_worm_linux.go"
  "mailserver/internal/webdav/webdav.go"
  "mailserver/internal/caldav/webdav.go"
  "authserver/internal/authn/webauthn.go"
  "authserver/internal/handlers/push.go"
  "authserver/internal/handlers/device.go"
)

# NOTE: bash arrays can't hold embedded newlines cleanly across all shells we
# might run under — keep every pattern a single line, exact substring match
# (grep -F), matching the exact source text at the time this guard was written.
PATTERNS=(
  'blob := append(res.PrivateKey, res.Certificate...)'
  'sha256 mismatch'
  '&c.InstantMsgs, &c.Notes'
  'if len(f) == 0 {'
  'panic in handleConn (recovered)'
  'is_shared = TRUE'
  'JOIN users u ON u.id=l.user_id'
  'l.source_id=$%d AND l.state='\''active'\'''
  "'provision'=ANY(l.purposes)"
  'AND NOT is_guest_account(u.id)'
  'unix.FS_IOC_GETFLAGS'
  'if !ok || isNilPropertyValue(value) {'
  'resolution := webdav.ResolveProperties('
  'WHERE passkey_credentials.user_id = EXCLUDED.user_id'
  'in-band push answer is not accepted'
  'VerifyPushApproval(publicKey, canonical, req.Signature)'
)

DESCS=(
  "C1: cert cache must survive restart (key+cert, not chain-only) — else fresh ACME issuance every restart risks an LE rate-limit outage"
  "C2: blob Put() must hash-verify before promoting into the content-addressed key — else any authed user can destroy another tenant's blob by SHA"
  "C3: contact scan must include instant_msgs — else every CardDAV read fails (col-count mismatch)"
  "C4a: AUTHENTICATE must reject an empty mechanism list — else an unauth client panics the connection"
  "C4b: handleConn must recover() — else one malformed connection crashes the whole process"
  "C5: LDAP Contacts OU must scope to is_shared — else any authed bind reads every user's private contacts"
  "C6a: SCIM COUNT query must join source links to users — otherwise filter aliases fail or ownership cannot be enforced"
  "C6b: SCIM COUNT query must bind the authenticated source and require an active link — otherwise cross-source or detached users leak"
  "C6c: SCIM COUNT query must require the provision purpose — otherwise authentication-only identities leak into provisioning"
  "C6d: SCIM COUNT query must exclude guests — otherwise the guest account class leaks into the identity plane"
  "C7: WORM ioctl must use the real FS_IOC_GETFLAGS/SETFLAGS constants — else WORM silently fails to protect blobs"
  "C8a: shared WebDAV resolution must classify absent and typed-nil properties as missing — never blind-assert a value"
  "C8b: CalDAV must consume the shared property resolver — otherwise the historical absent-property panic can return"
  "C9: WebAuthn credential upsert must be scoped to user_id — else a crafted credential id takes over another user's passkey"
  "C10a: push MFA verify must refuse in-band answers — else a password-only attacker bypasses 2FA"
  "C10b: push MFA device-channel completion must verify the enrolled device signature — number match alone is not identity proof"
)

echo "==> audit74 Criticals regression guard (10 findings, 15 fix signatures)"

fail=0
n=${#IDS[@]}
for ((i = 0; i < n; i++)); do
  id="${IDS[$i]}"
  file="$AUDIT_ROOT/${FILES[$i]}"
  pattern="${PATTERNS[$i]}"
  desc="${DESCS[$i]}"

  if [ ! -f "$file" ]; then
    echo "  REGRESSION: $id — file missing entirely: ${FILES[$i]}"
    echo "    ($desc)"
    fail=1
    continue
  fi

  if grep -qF -- "$pattern" "$file"; then
    echo "  ok: $id"
  else
    echo "  REGRESSION: $id — fix signature not found in ${FILES[$i]}:"
    echo "    expected substring: $pattern"
    echo "    ($desc)"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "check-audit74-criticals FAILED — one or more Critical fix signatures"
  echo "from the 2026-06-28 exhaustive audit appears to have regressed."
  exit 1
fi
echo "  all Critical fix signatures present."
