#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-guest-doors.sh — Guest Accounts P2 door guard (property-keyed, NOT a
# hand-maintained name list): the property is "a reducer that GRANTS
# membership/reach (INSERT INTO chat_channel_members / meeting_participants /
# meeting_join_requests / drive_space_members — the last is C-3: an explicit
# Drive grant row IS reach through the allowlisted generic reader routes)
# must declare a guest disposition" — either an
# is_guest_account( arm in the same file, or a justified entry below.
# A new org-open surface that declares no guest posture fails here at birth
# (the coverage-claims-need-a-machine-guard lesson applied from day one).
#
# Also asserts:
#  (2) the P11b allowlist SINGLE SOURCE: guestgate/allowlist.go carries the
#      marker pair and middleware.go contains no route-pattern literals of
#      its own (the middleware and this guard read ONE list);
#  (3) the belt seams hold: chain.go's AuthenticateRequest AND
#      AuthenticatePushToken call applyGuestBelt; bcrypt.go's CheckPassword
#      calls is_guest_account;
#  (4) no RLS-blind raw guest_accounts read: outside the named worker-owned
#      guest-account/profile authorities and provisioning/invite writers, SQL
#      reducers must use is_guest_account()/guest_account_status(), never
#      "FROM guest_accounts";
#  (5) the E-B1 dispatch wrap: main.go serves apiMux ONLY through the
#      guestgate (buildRootDispatch) — /api mount AND bare-root pinned branch.
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RED="$ROOT/mailserver/sql/reducers"
fail=0

# Justified membership-granting reducers WITHOUT an is_guest_account( arm.
# Every entry carries its reason — delete an entry when the file gains an arm.
justified() {
  case "$1" in
    chat_org_defaults.sql) return 0 ;;  # backfill SELECT excludes guests via NOT is_guest_account (guard §1 sees the call) — listed for the autojoin RETURN arm's readability
    meeting_lobby.sql)     return 0 ;;  # meeting_admit inserts model-③ LOBBY guests (p_user_id NULL rows); the AUTHED knock carries the BZ215 arm
    federation_apply_room.sql) return 0 ;;  # spoke mirror bootstrap: inserts no LOCAL memberships for guests (guests can't join mirrors — chat_member_add arm 1 covers the only local path)
    federation_apply_chat.sql) return 0 ;;  # inbound federated-DM local-owner row (:276-278): the target resolves through a mailboxes JOIN (:235) and guests are mailbox-less BY ENFORCEMENT (the V143 mailboxes_guest_guard trigger, C-2 — not just construction) — a guest can never be the inbound target
    drive_share_approval_decide.sql) return 0 ;;  # applies an APPROVED share: the request choke (drive_member_grant) refuses guest grantees BEFORE approval routing (C-3), and BZ221 forbids member->guest conversion while a request pends — a guest grantee cannot reach decide time
    *) return 1 ;;
  esac
}

# §1 membership-granting reducers must carry a guest disposition.
# guest_require_grantable counts as a disposition too (C-5: the guest-target
# grant writers declare theirs through the FOR SHARE serialization helper).
while IFS= read -r f; do
  base="$(basename "$f")"
  if grep -qE 'is_guest_account\(|guest_require_grantable\(' "$f"; then continue; fi
  if justified "$base"; then continue; fi
  echo "GUEST-DOORS: $base grants membership/reach but declares no guest disposition (add an is_guest_account/guest_require_grantable arm or a justified entry)"
  fail=1
done < <(grep -lE 'INSERT INTO (chat_channel_members|meeting_participants|meeting_join_requests|drive_space_members)' "$RED"/*.sql)

# §2 allowlist single source.
AL="$ROOT/mailserver/internal/guestgate/allowlist.go"
grep -q '// guest-allowlist-begin' "$AL" && grep -q '// guest-allowlist-end' "$AL" \
  || { echo "GUEST-DOORS: allowlist markers missing in guestgate/allowlist.go"; fail=1; }
if grep -E '"(GET|POST|PUT|HEAD|DELETE)"|"/[a-z]' "$ROOT/mailserver/internal/guestgate/middleware.go" >/dev/null; then
  echo "GUEST-DOORS: middleware.go carries route literals — the allowlist in allowlist.go is the SINGLE source"
  fail=1
fi
# G3 Meet is deliberately route-enumerated. A blanket prefix would silently
# guest-open every future Meet route, defeating P11b's deny-new-surfaces rule.
if grep -Eq '\{"",[[:space:]]*"prefix",[[:space:]]*"/meet/' "$AL"; then
  echo "GUEST-DOORS: Meet uses a blanket guest prefix — enumerate each current method/path shape"
  fail=1
fi
grep -Fq '{"GET", "regex", `^/public/meet/[^/]+/join-request/[0-9]+$`' "$AL" \
  || { echo "GUEST-DOORS: authenticated-knock public GET poll is missing from the guest allowlist"; fail=1; }
grep -Fq '{"GET", "exact", "/rtc"' "$AL" && grep -Fq '{"GET", "prefix", "/rtc/"' "$AL" \
  || { echo "GUEST-DOORS: guest LiveKit signal path must allow exact /rtc plus /rtc/ without opening /rtcx"; fail=1; }

# §3 belt seams.
CHAIN="$ROOT/mailserver/internal/auth/chain.go"
awk '/func \(c \*Chain\) AuthenticateRequest/,/^}/' "$CHAIN" | grep -q 'applyGuestBelt' \
  || { echo "GUEST-DOORS: AuthenticateRequest lost the guest belt"; fail=1; }
awk '/func \(c \*Chain\) AuthenticatePushToken/,/^}/' "$CHAIN" | grep -q 'applyGuestBelt' \
  || { echo "GUEST-DOORS: AuthenticatePushToken lost the guest belt"; fail=1; }
grep -q 'is_guest_account' "$ROOT/mailserver/internal/auth/bcrypt.go" \
  || { echo "GUEST-DOORS: CheckPassword lost the protocol-surface guest refusal"; fail=1; }

# §4 no RLS-blind raw satellite reads in reducers.
while IFS= read -r f; do
  base="$(basename "$f")"
  [ "$base" = "guest_account.sql" ] && continue
  if [ "$base" = "guest_profile.sql" ]; then
    creates="$(grep -c '^CREATE OR REPLACE FUNCTION ' "$f" || true)"
    definers="$(grep -cE '^LANGUAGE .*SECURITY DEFINER ' "$f" || true)"
    owners="$(grep -c '^SELECT apply_worker_ownership(' "$f" || true)"
    if [ "$creates" -eq 0 ] || [ "$definers" -ne "$creates" ] || [ "$owners" -ne "$creates" ]; then
      echo "GUEST-DOORS: guest_profile.sql exception lost worker authority — every function must be SECURITY DEFINER + apply_worker_ownership"
      fail=1
    fi
    continue
  fi
  [ "$base" = "provision_account.sql" ] && continue  # the writer choke owns its own table access
  [ "$base" = "guest_invite.sql" ] && continue  # worker-owned mint validates the satellite host+email atomically; no app-executable cross-user helper
  echo "GUEST-DOORS: $base reads guest_accounts directly — use is_guest_account()/guest_account_status() (FORCE-RLS makes raw reads fail OPEN)"
  fail=1
done < <(grep -l 'FROM guest_accounts' "$RED"/*.sql)

# §5 the dispatch wrap (E-B1): every route on apiMux — /api-mounted OR pinned
# bare-root (/jmap, /auth, /.well-known, …) — must be SERVED through the guest
# gate. Structural assertions on main.go's buildRootDispatch; if these hold,
# every prefix in scripts/api-pinned-prefixes.txt is gate-wrapped by
# construction (all registrations land on apiMux before the swap).
# Pinned surfaces that never carry our JWT are contained elsewhere — the
# VERIFIED stories: /caldav /carddav → auth.CheckPassword guest refusal
# (dav/basic.go funnels through it, §3 above guards the choke); /scim → its
# own bearer (INTERNAL_API_KEY), never our JWT; /rtc → reducer-scoped,
# signed LiveKit-token WS (G3 guests legitimately obtain one); /setup /approvals/email
# /link-protect /updates /downloads /health /ready /metrics /favicon.ico
# /terms → unauthenticated/HMAC/ops surfaces (the gate only narrows valid
# guest-JWT requests; everything else passes through untouched).
# Round-3 codex additions to the story table: the allowlisted generic Drive
# reader routes are contained by the C-3 grant-door arms + live
# chat-derivation (drive_member_role arm 2) — machine-checked by §1's
# drive_space_members pattern; G3's /meet allowlist enumerates current route
# shapes while reducers contain reads/joins/authority (future routes deny);
# the legacy non-GET 308 alias is served through the SAME gate (C-7 — no
# route-existence oracle; asserted by guest_dispatch_test.go's case table,
# not grep-able here).
#
# Per-pinned-prefix containment story (every prefix in
# scripts/api-pinned-prefixes.txt, kept in sync by hand — that file's own
# sync with main.go's apiPinnedPrefixes is check-api-namespace.sh's job, not
# this guard's):
#   /auth                   gated; authserver proxy — SAML/OIDC/WebAuthn
#                           callbacks are IdP-registered, not our JWT
#   /jmap                   gated (JWT-borne; §2 allowlist narrows it for guests)
#   /.well-known            gated, but unauthenticated (no JWT ⇒ gate no-op)
#   /caldav /carddav        Basic-auth only; guest refusal at auth.CheckPassword (§3)
#   /scim                   own INTERNAL_API_KEY bearer, never our JWT
#   /setup                  unauthenticated pre-auth bootstrap (installer/DR/first-boot)
#   /approvals/email        HMAC link token embedded in ALREADY-SENT mail, not a JWT
#   /link-protect           HMAC click-through token in delivered mail bodies, not a JWT
#   /admin/migration/m365   Azure-registered OAuth redirect + its own path-scoped
#                           CSRF cookie, not our JWT
#   /updates /downloads     unauthenticated appcast/HTML-page surfaces
#   /health /ready /metrics unauthenticated ops probes/scrape
#   /api                    the namespace itself — gated identically to everything under it
#   /favicon.ico            unauthenticated browser asset
#   /terms                  unauthenticated authserver-proxied static document
#   /rtc                    signed LiveKit-token WS; G3 route-enumerated and
#                           token grant reducer-scoped (the SFU is peripheral)
#   legacy non-GET 308 alias served through the SAME gate, no route-existence
#                           oracle (C-7; asserted by guest_dispatch_test.go's case
#                           table, not grep-able here)
MAIN="$ROOT/mailserver/cmd/mailserverd/main.go"
grep -q 'guestgate\.Middleware' "$MAIN" \
  || { echo "GUEST-DOORS: main.go lost the guestgate wrap (buildRootDispatch)"; fail=1; }
if grep -q 'apiMux\.ServeHTTP' "$MAIN"; then
  echo "GUEST-DOORS: main.go serves apiMux directly — every serving path must route through gatedAPI (E-B1: a bare apiMux.ServeHTTP lets the pinned bare-root branch bypass the allowlist, e.g. POST /jmap)"
  fail=1
fi
grep -q 'StripPrefix("/api", gatedAPI)' "$MAIN" \
  || { echo "GUEST-DOORS: the /api mount is not built from gatedAPI"; fail=1; }

exit $fail
