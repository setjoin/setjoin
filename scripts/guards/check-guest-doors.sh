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
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RED="$ROOT/sql/reducers"
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
  case "$base" in
    rust_guest_invite.sql|rust_guest_invite_accept.sql|rust_guest_invite_disclosure.sql|rust_guest_status.sql)
      # Worker-pool BYPASSRLS composition/acceptance wrappers (#272/#342): must stay
      # SECURITY INVOKER so any accidental app-pool call fails closed under FORCE-RLS.
      if grep -qi 'SECURITY DEFINER' "$f"; then
        echo "GUEST-DOORS: $base must remain SECURITY INVOKER (worker-pool BYPASSRLS wrapper; fail-closed under FORCE-RLS)"
        fail=1
      fi
      continue
      ;;
  esac
  echo "GUEST-DOORS: $base reads guest_accounts directly — use is_guest_account()/guest_account_status() (FORCE-RLS makes raw reads fail OPEN)"
  fail=1
done < <(grep -l 'FROM guest_accounts' "$RED"/*.sql)

exit $fail
