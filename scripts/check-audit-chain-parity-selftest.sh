#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-audit-chain-parity-selftest.sh — proves check-audit-chain-parity.sh
# actually FIRES. Builds synthetic chat/drive clone files and asserts:
#   (A) the REAL repo files (chat_access_audit.sql / drive_access_audit.sql)
#       pass today — a baseline sanity check, not a fixture.
#   (B) a faithful clone (only the five documented substitutions +  the bare
#       domain word differ) PASSES.
#   (C) a clone with a genuine LOGIC divergence (an extra guard clause on
#       one side only) FAILS, and the guard's diff output names the drifted
#       line.
#   (D) a clone whose PROSE COMMENTS differ (but logic is identical) still
#       PASSES — comments must not cause a false failure.
#   (E) a missing function (renamed/deleted) FAILS and says so.
# Runs FIRST via run-guards.sh so a broken guard is caught before we trust
# it.
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

GUARD="$(dirname "$0")/check-audit-chain-parity.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
ok()  { echo "  ok: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

run_guard() { # <chat-file> <drive-file>
  AUDIT_PARITY_CHAT_FILE="$1" AUDIT_PARITY_DRIVE_FILE="$2" bash "$GUARD" 2>&1
}

# ── (A) the real repo files pass today ──────────────────────────────────────
rc=0; out="$(bash "$GUARD" 2>&1)" || rc=$?
if [ "$rc" -eq 0 ]; then ok "(A) the real chat_access_audit.sql / drive_access_audit.sql pass"; else bad "(A) the REAL repo files fail the guard right now:"$'\n'"$out"; fi

# ── Synthetic faithful-clone fixture (B) ────────────────────────────────────
cat > "$WORK/drive_ok.sql" <<'SQL'
-- prose comment A, drive-specific, never matches chat's prose
CREATE OR REPLACE FUNCTION drive_access_audit(
  p_user_id  BIGINT,
  p_space_id BIGINT,
  p_action   TEXT
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF p_action NOT IN (SELECT jsonb_array_elements_text(drive_audit_actions())) THEN
    RAISE EXCEPTION 'unknown drive audit action %', p_action
      USING ERRCODE='BZ141';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('drive_audit_' || p_space_id::text));
  SELECT COALESCE(MAX(id), 0) + 1 INTO v_id FROM drive_audit_log WHERE space_id = p_space_id;
  RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION verify_drive_audit_chain(
  p_space_id BIGINT
) RETURNS BOOLEAN AS $$
BEGIN
  RETURN EXISTS (SELECT 1 FROM drive_audit_log WHERE space_id = p_space_id);
END;
$$ LANGUAGE plpgsql;
SQL

cat > "$WORK/chat_ok.sql" <<'SQL'
-- totally different prose about channels, task numbers, whatever
CREATE OR REPLACE FUNCTION chat_access_audit(
  p_user_id    BIGINT,
  p_channel_id BIGINT,
  p_action     TEXT
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF p_action NOT IN (SELECT jsonb_array_elements_text(chat_audit_actions())) THEN
    RAISE EXCEPTION 'unknown chat audit action %', p_action
      USING ERRCODE='BZ191';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('chat_audit_' || p_channel_id::text));
  SELECT COALESCE(MAX(id), 0) + 1 INTO v_id FROM chat_audit_log WHERE channel_id = p_channel_id;
  RETURN v_id;
END;
$$;

CREATE OR REPLACE FUNCTION verify_chat_audit_chain(
  p_channel_id BIGINT
) RETURNS BOOLEAN AS $$
BEGIN
  RETURN EXISTS (SELECT 1 FROM chat_audit_log WHERE channel_id = p_channel_id);
END;
$$ LANGUAGE plpgsql;
SQL

rc=0; out="$(run_guard "$WORK/chat_ok.sql" "$WORK/drive_ok.sql")" || rc=$?
if [ "$rc" -eq 0 ]; then ok "(B) a faithful clone (5 tokens + domain word only) passes"; else bad "(B) a faithful clone FAILED (false-positive!):"$'\n'"$out"; fi

# ── (D) prose-only divergence: reuse the SAME faithful bodies but rewrite
# every comment line — logic untouched, must still pass. ───────────────────
sed 's/^-- .*/-- REWRITTEN PROSE, nothing like the other file at all/' "$WORK/chat_ok.sql" > "$WORK/chat_prose.sql"
rc=0; out="$(run_guard "$WORK/chat_prose.sql" "$WORK/drive_ok.sql")" || rc=$?
if [ "$rc" -eq 0 ]; then ok "(D) prose-comment-only divergence still passes (comments are stripped, not compared)"; else bad "(D) prose-only divergence wrongly FAILED the guard:"$'\n'"$out"; fi

# ── (C) a genuine logic divergence: chat's writer gains an extra guard
# clause the drive side never had. ──────────────────────────────────────────
sed '/RAISE EXCEPTION .unknown chat audit action/i\
  IF p_user_id IS NULL THEN RAISE EXCEPTION '"'"'no actor'"'"'; END IF;' \
  "$WORK/chat_ok.sql" > "$WORK/chat_drift.sql"
rc=0; out="$(run_guard "$WORK/chat_drift.sql" "$WORK/drive_ok.sql")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "(C) a genuine logic divergence is caught (guard fires)"; else bad "(C) logic divergence NOT caught (false-negative!):"$'\n'"$out"; fi
if printf '%s' "$out" | grep -qi 'DIVERGED'; then ok "(C) names the divergence"; else bad "(C) did not name the divergence"; fi
if printf '%s' "$out" | grep -q 'no actor'; then ok "(C) the diff surfaces the drifted line"; else bad "(C) the diff did not surface the drifted line"; fi

# ── (E) a renamed/missing function is caught. ───────────────────────────────
sed 's/verify_drive_audit_chain/verify_drive_audit_chain_renamed/' "$WORK/drive_ok.sql" > "$WORK/drive_renamed.sql"
rc=0; out="$(run_guard "$WORK/chat_ok.sql" "$WORK/drive_renamed.sql")" || rc=$?
if [ "$rc" -ne 0 ]; then ok "(E) a renamed verifier function is caught"; else bad "(E) renamed function NOT caught (false-negative!)"; fi
if printf '%s' "$out" | grep -qi 'could not find'; then ok "(E) names the missing function"; else bad "(E) did not name the missing function"; fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "check-audit-chain-parity selftest FAILED ($fail/$((pass+fail)) checks failed) — the guard does not behave as specified."
  exit 1
fi
echo "check-audit-chain-parity selftest: all $pass checks passed (guard fires + is precise)."
