-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V081: per-user read-receipt (MDN) privacy policy (Track A)
--
-- The RECIPIENT chooses whether a read receipt (MDN) is ever sent, for privacy.
-- read_receipt_policy ∈ {ask, always, never}, default 'ask':
--   never  → send_read_receipt() sends NO MDN (even if a client passes consent).
--   ask    → not auto-sent; needs explicit recipient consent (the webmail prompts).
--   always → sent.
-- The hard gate lives in send_read_receipt() (reducers/send.sql) — "logic where the
-- data is" — so a buggy or hostile client cannot leak a receipt the user disallowed.
BEGIN;

ALTER TABLE user_notification_prefs
  ADD COLUMN IF NOT EXISTS read_receipt_policy TEXT NOT NULL DEFAULT 'ask'
    CHECK (read_receipt_policy IN ('ask','always','never'));

-- Effective policy for a user: the global (device_fingerprint IS NULL) row, default 'ask'.
CREATE OR REPLACE FUNCTION get_read_receipt_policy(p_user_id BIGINT)
RETURNS TEXT AS $$
  SELECT COALESCE(
    (SELECT read_receipt_policy FROM user_notification_prefs
      WHERE user_id = p_user_id AND device_fingerprint IS NULL
      LIMIT 1),
    'ask');
$$ LANGUAGE sql STABLE;

COMMIT;
