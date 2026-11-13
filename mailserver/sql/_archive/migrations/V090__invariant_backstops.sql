-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V090: invariant DB backstops (Wave 8) — push reducer-only invariants to the
-- data ONLY where verification proves a CHECK/trigger never fires on a legitimate
-- state. See docs/superpowers/plans/archive/2026-06-18-reducer-invariant-db-backstops.md
-- and CONTEXT.md → "State invariant vs transition invariant".
--
-- Deliberately ASYMMETRIC, by design:
--   • The quota CEILINGS (used_bytes <= quota_bytes, sending_sent_today <=
--     sending_quota_day) get NO CHECK — they are TRANSITION invariants. An admin
--     legitimately lowers a quota below current usage (internal/admin/
--     admin_mailboxes.go) and reconciliation overwrites used_bytes with the live
--     SUM (reducers/startup_recovery.sql); a ceiling CHECK would reject those
--     legitimate over-states and turn a routine admin action into an outage.
--   • The FLOORS (used_bytes >= 0, sending_sent_today >= 0) are STATE invariants —
--     true of one row in isolation, never legitimately crossed (the reducer code
--     already clamps decrements via GREATEST(0,…)). They take the CHECK: free,
--     un-bypassable, and they catch a real bug class (a buggy decrement underflow
--     on a future direct-SQL path).
--   • The read-receipt 'never' guard is a STATE-derivable privacy invariant (the
--     recipient's policy is consent-independent for 'never'), so a narrow BEFORE
--     INSERT trigger backstops the strongest privacy promise even against a direct
--     INSERT that skips send_read_receipt().
--
-- Idempotent: drop-by-name-then-add for the CHECKs (catalog-guarded), CREATE OR
-- REPLACE + drop-and-create for the trigger/function.
BEGIN;

-- ── 1. Non-negative FLOOR CHECKs on mailboxes (state invariants) ──────────────
-- The columns already exist (schema/004_mailboxes.sql) and are NOT NULL, so the
-- CHECK is NOT NULL-safe. We drop any prior copy by name (idempotent replay) and
-- re-add. There is intentionally NO ceiling CHECK here (see header).
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'mailboxes_used_bytes_nonneg') THEN
    ALTER TABLE mailboxes DROP CONSTRAINT mailboxes_used_bytes_nonneg;
  END IF;
  ALTER TABLE mailboxes ADD CONSTRAINT mailboxes_used_bytes_nonneg CHECK (used_bytes >= 0);

  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'mailboxes_sending_sent_today_nonneg') THEN
    ALTER TABLE mailboxes DROP CONSTRAINT mailboxes_sending_sent_today_nonneg;
  END IF;
  ALTER TABLE mailboxes ADD CONSTRAINT mailboxes_sending_sent_today_nonneg CHECK (sending_sent_today >= 0);
END;
$$;

-- ── 2. Read-receipt 'never' guard trigger on read_receipts ───────────────────
-- A direct INSERT INTO read_receipts bypasses send_read_receipt()'s privacy gate.
-- This BEFORE INSERT trigger re-derives the recipient's policy via the MAILBOX
-- chain (NEW.message_id → messages.mailbox_id → account_scope(mailbox_id).user_id
-- → get_read_receipt_policy(user_id)) — mailbox-keyed and alias-proof by
-- construction (NOT keyed on recipient_email / any address / resolve_identity).
--
-- It RAISES (BZ073) ONLY when policy = 'never' — the one value decidable from the
-- row alone (consent-independent). It does NOT try to enforce 'ask': the
-- read_receipts row has NO consent column, so 'ask'+consent (allowed) is
-- indistinguishable from 'ask'+no-consent (forbidden) at row level — blocking
-- 'ask' would over-block legitimate inserts.
--
-- FAIL-OPEN: if the message / mailbox / user can't be resolved (missing
-- message_id, shared/resource mailbox with NULL user_id, etc.) the policy resolves
-- to a non-'never' value and the insert is ALLOWED. The reducer remains the
-- primary gate; this trigger is a backstop for the direct-INSERT path only.
--
-- send_read_receipt() only ever inserts for policy ∈ {always, ask+consent}
-- (it returns early on 'never'), so the trigger always passes its legitimate
-- inserts and the reducer flow is unchanged.
CREATE OR REPLACE FUNCTION trg_read_receipt_never_guard() RETURNS TRIGGER AS $$
DECLARE
  v_mailbox_id BIGINT;
  v_user_id    BIGINT;
  v_policy     TEXT;
BEGIN
  -- message → mailbox (the row carries message_id only; no mailbox_id column).
  SELECT m.mailbox_id INTO v_mailbox_id FROM messages m WHERE m.id = NEW.message_id;
  IF v_mailbox_id IS NULL THEN
    RETURN NEW;  -- unresolvable message → fail-open (reducer is the primary gate).
  END IF;

  -- mailbox → owning user via the account_scope() seam (ADR-003). NULL for a
  -- shared/resource mailbox → no policy row → get_read_receipt_policy falls back
  -- to 'ask' (≠ 'never'), so the insert is allowed (fail-open).
  SELECT s.user_id INTO v_user_id FROM account_scope(v_mailbox_id) s;

  v_policy := get_read_receipt_policy(v_user_id);
  IF v_policy = 'never' THEN
    RAISE EXCEPTION 'Read receipt forbidden by recipient policy (never)'
      USING ERRCODE = 'BZ073',
            HINT = jsonb_build_object(
              'type', 'read_receipt_never',
              'message_id', NEW.message_id,
              'mailbox_id', v_mailbox_id
            )::TEXT;
  END IF;

  RETURN NEW;  -- always / ask (and any unresolvable case) → allow.
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS read_receipt_never_guard ON read_receipts;
CREATE TRIGGER read_receipt_never_guard
  BEFORE INSERT ON read_receipts
  FOR EACH ROW EXECUTE FUNCTION trg_read_receipt_never_guard();

COMMIT;
