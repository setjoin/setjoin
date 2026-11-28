-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V086 (A5 — Out-of-Office parity): separate internal-vs-external auto-reply bodies.
--
-- Outlook's defining Automatic-Replies feature is a DISTINCT reply body for senders
-- outside the organization, plus a scope toggle for who outside the org gets a reply.
-- This adds three columns to vacation_settings:
--   body_external      — reply text for external senders (NULL = reuse the internal body)
--   body_external_html — HTML variant (NULL = fall back to body_external, then internal)
--   external_audience  — who outside the org is replied to: all | contacts | none
--
-- external_audience values (ENFORCED in deliver() — deliver_group_vacation.sql):
--   'all'      external senders get the external (or fallen-back internal) body — current behavior
--   'contacts' ONLY external senders in the mailbox owner's address book get a reply
--   'none'     external senders NEVER get an auto-reply (Outlook "reply only inside my org")
--
-- R4: vacation_settings is scoped by p_mailbox_id parameter propagation in set_vacation()
-- (this repo enforces R1–R4 by mailbox-id propagation, not native RLS — see
-- docs/standards/DATABASE_SECURITY.md and V083's note). No native RLS policy is added here,
-- consistent with the sibling vacation/contacts tables.
--
-- Idempotent: the same three columns also ship in schema/020_vacation.sql so a fresh load
-- (V001 \i 020_vacation.sql) already has them; ADD COLUMN IF NOT EXISTS makes the migration
-- a no-op in that path.

ALTER TABLE vacation_settings
  ADD COLUMN IF NOT EXISTS body_external      TEXT,
  ADD COLUMN IF NOT EXISTS body_external_html TEXT,
  ADD COLUMN IF NOT EXISTS external_audience  TEXT NOT NULL DEFAULT 'all';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'vacation_settings_external_audience_check'
  ) THEN
    ALTER TABLE vacation_settings
      ADD CONSTRAINT vacation_settings_external_audience_check
      CHECK (external_audience IN ('all', 'contacts', 'none'));
  END IF;
END$$;
