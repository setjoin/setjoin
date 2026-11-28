-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V082: signature new-vs-reply default discriminator (A1 — compose parity).
--
-- user_signatures already carries a single boolean `is_default`. Outlook parity
-- needs separate "default signature for NEW mail" and "default for REPLY/forward"
-- choices. `default_for` ∈ {new, reply, both, none} captures both roles in one
-- column; set_signature_default() (reducers/set_signature_default.sql) is the
-- atomic flip that guarantees at most one signature holds each role per user.
BEGIN;

ALTER TABLE user_signatures
  ADD COLUMN IF NOT EXISTS default_for TEXT NOT NULL DEFAULT 'none'
    CHECK (default_for IN ('new', 'reply', 'both', 'none'));

COMMIT;
