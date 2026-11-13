-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V083 — Track A2: triage parity (follow-up flag fields, Quick Steps macro store,
-- Archive view filter columns) + the LINK-PROTECT egress sanitization rail.
--
-- R4 is enforced in this repo by p_account_id/p_mailbox_id parameter propagation
-- in reducers (DATABASE_SECURITY.md), NOT by native PostgreSQL RLS. There are no
-- per-user policies to add here; ownership is filtered inside quick_step_* reducers.

-- ── Follow-up flag (Task 4) ────────────────────────────────────────────────
-- A2 stores the due/reminder instants; A6's scan_due_reminders() flag branch
-- (currently guarded behind a column-exists check) fires them via the `remind`
-- handler. A2 does not run a parallel timer.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS flag_due_at      TIMESTAMPTZ;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS flag_reminder_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS messages_flag_reminder_idx
  ON messages(flag_reminder_at) WHERE flag_reminder_at IS NOT NULL;

-- ── Quick Steps: user-defined one-click action macros ──────────────────────
CREATE TABLE IF NOT EXISTS quick_steps (
  id          BIGSERIAL   PRIMARY KEY,
  mailbox_id  BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  name        TEXT        NOT NULL,
  icon        TEXT        NOT NULL DEFAULT 'Zap',
  position    INT         NOT NULL DEFAULT 0,
  -- actions: array of {type, params} — a SUBSET of the rules.actions vocabulary
  -- (move_to / categorize / flag / mark_read / forward_to). The allowlist is
  -- enforced in quick_step_set() + quick_step_apply(); privileged rule actions
  -- (add_header / discard / delete) are rejected, not silently passed through.
  actions     JSONB       NOT NULL DEFAULT '[]',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT quick_steps_actions_check CHECK (jsonb_typeof(actions) = 'array')
);
CREATE INDEX IF NOT EXISTS quick_steps_mailbox_idx ON quick_steps(mailbox_id, position);

-- ── LINK-PROTECT egress sanitization rail (security correctness) ───────────
-- When a Quick Step / rule forwards an inbound message, its stored raw_ref body
-- already had external URLs rewritten to /link-protect?token=… redirects that
-- (a) resolve against the RECIPIENT's server (broken for the forward target) and
-- (b) leak the recipient mailbox_id + message_id encoded in the HMAC token. A
-- forwarded copy MUST carry the original URLs, not the recipient's protected
-- redirects. This flag marks an outbound row whose body the Go egress un-rewrites
-- (link-protect tokens → original URLs) before signing/transmission.
-- outbound_queue_hot is `LIKE outbound_queue INCLUDING DEFAULTS`, so it does NOT
-- inherit columns added after its creation — add the column to both tables.
ALTER TABLE outbound_queue     ADD COLUMN IF NOT EXISTS forward_unwrap_links BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE outbound_queue_hot ADD COLUMN IF NOT EXISTS forward_unwrap_links BOOLEAN NOT NULL DEFAULT FALSE;
