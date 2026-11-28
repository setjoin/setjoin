-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V084 — Calendar ACL free/busy permission level + delegate manage_calendar.
-- A3 (calendar Outlook parity). Adds a 'freebusy' permission to calendar_acls so a
-- shared calendar can be granted as time-blocks-only (title/location/description
-- redacted) — the Outlook "Free/Busy only" sharing level — and a 'manage_calendar'
-- permission to mailbox_delegates so a delegate can respond to meeting requests on a
-- manager's behalf without holding full_access.
--
-- Both CHECK constraints are recreated (rather than left as-is) so the new enum
-- values are accepted in the write path. Idempotent: drops the old constraint by name
-- if present, then re-adds with the widened value set.

-- calendar_acls.permission: add 'freebusy'.
ALTER TABLE calendar_acls DROP CONSTRAINT IF EXISTS calendar_acls_permission_check;
ALTER TABLE calendar_acls
  ADD CONSTRAINT calendar_acls_permission_check
  CHECK (permission IN ('freebusy', 'read', 'write', 'admin'));

-- mailbox_delegates.permission: add 'manage_calendar' if the constraint does not
-- already include it. The mailbox_delegates table + its permission CHECK live in an
-- earlier migration; recreate the CHECK to include the new value. The full value set
-- is preserved (send_as / send_on_behalf / full_access) plus the new manage_calendar.
ALTER TABLE mailbox_delegates DROP CONSTRAINT IF EXISTS mailbox_delegates_permission_check;
ALTER TABLE mailbox_delegates
  ADD CONSTRAINT mailbox_delegates_permission_check
  CHECK (permission IN ('read', 'send_as', 'send_on_behalf', 'full_access', 'manage_calendar'));
