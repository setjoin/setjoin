-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V011: MRM policy templates — pre-built retention templates for common compliance needs.
-- These are standard policy templates that admins can clone with one click.
-- The existing Default Global Policy (30-day delete, V004) stays as the active default.
INSERT INTO retention_policies (name, description, retain_days, action, is_default, domain_id)
VALUES
  ('Default 2-Year', 'Standard retention policy — keep messages for 2 years then delete.', 730, 'delete', FALSE, NULL),
  ('Finance 7-Year', 'Finance compliance retention — 7 years per SEC/IRS recordkeeping requirements.', 2555, 'delete', FALSE, NULL),
  ('HR 1-Year', 'HR personnel records retention — 1 year per standard employment guidelines.', 365, 'delete', FALSE, NULL),
  ('Auto-Purge 90-Day', 'Short retention — auto-delete messages after 90 days. For transient or notification-only mailboxes.', 90, 'delete', FALSE, NULL)
ON CONFLICT (name) DO NOTHING;
