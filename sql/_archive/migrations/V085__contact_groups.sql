-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V085 — Track A4: personal contact groups (user-created distribution lists).
--
-- Adds contact_groups + contact_group_members: a mailbox-owned named recipient
-- list that expands to its members at compose time. Distinct from the admin/SCIM
-- distribution_groups (org-wide, satellite-table role): these are strictly
-- per-mailbox and JMAP-stateful (groups advance addressbooks-domain jmap_state
-- via the owning mailbox).
--
-- R4 is enforced in this repo by p_account_id / mailbox_id parameter propagation
-- in reducers (DATABASE_SECURITY.md), NOT by native PostgreSQL RLS. There are no
-- per-user policies to add here; every group/member SELECT/INSERT/UPDATE/DELETE is
-- ownership-filtered inside the jmap_contact_group_* / contact_group_members_set /
-- expand_contact_group reducers — consistent with the sibling contacts reducers.
--
-- Idempotent: tables use IF NOT EXISTS; the schema mirror in schema/011_contacts.sql
-- carries the same DDL for fresh loads (loaded by V001).

CREATE TABLE IF NOT EXISTS contact_groups (
  id          BIGSERIAL   PRIMARY KEY,
  mailbox_id  BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  name        TEXT        NOT NULL,
  jmap_state  BIGINT      NOT NULL DEFAULT 1,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS contact_groups_mailbox_idx ON contact_groups(mailbox_id);
CREATE UNIQUE INDEX IF NOT EXISTS contact_groups_name_idx ON contact_groups(mailbox_id, lower(name));

CREATE TABLE IF NOT EXISTS contact_group_members (
  id          BIGSERIAL   PRIMARY KEY,
  group_id    BIGINT      NOT NULL REFERENCES contact_groups(id) ON DELETE CASCADE,
  contact_id  BIGINT      REFERENCES contacts(id) ON DELETE CASCADE,
  email       TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT cgm_one_target CHECK (num_nonnulls(contact_id, email) = 1)
);
CREATE UNIQUE INDEX IF NOT EXISTS cgm_contact_uniq ON contact_group_members(group_id, contact_id) WHERE contact_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS cgm_email_uniq   ON contact_group_members(group_id, lower(email)) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS cgm_group_idx ON contact_group_members(group_id);

-- Group CRUD + member set + expand reducers (BZ044 duplicate name, BZ045 ownership).
\i ../reducers/jmap_contact_group.sql
