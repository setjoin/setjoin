-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Email aliases: multiple addresses that deliver to one mailbox.
CREATE TABLE aliases (
  id              BIGSERIAL   PRIMARY KEY,
  mailbox_id      BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  email           TEXT        NOT NULL UNIQUE,
  domain_id       BIGINT      NOT NULL REFERENCES domains(id),
  is_primary      BOOL        NOT NULL DEFAULT FALSE,
  display_name    TEXT,
  signature       TEXT,
  reply_to        TEXT,
  bcc_send        TEXT,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX aliases_mailbox_idx ON aliases(mailbox_id);
-- Note: email already has a UNIQUE constraint (implicit index), no separate index needed.

-- Distribution groups: static and dynamic (query-based) mailing lists.
CREATE TABLE distribution_groups (
  id                      BIGSERIAL   PRIMARY KEY,
  mailbox_id              BIGINT      NOT NULL REFERENCES mailboxes(id) UNIQUE,
  is_dynamic              BOOL        NOT NULL DEFAULT FALSE,
  -- Dynamic filter: {department_id, enabled, domain_id, ...} — evaluated at delivery
  dynamic_filter          JSONB,
  moderated               BOOL        NOT NULL DEFAULT FALSE,
  moderator_mailbox_id    BIGINT      REFERENCES mailboxes(id) ON DELETE SET NULL,
  allow_external_senders  BOOL        NOT NULL DEFAULT FALSE,
  delivery_report_to_owner BOOL       NOT NULL DEFAULT FALSE,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE distribution_group_members (
  group_id        BIGINT  NOT NULL REFERENCES distribution_groups(id) ON DELETE CASCADE,
  mailbox_id      BIGINT  NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  source          TEXT        NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'sso')),
  PRIMARY KEY (group_id, mailbox_id)
);

CREATE INDEX dg_members_mailbox_idx ON distribution_group_members(mailbox_id);

-- Expand a distribution group into its current member list.
-- For static groups: read members table.
-- For dynamic groups: evaluate the filter against current users/mailboxes.
CREATE OR REPLACE FUNCTION expand_group(p_group_id BIGINT)
RETURNS TABLE(mailbox_id BIGINT) AS $$
DECLARE
  v_dynamic      BOOL;
  v_filter       JSONB;
BEGIN
  SELECT is_dynamic, dynamic_filter
  INTO v_dynamic, v_filter
  FROM distribution_groups WHERE id = p_group_id;

  IF NOT v_dynamic THEN
    RETURN QUERY
      SELECT m.mailbox_id FROM distribution_group_members m WHERE m.group_id = p_group_id;
  ELSE
    -- Dynamic: filter mailboxes by department / domain / enabled status.
    -- Exclude mailboxes that back a distribution group (satellite table is the sole
    -- group signal after the type-refactor; mb.type is no longer a reliable guard).
    RETURN QUERY
      SELECT mb.id
      FROM mailboxes mb
      JOIN users u ON u.id = mb.user_id
      WHERE NOT EXISTS (SELECT 1 FROM distribution_groups dgx WHERE dgx.mailbox_id = mb.id)
        AND mb.enabled = TRUE
        AND (v_filter->>'enabled'  IS NULL OR u.enabled = (v_filter->>'enabled')::BOOL)
        AND (v_filter->>'domain_id' IS NULL OR mb.domain_id = (v_filter->>'domain_id')::BIGINT)
        AND (v_filter->>'department_id' IS NULL
             OR u.department_id = (v_filter->>'department_id')::BIGINT);
  END IF;
END;
$$ LANGUAGE plpgsql STABLE;
