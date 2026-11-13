-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Contacts: vCard model. JMAP primary; CardDAV bridge reads same tables.
CREATE TABLE addressbooks (
  id              BIGSERIAL   PRIMARY KEY,
  mailbox_id      BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  name            TEXT        NOT NULL,
  description     TEXT,
  is_default      BOOL        NOT NULL DEFAULT FALSE,
  is_shared       BOOL        NOT NULL DEFAULT FALSE,
  jmap_state      BIGINT      NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX addressbooks_mailbox_idx ON addressbooks(mailbox_id);
CREATE UNIQUE INDEX addressbooks_default_idx ON addressbooks(mailbox_id) WHERE is_default;

CREATE TABLE contacts (
  id              BIGSERIAL   PRIMARY KEY,
  addressbook_id  BIGINT      NOT NULL REFERENCES addressbooks(id) ON DELETE CASCADE,
  vcard_uid       TEXT        NOT NULL,
  display_name    TEXT        NOT NULL,
  first_name      TEXT,
  last_name       TEXT,
  company         TEXT,
  job_title       TEXT,
  department      TEXT,
  -- Structured multi-value fields stored as JSONB arrays
  emails          JSONB       NOT NULL DEFAULT '[]',   -- [{type,address,is_primary}]
  phones          JSONB       NOT NULL DEFAULT '[]',   -- [{type,number}]
  addresses       JSONB       NOT NULL DEFAULT '[]',   -- [{type,street,city,...}]
  urls            JSONB       NOT NULL DEFAULT '[]',   -- [{type,url}]
  instant_msgs    JSONB       NOT NULL DEFAULT '[]',   -- [{type,handle}]
  notes           TEXT,
  birthday        DATE,
  anniversary     DATE,
  avatar_sha256   TEXT        REFERENCES blobs(sha256),           -- ref into blobs
  categories      TEXT[]      NOT NULL DEFAULT '{}',
  -- vCard / CardDAV sync
  etag            TEXT        NOT NULL DEFAULT '',
  jmap_state      BIGINT      NOT NULL DEFAULT 0,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (addressbook_id, vcard_uid)
);

CREATE INDEX contacts_addressbook_idx   ON contacts(addressbook_id);
CREATE INDEX contacts_display_name_idx  ON contacts(display_name);
CREATE INDEX contacts_company_idx       ON contacts(company) WHERE company IS NOT NULL;
-- Trigram index for fuzzy name search
CREATE INDEX contacts_name_trgm_idx     ON contacts USING GIN(display_name gin_trgm_ops);
CREATE INDEX contacts_vcard_uid_idx     ON contacts(vcard_uid);
CREATE INDEX contacts_avatar_idx        ON contacts(avatar_sha256) WHERE avatar_sha256 IS NOT NULL;
CREATE INDEX contacts_categories_idx    ON contacts USING GIN(categories);

-- Personal contact groups (user-created distribution lists). Distinct from
-- admin/SCIM distribution_groups: these are owned by a single mailbox and are
-- addressable as one recipient that expands at compose time. R1–R4 enforced by
-- mailbox_id / p_mailbox_id parameter propagation (this repo does not use native
-- RLS policies — see docs/standards/DATABASE_SECURITY.md), consistent with the
-- sibling addressbooks/contacts tables above.
CREATE TABLE contact_groups (
  id          BIGSERIAL   PRIMARY KEY,
  mailbox_id  BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  name        TEXT        NOT NULL,
  jmap_state  BIGINT      NOT NULL DEFAULT 1,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX contact_groups_mailbox_idx ON contact_groups(mailbox_id);
CREATE UNIQUE INDEX contact_groups_name_idx ON contact_groups(mailbox_id, lower(name));

CREATE TABLE contact_group_members (
  id          BIGSERIAL   PRIMARY KEY,
  group_id    BIGINT      NOT NULL REFERENCES contact_groups(id) ON DELETE CASCADE,
  contact_id  BIGINT      REFERENCES contacts(id) ON DELETE CASCADE,
  email       TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Exactly one of (contact_id, email) is set: a saved contact, or a free-typed
  -- address the user has not saved to their address book.
  CONSTRAINT cgm_one_target CHECK (num_nonnulls(contact_id, email) = 1)
);
CREATE UNIQUE INDEX cgm_contact_uniq ON contact_group_members(group_id, contact_id) WHERE contact_id IS NOT NULL;
CREATE UNIQUE INDEX cgm_email_uniq   ON contact_group_members(group_id, lower(email)) WHERE email IS NOT NULL;
CREATE INDEX cgm_group_idx ON contact_group_members(group_id);
