-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Mailboxes: the mail container. One per user; shared/resource/group mailboxes
-- are also personal-type rows distinguished by satellite tables:
--   distribution group  — distribution_groups row
--   shared mailbox      — mailbox_delegates row + user_id IS NULL
--   room / equipment    — mailboxes.resource_type + calendars.resource_type
-- The derived role is available via mailbox_effective_type(p_mailbox_id).
CREATE TABLE mailboxes (
  id                      BIGSERIAL   PRIMARY KEY,
  user_id                 BIGINT      REFERENCES users(id) ON DELETE SET NULL, -- NULL = shared/resource
  domain_id               BIGINT      NOT NULL REFERENCES domains(id),
  email                   TEXT        NOT NULL,
  type                    TEXT        NOT NULL DEFAULT 'personal'
                            CHECK (type IN ('personal')),
  display_name            TEXT        NOT NULL,

  -- Primary mailbox for the user — JMAP Session.accountId resolves via this.
  -- Exactly one mailbox per user should have this set to TRUE (partial UNIQUE below).
  is_primary              BOOL        NOT NULL DEFAULT FALSE,

  -- Quotas
  quota_bytes             BIGINT      NOT NULL DEFAULT 53687091200, -- 50 GB
  used_bytes              BIGINT      NOT NULL DEFAULT 0,
  sending_quota_day       INT         NOT NULL DEFAULT 500,        -- messages per day
  sending_sent_today      INT         NOT NULL DEFAULT 0,
  sending_quota_reset_at  DATE        NOT NULL DEFAULT CURRENT_DATE,

  -- State
  enabled                 BOOL        NOT NULL DEFAULT TRUE,
  receive_enabled         BOOL        NOT NULL DEFAULT TRUE,
  hidden_from_gal         BOOL        NOT NULL DEFAULT FALSE,

  -- Litigation hold (immutable: trigger blocks DELETE on held messages)
  litigation_hold         BOOL        NOT NULL DEFAULT FALSE,
  hold_since              TIMESTAMPTZ,
  hold_reason             TEXT,
  hold_set_by             BIGINT      REFERENCES users(id) ON DELETE SET NULL,

  -- Per-mailbox auto-purge overrides (NULL = use system_config default, 0 = disable)
  deleted_purge_days       INT,
  spam_purge_days          INT,


  -- Spam
  spam_folder_enabled     BOOL        NOT NULL DEFAULT TRUE,
  spam_sensitivity        TEXT        NOT NULL DEFAULT 'medium'
                            CHECK (spam_sensitivity IN ('low','medium','high')),

  -- Resource mailbox (type = 'resource')
  resource_type           TEXT        CHECK (resource_type IN ('room','equipment')),
  resource_capacity       INT CHECK (resource_capacity IS NULL OR resource_capacity >= 0),
  auto_accept_meetings    BOOL        NOT NULL DEFAULT FALSE,
  max_meeting_hours       INT,
  booking_window_days     INT         NOT NULL DEFAULT 365,

  -- JMAP state tokens (incremented on any change → clients detect drift)
  jmap_email_state        BIGINT      NOT NULL DEFAULT 0,
  jmap_mailbox_state      BIGINT      NOT NULL DEFAULT 0,
  jmap_thread_state       BIGINT      NOT NULL DEFAULT 0,

  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX mailboxes_user_idx   ON mailboxes(user_id)   WHERE user_id IS NOT NULL;
CREATE INDEX mailboxes_domain_idx ON mailboxes(domain_id);
CREATE INDEX mailboxes_type_idx   ON mailboxes(type);
CREATE UNIQUE INDEX mailboxes_email_lower_idx ON mailboxes(lower(email));
CREATE INDEX mailboxes_hold_set_by_idx ON mailboxes(hold_set_by) WHERE hold_set_by IS NOT NULL;

-- At most one primary mailbox per user; resolved by the JMAP Session handler.
CREATE UNIQUE INDEX mailboxes_user_primary_idx
  ON mailboxes(user_id) WHERE is_primary;

-- Shared/resource mailboxes cannot be primary (they have no user_id)
ALTER TABLE mailboxes
  ADD CONSTRAINT mailboxes_shared_not_primary
  CHECK (is_primary = FALSE OR user_id IS NOT NULL);

-- Ensure every user with at least one mailbox has exactly one primary.
-- Fires on INSERT, UPDATE, and DELETE to verify the invariant.
CREATE OR REPLACE FUNCTION trg_mailbox_primary_enforce() RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.user_id IS NOT NULL AND OLD.is_primary THEN
      IF NOT EXISTS (
        SELECT 1 FROM mailboxes
        WHERE user_id = OLD.user_id AND is_primary AND id != OLD.id
      ) THEN
        RAISE EXCEPTION 'User % must have at least one primary mailbox; reassign before deleting', OLD.user_id
          USING ERRCODE = 'BZ013', HINT = jsonb_build_object('type', 'must_set_primary', 'user_id', OLD.user_id)::TEXT;
      END IF;
    END IF;
    RETURN OLD;
  ELSIF TG_OP IN ('INSERT', 'UPDATE') THEN
    IF NEW.user_id IS NOT NULL THEN
      IF NOT EXISTS (
        SELECT 1 FROM mailboxes
        WHERE user_id = NEW.user_id AND id != COALESCE(NEW.id, 0) AND is_primary
      ) AND NOT NEW.is_primary THEN
        RAISE EXCEPTION 'User % has no primary mailbox; set is_primary = TRUE on one mailbox', NEW.user_id
          USING ERRCODE = 'BZ014', HINT = jsonb_build_object('type', 'no_primary', 'user_id', NEW.user_id)::TEXT;
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER mailbox_primary_enforce
  AFTER INSERT OR UPDATE OR DELETE ON mailboxes
  FOR EACH ROW EXECUTE FUNCTION trg_mailbox_primary_enforce();

-- Delegates: send-as / send-on-behalf / full-access
CREATE TABLE mailbox_delegates (
  mailbox_id      BIGINT  NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  user_id         BIGINT  NOT NULL REFERENCES users(id)     ON DELETE CASCADE,
  permission      TEXT    NOT NULL
                    CHECK (permission IN ('read','send_as','send_on_behalf','full_access')),
  granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  granted_by      BIGINT  NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  PRIMARY KEY (mailbox_id, user_id, permission)
);
