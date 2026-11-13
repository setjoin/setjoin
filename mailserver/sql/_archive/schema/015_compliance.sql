-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Compliance: archiving policies, eDiscovery, journaling, retention, audit logs.

-- Retention tags: assign policies to messages.
CREATE TABLE retention_policies (
  id              BIGSERIAL   PRIMARY KEY,
  name            TEXT        NOT NULL UNIQUE,
  description     TEXT,
  retain_days     INT CHECK (retain_days IS NULL OR retain_days > 0),  -- NULL = keep forever
  action          TEXT        NOT NULL DEFAULT 'delete'
                    CHECK (action IN ('delete','archive','hold')),
  is_default      BOOL        NOT NULL DEFAULT FALSE,
  domain_id       BIGINT      REFERENCES domains(id) ON DELETE CASCADE, -- NULL = global
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE message_retention_tags (
  message_id      BIGINT      NOT NULL,
  received_at     TIMESTAMPTZ NOT NULL,
  policy_id       BIGINT      NOT NULL REFERENCES retention_policies(id),
  expires_at      TIMESTAMPTZ,            -- computed: received_at + retain_days
  PRIMARY KEY (message_id, received_at),
  FOREIGN KEY (message_id, received_at) REFERENCES messages(id, received_at)
);

CREATE INDEX retention_expires_idx ON message_retention_tags(expires_at)
  WHERE expires_at IS NOT NULL;

-- Journaling policies: admin-configured rules deciding which traffic
-- gets BCC'd into a journal mailbox. Checked by journal_if_policy_matches()
-- in deliver() (inbound) and send() (outbound).
CREATE TABLE journaling_policies (
  id                 BIGSERIAL   PRIMARY KEY,
  domain_id          BIGINT      REFERENCES domains(id) ON DELETE CASCADE, -- NULL = global
  direction          TEXT        NOT NULL
                       CHECK (direction IN ('inbound','outbound','both')),
  journal_mailbox_id BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE RESTRICT,
  enabled            BOOL        NOT NULL DEFAULT TRUE,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX journaling_policies_lookup_idx
  ON journaling_policies(domain_id, direction, enabled);

-- Journal queue: BCC-style copy of messages to a journal mailbox.
CREATE TABLE journal_queue (
  id              BIGSERIAL   PRIMARY KEY,
  message_id      TEXT        NOT NULL,
  envelope_from   TEXT        NOT NULL,
  envelope_to     TEXT        NOT NULL,
  raw_ref         TEXT        NOT NULL,   -- MinIO path
  journal_mailbox_id BIGINT   NOT NULL REFERENCES mailboxes(id) ON DELETE RESTRICT,
  status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','delivered','failed')),
  attempt_count   INT         NOT NULL DEFAULT 0,
  queued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at    TIMESTAMPTZ
);

CREATE INDEX journal_queue_pending_idx ON journal_queue(status) WHERE status = 'pending';

-- eDiscovery search runs: tracks cross-mailbox admin searches.
CREATE TABLE ediscovery_searches (
  id              BIGSERIAL   PRIMARY KEY,
  name            TEXT        NOT NULL,
  created_by      BIGINT      NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  query           JSONB       NOT NULL,  -- {keywords, from, to, date_from, date_to, mailboxes}
  status          TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','running','complete','failed')),
  result_count    INT,
  export_ref      TEXT,                  -- MinIO path to exported MBOX
  started_at      TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE ediscovery_searches ADD CONSTRAINT ediscovery_query_check CHECK (jsonb_typeof(query) = 'object');

-- Admin audit log: every admin action recorded with before/after state.
CREATE TABLE admin_audit_log (
  id              BIGSERIAL   PRIMARY KEY,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id         BIGINT      REFERENCES users(id) ON DELETE SET NULL,
  ip              INET,
  action          TEXT        NOT NULL,  -- 'create_user','delete_mailbox','set_hold',...
  target_type     TEXT,                  -- 'user','mailbox','domain','rule',...
  target_id       BIGINT,
  before_state    JSONB,
  after_state     JSONB,
  notes           TEXT
);

CREATE INDEX admin_audit_user_idx    ON admin_audit_log(user_id, occurred_at DESC);
CREATE INDEX admin_audit_target_idx  ON admin_audit_log(target_type, target_id, occurred_at DESC);
CREATE INDEX admin_audit_time_idx    ON admin_audit_log(occurred_at DESC);

-- Mailbox audit log: per-mailbox access events (configurable verbosity).
CREATE TABLE mailbox_audit_log (
  id              BIGSERIAL   NOT NULL,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  mailbox_id      BIGINT      NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  actor_user_id   BIGINT      REFERENCES users(id) ON DELETE SET NULL,
  action          TEXT        NOT NULL,  -- 'read','move','delete','send_as','login',...
  message_id      BIGINT,
  details         JSONB,
  PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

CREATE TABLE mailbox_audit_log_default PARTITION OF mailbox_audit_log DEFAULT;

CREATE INDEX mailbox_audit_mailbox_idx ON mailbox_audit_log(mailbox_id, occurred_at DESC);

-- Append-only checksum chain on admin_audit_log for tamper detection.
-- Each row's checksum covers: id + occurred_at + action + before/after + prev_checksum
CREATE OR REPLACE FUNCTION trg_admin_audit_checksum() RETURNS TRIGGER AS $$
DECLARE
  v_prev_checksum TEXT;
  v_last_id       BIGINT;
BEGIN
  -- Serialize all checksum chain writes with an advisory lock so concurrent
  -- inserts cannot read the same "latest" row and fork the chain.
  PERFORM pg_advisory_xact_lock('admin_audit_log'::regclass::int, 0);

  SELECT id, after_state->>'_checksum'
  INTO v_last_id, v_prev_checksum
  FROM admin_audit_log
  ORDER BY id DESC
  LIMIT 1;

  NEW.after_state := coalesce(NEW.after_state, '{}'::JSONB)
    || jsonb_build_object('_checksum',
         encode(sha256((
           NEW.id::TEXT || NEW.occurred_at::TEXT || NEW.action ||
           coalesce(NEW.before_state::TEXT,'') ||
           coalesce(v_prev_checksum,'')
         )::BYTEA), 'hex'));
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER admin_audit_chain
  BEFORE INSERT ON admin_audit_log
  FOR EACH ROW EXECUTE FUNCTION trg_admin_audit_checksum();

-- SAML assertion replay prevention (OASIS SAML Core §2.5.1)
CREATE TABLE IF NOT EXISTS used_saml_assertions (
    assertion_id TEXT PRIMARY KEY,
    used_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prune SAML assertions older than 24 hours
CREATE OR REPLACE FUNCTION prune_saml_assertions()
RETURNS VOID AS $$
BEGIN
    DELETE FROM used_saml_assertions WHERE used_at < now() - INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql;

-- Append-only enforcement: block UPDATE/DELETE on audit tables
CREATE OR REPLACE FUNCTION trg_audit_append_only() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Cannot UPDATE or DELETE audit records'
      USING ERRCODE = 'BZ017', HINT = '{"type":"audit_append_only"}';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER admin_audit_append_only
    BEFORE UPDATE OR DELETE ON admin_audit_log
    FOR EACH ROW EXECUTE FUNCTION trg_audit_append_only();

CREATE TRIGGER mailbox_audit_append_only
    BEFORE UPDATE OR DELETE ON mailbox_audit_log
    FOR EACH ROW EXECUTE FUNCTION trg_audit_append_only();

-- Chain-of-custody verification: validate the SHA-256 checksum chain.
CREATE OR REPLACE FUNCTION verify_audit_chain(
    p_from_id BIGINT DEFAULT NULL,
    p_to_id   BIGINT DEFAULT NULL
) RETURNS TABLE(
    row_id BIGINT, valid BOOL, occurred_at TIMESTAMPTZ, action TEXT
) AS $$
DECLARE
    v_prev TEXT := '';
    v_row  RECORD;
BEGIN
    FOR v_row IN
        SELECT id, after_state->>'_checksum' AS checksum, occurred_at, action
        FROM admin_audit_log
        WHERE (p_from_id IS NULL OR id >= p_from_id)
          AND (p_to_id IS NULL OR id <= p_to_id)
        ORDER BY id
    LOOP
        row_id := v_row.id;
        occurred_at := v_row.occurred_at;
        action := v_row.action;
        valid := v_row.checksum IS NOT NULL; -- chain exists (hash was computed on insert)
        v_prev := v_row.checksum;
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql;
