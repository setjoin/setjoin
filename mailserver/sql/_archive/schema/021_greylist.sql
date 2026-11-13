-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Greylisting: RFC-compliant temporary rejection for unknown triplets.
-- Unlogged table = truncated on crash; acceptable (greylist is best-effort).
CREATE UNLOGGED TABLE IF NOT EXISTS greylist (
  ip              INET        NOT NULL,
  sender          TEXT        NOT NULL,
  recipient       TEXT        NOT NULL,
  first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
  pass_count      INT         NOT NULL DEFAULT 0,
  whitelisted     BOOL        NOT NULL DEFAULT FALSE,
  PRIMARY KEY (ip, sender, recipient)
);

CREATE INDEX greylist_first_seen_idx ON greylist(first_seen);

-- Whitelist: trusted senders that bypass greylisting.
CREATE TABLE greylist_whitelist (
  id             BIGSERIAL   PRIMARY KEY,
  entry_type     TEXT        NOT NULL CHECK (entry_type IN ('ip','domain','email')),
  entry_value    TEXT        NOT NULL,
  description    TEXT,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (entry_type, entry_value)
);

-- Greylist check function: returns TRUE if message should be accepted.
-- Returns FALSE if it should be temporarily rejected.
CREATE OR REPLACE FUNCTION greylist_check(
  p_client_ip  INET,
  p_sender     TEXT,
  p_recipient  TEXT,
  p_delay_min  INT DEFAULT 5
) RETURNS BOOL AS $$
DECLARE
  v_record RECORD;
  v_whitelisted BOOL := FALSE;
BEGIN
  IF p_delay_min <= 0 THEN
    RAISE EXCEPTION 'p_delay_min must be positive, got %', p_delay_min
      USING ERRCODE = 'BZ018', HINT = jsonb_build_object('type', 'invalid_delay_min', 'delay_min', p_delay_min)::TEXT;
  END IF;
  -- Check whitelist
  SELECT TRUE INTO v_whitelisted FROM greylist_whitelist
  WHERE (entry_type = 'ip' AND entry_value = p_client_ip::TEXT)
     OR (entry_type = 'domain' AND lower(p_sender) LIKE '%@' || lower(entry_value))
     OR (entry_type = 'email' AND lower(entry_value) = lower(p_sender))
  LIMIT 1;

  IF v_whitelisted THEN
    RETURN TRUE;
  END IF;

  -- Check existing triplet
  SELECT * INTO v_record FROM greylist
  WHERE ip = p_client_ip
    AND sender = lower(p_sender)
    AND recipient = lower(p_recipient);

  IF v_record.ip IS NULL THEN
    -- First time: insert and reject
    INSERT INTO greylist (ip, sender, recipient)
    VALUES (p_client_ip, lower(p_sender), lower(p_recipient));
    RETURN FALSE;
  END IF;

  IF v_record.pass_count > 0 THEN
    -- Already passed greylisting: accept and update count + last_seen
    UPDATE greylist SET pass_count = pass_count + 1, last_seen = now()
    WHERE ip = p_client_ip
      AND sender = lower(p_sender)
      AND recipient = lower(p_recipient);
    RETURN TRUE;
  END IF;

  IF v_record.first_seen < now() - (p_delay_min || ' minutes')::INTERVAL THEN
    -- Delay has passed: accept
    UPDATE greylist SET pass_count = 1, last_seen = now()
    WHERE ip = p_client_ip
      AND sender = lower(p_sender)
      AND recipient = lower(p_recipient);
    RETURN TRUE;
  END IF;

  -- Still within delay window: reject
  RETURN FALSE;
END;
$$ LANGUAGE plpgsql;

-- Cleanup old greylist entries (run via pg_cron daily)
CREATE OR REPLACE FUNCTION greylist_prune()
RETURNS VOID AS $$
BEGIN
  DELETE FROM greylist
  WHERE pass_count = 0 AND first_seen < now() - interval '24 hours';
  DELETE FROM greylist
  WHERE pass_count > 0 AND first_seen < now() - interval '30 days';
END;
$$ LANGUAGE plpgsql;
