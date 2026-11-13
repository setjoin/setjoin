-- Utility functions shared by all reducers.

-- Compute a stable thread_id from the References / In-Reply-To chain.
-- Walks backwards from the current message to find the root Message-ID.
CREATE OR REPLACE FUNCTION compute_thread_id(
  p_message_id   TEXT,
  p_in_reply_to  TEXT,
  p_references   TEXT,
  p_mailbox_id   BIGINT
) RETURNS TEXT AS $$
DECLARE
  v_root_id  TEXT;
  v_ref_ids  TEXT[];
  v_ref_id   TEXT;
BEGIN
  -- Parse References header into array of Message-IDs
  IF p_references IS NOT NULL THEN
    v_ref_ids := string_to_array(
      regexp_replace(p_references, '[<>]', '', 'g'), ' '
    );
  ELSIF p_in_reply_to IS NOT NULL THEN
    v_ref_ids := ARRAY[trim(both '<>' FROM p_in_reply_to)];
  ELSE
    RETURN trim(both '<>' FROM p_message_id);   -- No thread ancestors → this message is the thread root
  END IF;

  -- Walk reference list oldest-first; find the earliest one we already have
  FOREACH v_ref_id IN ARRAY v_ref_ids LOOP
    SELECT thread_id INTO v_root_id
    -- messages.message_id is stored with its angle brackets (raw Message-Id
    -- header), but v_ref_id was trimmed of <> above — so trim the stored side too,
    -- else a reply never matches its parent and every reply starts a new thread.
    -- ponytail: trim() defeats the (mailbox_id, message_id) index; delivery walks
    -- only a handful of refs per message so it's fine — add a functional index on
    -- trim(both '<>' from message_id) if a huge References chain ever shows up hot.
    FROM messages
    WHERE mailbox_id = p_mailbox_id AND trim(both '<>' FROM message_id) = v_ref_id
    LIMIT 1;
    IF v_root_id IS NOT NULL THEN
      RETURN v_root_id;
    END IF;
  END LOOP;

  -- None of the ancestors exist in this mailbox → this is the root
  RETURN trim(both '<>' FROM p_message_id);
END;
$$ LANGUAGE plpgsql STABLE;

-- Check whether a mailbox has quota headroom for a given number of bytes.
-- Uses FOR UPDATE to serialise concurrent deliveries on the same mailbox.
CREATE OR REPLACE FUNCTION check_quota(
  p_mailbox_id  BIGINT,
  p_bytes       BIGINT
) RETURNS BOOL AS $$
DECLARE
  v_used   BIGINT;
  v_limit  BIGINT;
BEGIN
  SELECT used_bytes, quota_bytes INTO v_used, v_limit
  FROM mailboxes WHERE id = p_mailbox_id FOR UPDATE;
  RETURN (v_used + p_bytes) <= v_limit;
END;
$$ LANGUAGE plpgsql;

-- Assign the next IMAP UID in the folder and increment uid_next.
CREATE OR REPLACE FUNCTION next_imap_uid(p_folder_id BIGINT) RETURNS BIGINT AS $$
DECLARE
  v_uid BIGINT;
BEGIN
  UPDATE folders SET imap_uid_next = imap_uid_next + 1
  WHERE id = p_folder_id
  RETURNING imap_uid_next - 1 INTO v_uid;
  RETURN v_uid;
END;
$$ LANGUAGE plpgsql;

-- Write a message trace event.
CREATE OR REPLACE FUNCTION trace(
  p_message_id  TEXT,
  p_event       TEXT,
  p_from_addr   TEXT,
  p_rcpt_addr   TEXT,
  p_remote_host TEXT DEFAULT NULL,
  p_details     JSONB DEFAULT NULL
) RETURNS VOID AS $$
BEGIN
  INSERT INTO message_trace
    (message_id, event, from_addr, rcpt_addr, remote_host, details)
  VALUES
    (p_message_id, p_event, p_from_addr, p_rcpt_addr, p_remote_host, p_details);
END;
$$ LANGUAGE plpgsql;

-- Increment a mailbox's JMAP email state token and return new value.
CREATE OR REPLACE FUNCTION bump_email_state(p_mailbox_id BIGINT) RETURNS BIGINT AS $$
DECLARE
  v_state BIGINT;
BEGIN
  UPDATE mailboxes SET jmap_email_state = jmap_email_state + 1
  WHERE id = p_mailbox_id
  RETURNING jmap_email_state INTO v_state;
  RETURN v_state;
END;
$$ LANGUAGE plpgsql;

-- adjust_folder_counters() was removed (V077): it maintained the dead
-- folders.total_count/unread_count/size_bytes columns (never read — JMAP/IMAP use
-- tags.*_count) and, via its only caller enforce_retention, was fed messages.folder_id
-- which holds a TAG id, so its live mailbox used_bytes/state bump silently misfired.
-- enforce_retention (retention.sql) now bumps mailboxes.used_bytes + JMAP state
-- directly by mailbox_id; tag counters are maintained by trg_message_tags_counters.


-- Generate a random ETag for CalDAV/CardDAV resources.
CREATE OR REPLACE FUNCTION generate_etag() RETURNS TEXT AS $$
  SELECT encode(digest(gen_random_uuid()::text, 'sha256'), 'hex');
$$ LANGUAGE SQL VOLATILE;

-- Neutralize email header injection: strip CR/LF (a bare CR/LF terminates a header
-- per RFC 5322, so an un-sanitized user value can inject arbitrary headers or split
-- the message). Runs of CR/LF collapse to one space so a pasted multi-line value
-- stays readable on one line. Wrap EVERY user-controlled value that is concatenated
-- into a raw RFC 5322 header (Subject, From/To/Cc display names, Reply-To,
-- Sensitivity, X-Mailserver-Vote*, MDN echoes). These builders do not fold headers,
-- so no legitimate CR/LF exists inside a value here.
CREATE OR REPLACE FUNCTION email_header_value(p_val TEXT) RETURNS TEXT AS $$
  SELECT regexp_replace(COALESCE(p_val, ''), E'[\r\n]+', ' ', 'g');
$$ LANGUAGE SQL IMMUTABLE;

-- Tag system utilities moved to utils_tags.sql (loaded by V005 after tags table exists)
