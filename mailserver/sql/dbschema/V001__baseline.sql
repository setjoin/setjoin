--
-- PostgreSQL database dump
--

\restrict 4ytpLFRZJF1Y5RJjRbO84hlsoaBmGzxZSm9pK5Eh2W8nbstGCHNCMs55ZxNIUEk

-- Dumped from database version 17.10 (Homebrew)
-- Dumped by pg_dump version 17.10 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pg_stat_statements; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA public;


--
-- Name: EXTENSION pg_stat_statements; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_stat_statements IS 'track planning and execution statistics of all SQL statements executed';


--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: pgtap; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgtap WITH SCHEMA public;


--
-- Name: EXTENSION pgtap; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgtap IS 'Unit testing for PostgreSQL';
--
-- Name: all_mail(bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.all_mail(p_mailbox_id bigint) RETURNS TABLE(id bigint, received_at timestamp with time zone)
    LANGUAGE sql STABLE
    AS $$
    SELECT DISTINCT m.id, m.received_at
    FROM messages m
    JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
    WHERE m.mailbox_id = p_mailbox_id
      AND NOT m.is_deleted
      AND NOT EXISTS (
        SELECT 1 FROM message_tags mt2
        JOIN tags t ON t.id = mt2.tag_id
        WHERE mt2.message_id = m.id
          AND mt2.received_at = m.received_at
          AND t.name IN ('Trash', 'Spam')
      );
$$;
--
-- Name: backfill_scheduled_actions(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.backfill_scheduled_actions() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_rec   RECORD;
    v_count INT := 0;
    v_id    UUID;
BEGIN
    -- Legacy snoozes.
    FOR v_rec IN
        SELECT mt.message_id, mt.received_at, mt.snooze_until, t.mailbox_id
        FROM message_tags mt
        JOIN tags t ON t.id = mt.tag_id
        WHERE t.exclusive_group = 'snooze' AND t.name = 'Snoozed'
          AND mt.snooze_until IS NOT NULL AND mt.snooze_until > now()
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM scheduled_actions
            WHERE action_kind = 'snooze' AND mailbox_id = v_rec.mailbox_id
              AND payload @> jsonb_build_object('message_id', v_rec.message_id)
        ) THEN
            INSERT INTO scheduled_actions (action_kind, fire_at, payload, mailbox_id)
            VALUES ('snooze', v_rec.snooze_until,
                    jsonb_build_object('message_id', v_rec.message_id, 'received_at', v_rec.received_at),
                    v_rec.mailbox_id);
            v_count := v_count + 1;
        END IF;
    END LOOP;

    -- Legacy scheduled sends (Scheduled tag with a future scheduled_at).
    FOR v_rec IN
        SELECT mt.message_id, mt.received_at, mt.scheduled_at, t.mailbox_id
        FROM message_tags mt
        JOIN tags t ON t.id = mt.tag_id
        WHERE t.name = 'Scheduled'
          AND mt.scheduled_at IS NOT NULL AND mt.scheduled_at > now()
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM scheduled_actions
            WHERE action_kind = 'send' AND mailbox_id = v_rec.mailbox_id
              AND payload @> jsonb_build_object('message_id', v_rec.message_id)
        ) THEN
            INSERT INTO scheduled_actions (action_kind, fire_at, payload, mailbox_id)
            VALUES ('send', v_rec.scheduled_at,
                    jsonb_build_object('message_id', v_rec.message_id, 'received_at', v_rec.received_at, 'undo', FALSE),
                    v_rec.mailbox_id)
            RETURNING id INTO v_id;
            -- Default the egress dedup_key to the action id (idempotency).
            UPDATE scheduled_actions SET dedup_key = v_id::TEXT WHERE id = v_id;
            v_count := v_count + 1;
        END IF;
    END LOOP;

    RETURN v_count;
END;
$$;
--
-- Name: scheduled_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scheduled_actions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    action_kind text NOT NULL,
    fire_at timestamp with time zone NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    locked_until timestamp with time zone,
    locked_by text,
    last_error text,
    dedup_key text,
    mailbox_id bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT scheduled_actions_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'processing'::text, 'done'::text, 'failed'::text])))
);
--
-- Name: create_system_folders(bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.create_system_folders(p_mailbox_id bigint) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
  v_uid_validity BIGINT := EXTRACT(EPOCH FROM now())::BIGINT;
  v_type         TEXT;
BEGIN
  SELECT type INTO v_type FROM mailboxes WHERE id = p_mailbox_id;

  -- Journal mailboxes only need Inbox
  IF v_type = 'journal' THEN
    INSERT INTO folders (mailbox_id, name, role, path, sort_order, imap_uid_validity) VALUES
      (p_mailbox_id, 'Inbox', 'inbox', 'INBOX', 0, v_uid_validity);
    RETURN;
  END IF;

  INSERT INTO folders (mailbox_id, name, role, path, sort_order, imap_uid_validity) VALUES
    (p_mailbox_id, 'Inbox',     'inbox',    'INBOX',              0,  v_uid_validity),
    (p_mailbox_id, 'Sent',      'sent',     'INBOX/Sent',         10, v_uid_validity),
    (p_mailbox_id, 'Drafts',    'drafts',   'INBOX/Drafts',       20, v_uid_validity),
    (p_mailbox_id, 'Trash',     'trash',    'INBOX/Trash',        30, v_uid_validity),
    (p_mailbox_id, 'Spam',      'spam',     'INBOX/Spam',         40, v_uid_validity),
    (p_mailbox_id, 'Archive',   'archive',  'INBOX/Archive',      50, v_uid_validity),
    (p_mailbox_id, 'Templates', 'templates','INBOX/Templates',    60, v_uid_validity);
END;
$$;


--
-- Name: create_system_tags(bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.create_system_tags(p_mailbox_id bigint) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_uid_validity BIGINT := EXTRACT(EPOCH FROM now())::BIGINT;
    v_type         TEXT;
    v_inbox_id     BIGINT;
BEGIN
    SELECT type INTO v_type FROM mailboxes WHERE id = p_mailbox_id;

    IF v_type = 'journal' THEN
        INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group, is_default, sort_order,
                          imap_uid_validity, imap_expose)
        VALUES (p_mailbox_id, 'Inbox', 'system', 'location', TRUE, 0, v_uid_validity, TRUE)
        ON CONFLICT (mailbox_id, name) DO NOTHING;
        RETURN;
    END IF;

    INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group, is_default,
                      icon, color, sort_order, imap_uid_validity, imap_expose, imap_name)
    VALUES
        (p_mailbox_id, 'Inbox',     'system', 'location', TRUE,
         'inbox',    '#7C8DB5', 0,  v_uid_validity, TRUE,  NULL)
    ON CONFLICT (mailbox_id, name) DO NOTHING
    RETURNING id INTO v_inbox_id;

    INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group,
                      icon, color, sort_order, imap_uid_validity, imap_expose, imap_name)
    VALUES
        (p_mailbox_id, 'Sent',      'system', 'location',
         'send',     '#5CB85C', 10, v_uid_validity, TRUE,  NULL),
        (p_mailbox_id, 'Drafts',    'system', 'location',
         'edit',     '#F0AD4E', 20, v_uid_validity, TRUE,  NULL),
        (p_mailbox_id, 'Trash',     'system', 'location',
         'delete',   '#D9534F', 30, v_uid_validity, TRUE,  '[Gmail]/Trash'),
        (p_mailbox_id, 'Spam',      'system', 'location',
         'warning',  '#D9534F', 40, v_uid_validity, TRUE,  '[Gmail]/Spam'),
        (p_mailbox_id, 'Starred',   'system', NULL,
         'star',     '#F5A623', 50, v_uid_validity, TRUE,  NULL),
        (p_mailbox_id, 'Snoozed',   'system', 'snooze',
         'clock',    '#9B59B6', 60, v_uid_validity, FALSE, NULL),
        (p_mailbox_id, 'Scheduled', 'system', 'snooze',
         'calendar', '#3498DB', 70, v_uid_validity, TRUE,  '[Gmail]/Scheduled'),
        (p_mailbox_id, 'Important', 'system', NULL,
         'priority', '#E74C3C', 80, v_uid_validity, FALSE, NULL),
        (p_mailbox_id, 'Muted',     'system', NULL,
         'volume_off', '#888888', 90, v_uid_validity, FALSE, NULL)
    ON CONFLICT (mailbox_id, name) DO NOTHING;
END;
$$;
--
-- Name: dlp_check(bigint, bigint, text, text, text, jsonb); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.dlp_check(p_mailbox_id bigint, p_domain_id bigint, p_subject text, p_body_text text, p_body_html text, p_attachments jsonb DEFAULT '[]'::jsonb) RETURNS TABLE(violated boolean, policy_id bigint, action text, reason text)
    LANGUAGE plpgsql
    AS $$
DECLARE
  v_policy        RECORD;
  v_content       TEXT;
  v_match_count   INT;
  v_total_count   INT;
  v_att           JSONB;
  v_blocked       BOOL := FALSE;
BEGIN
  SET LOCAL statement_timeout = '5s';
  v_content := lower(coalesce(p_subject,'') || ' ' || coalesce(p_body_text,'') || ' ' || coalesce(p_body_html,''));

  FOR v_policy IN
    SELECT dp.* FROM dlp_policies dp
    WHERE dp.enabled = TRUE
      AND (dp.domain_id IS NULL OR dp.domain_id = p_domain_id)
      AND (dp.applies_to_all = TRUE OR EXISTS (
        SELECT 1 FROM dlp_policy_targets dpt
        WHERE dpt.policy_id = dp.id AND dpt.mailbox_id = p_mailbox_id
      ))
    ORDER BY dp.priority
  LOOP
    -- Regex check
    IF array_length(v_policy.regex_patterns, 1) > 0 THEN
      FOR i IN 1..array_length(v_policy.regex_patterns, 1) LOOP
        IF v_content ~* v_policy.regex_patterns[i] THEN
          v_blocked := TRUE;
          RETURN QUERY SELECT TRUE, v_policy.id, v_policy.action,
            'Matched regex: ' || v_policy.regex_patterns[i];
        END IF;
      END LOOP;
    END IF;

    IF v_blocked THEN CONTINUE; END IF;

    -- Keyword check
    IF array_length(v_policy.keywords, 1) > 0 THEN
      v_match_count := 0;
      v_total_count := array_length(v_policy.keywords, 1);
      FOR i IN 1..v_total_count LOOP
        IF v_content LIKE '%' || lower(v_policy.keywords[i]) || '%' THEN
          v_match_count := v_match_count + 1;
        END IF;
      END LOOP;
      IF v_match_count::REAL / v_total_count >= v_policy.min_confidence THEN
        v_blocked := TRUE;
        RETURN QUERY SELECT TRUE, v_policy.id, v_policy.action,
          'Matched keywords: ' || v_match_count || '/' || v_total_count;
      END IF;
    END IF;

    IF v_blocked THEN CONTINUE; END IF;

    -- Attachment checks
    FOR v_att IN SELECT * FROM jsonb_array_elements(p_attachments) LOOP
      -- File type check
      IF array_length(v_policy.blocked_file_types, 1) > 0 THEN
        FOR i IN 1..array_length(v_policy.blocked_file_types, 1) LOOP
          IF lower(v_att->>'filename') LIKE '%.' || lower(v_policy.blocked_file_types[i]) THEN
            v_blocked := TRUE;
            RETURN QUERY SELECT TRUE, v_policy.id, v_policy.action,
              'Blocked file type: ' || (v_att->>'filename');
          END IF;
        END LOOP;
      END IF;

      -- Size check
      IF v_policy.max_attachment_size > 0 AND (v_att->>'size_bytes')::BIGINT > v_policy.max_attachment_size THEN
        v_blocked := TRUE;
        RETURN QUERY SELECT TRUE, v_policy.id, v_policy.action,
          'Oversized attachment: ' || (v_att->>'filename');
      END IF;
    END LOOP;
  END LOOP;

  RETURN QUERY SELECT FALSE, NULL::BIGINT, NULL::TEXT, NULL::TEXT;
END;
$$;
--
-- Name: drain_outbound_hot(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.drain_outbound_hot() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    WITH drained AS (
        DELETE FROM outbound_queue_hot
        RETURNING *
    )
    INSERT INTO outbound_queue
    SELECT * FROM drained
    ON CONFLICT (id) DO NOTHING;
END;
$$;


--
-- Name: drain_outbound_queue(boolean); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.drain_outbound_queue(p_retry_only boolean DEFAULT false) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE outbound_queue
    SET status = 'pending', next_attempt_at = NULL
    WHERE status = 'deferred'
      AND next_attempt_at <= now()
      AND attempt_count < 20;
END;
$$;
--
-- Name: expand_group(bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.expand_group(p_group_id bigint) RETURNS TABLE(mailbox_id bigint)
    LANGUAGE plpgsql STABLE
    AS $$
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
$$;
--
-- Name: fold_stored_address(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fold_stored_address(p_raw text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$
  SELECT CASE
    WHEN p_raw IS NULL THEN NULL
    ELSE btrim(translate(p_raw,
                         'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
                         'abcdefghijklmnopqrstuvwxyz'),
               -- Go's strings.TrimSpace / unicode.IsSpace whitespace set:
               U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680'
                 '\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A'
                 '\2028\2029\202F\205F\3000')
  END
$$;


--
-- Name: FUNCTION fold_stored_address(p_raw text); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.fold_stored_address(p_raw text) IS 'ONE-TIME BACKFILL helper for the FINITE set of pre-canonical stored identity addresses (users.email, aliases.email, users.ad_upn) — NOT a live twin of shared/identity.CanonicalizeAddress. As of the AD/LDAP-writer-canonical wave (2026-06-18) every address WRITER routes through CanonicalizeAddress (the CanonicalAddress newtype makes a raw-string write fail to compile), so nothing live writes a non-canonical row this fold must stay byte-equal to. Fold rule: trim (Go strings.TrimSpace / unicode.IsSpace whitespace set — U+0009,000A,000B,000C,000D,0020,0085,00A0,1680,2000-200A,2028,2029,202F,205F,3000) + ASCII-A-Z fold ONLY (display-name strip is INPUT-only and deliberately absent). Pinned by the PINNED-CORPUS regression shared/identity.TestFoldStoredAddress_PinnedCorpus (frozen V089 corpus; no longer a "byte-equal to Go forever" drift guard). SUNSET: do NOT re-run the archived V089 after the canonicalizer evolves (a replay would fold stored rows with the OLD rule while live writes use the new rule → split-brain). DELETE this function once a prod audit confirms every stored row is already canonical (x = fold_stored_address(x) for all rows). IDN deferred.';
--
-- Name: get_mailbox_delegates(bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_mailbox_delegates(p_mailbox_id bigint) RETURNS jsonb
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_result JSONB := '[]'::JSONB;
    v_row RECORD;
BEGIN
    FOR v_row IN
        SELECT mb.id, mb.email, u.display_name
        FROM mailboxes mb
        JOIN users u ON u.id = mb.user_id
        WHERE mb.id = p_mailbox_id
        UNION
        SELECT mb.id, mb.email, u.display_name
        FROM mailbox_delegates md
        JOIN mailboxes mb ON mb.id = md.mailbox_id
        JOIN users u ON u.id = mb.user_id
        WHERE md.mailbox_id = p_mailbox_id
          AND md.permission IN ('send_as', 'send_on_behalf', 'full_access')
    LOOP
        v_result := v_result || jsonb_build_object(
            'id', v_row.id::TEXT,
            'email', v_row.email,
            'name', v_row.display_name
        );
    END LOOP;
    RETURN v_result;
END;
$$;


--
-- Name: get_read_receipt_policy(bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_read_receipt_policy(p_user_id bigint) RETURNS text
    LANGUAGE sql STABLE
    AS $$
  SELECT COALESCE(
    (SELECT read_receipt_policy FROM user_notification_prefs
      WHERE user_id = p_user_id AND device_fingerprint IS NULL
      LIMIT 1),
    'ask');
$$;


--
-- Name: get_system_config(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_system_config(p_key text DEFAULT NULL::text) RETURNS jsonb
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
  v_result JSONB;
BEGIN
  IF p_key IS NULL THEN
    SELECT jsonb_object_agg(key, value) INTO v_result FROM system_config;
    RETURN COALESCE(v_result, '{}'::JSONB);
  ELSE
    SELECT value INTO v_result FROM system_config WHERE key = p_key;
    RETURN v_result;
  END IF;
END;
$$;
--
-- Name: vacation_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vacation_settings (
    mailbox_id bigint NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    subject text DEFAULT 'Out of office'::text NOT NULL,
    body_text text DEFAULT ''::text NOT NULL,
    body_html text,
    body_external text,
    body_external_html text,
    external_audience text DEFAULT 'all'::text NOT NULL,
    start_date date,
    end_date date,
    only_contacts boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT vacation_settings_check CHECK (((start_date IS NULL) OR (end_date IS NULL) OR (start_date <= end_date))),
    CONSTRAINT vacation_settings_external_audience_check CHECK ((external_audience = ANY (ARRAY['all'::text, 'contacts'::text, 'none'::text])))
);
--
-- Name: greylist_check(inet, text, text, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.greylist_check(p_client_ip inet, p_sender text, p_recipient text, p_delay_min integer DEFAULT 5) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: greylist_prune(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.greylist_prune() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
  DELETE FROM greylist
  WHERE pass_count = 0 AND first_seen < now() - interval '24 hours';
  DELETE FROM greylist
  WHERE pass_count > 0 AND first_seen < now() - interval '30 days';
END;
$$;
--
-- Name: last_notify_event(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.last_notify_event(p_channel text) RETURNS text
    LANGUAGE sql STABLE
    AS $$
  SELECT (payload::jsonb)->>'event'
  FROM _test_notify_log WHERE channel = p_channel
  ORDER BY seq DESC LIMIT 1;
$$;
--
-- Name: mk_account(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mk_account(p_label text) RETURNS bigint
    LANGUAGE plpgsql
    AS $$
DECLARE
  v_user_id   BIGINT := nextval('mk_account_user_seq');
  v_mb_id     BIGINT := nextval('mk_account_mb_seq');
  v_domain_id BIGINT;
  v_email     TEXT   := p_label || '-' || v_mb_id || '@mk.test';
BEGIN
  INSERT INTO domains (name, is_local) VALUES ('mk.test', TRUE)
    ON CONFLICT (name) DO NOTHING;
  SELECT id INTO v_domain_id FROM domains WHERE name = 'mk.test';

  INSERT INTO users (id, username, domain_id, email, display_name, password_hash)
    VALUES (v_user_id, p_label || '-' || v_user_id, v_domain_id, v_email, p_label, 'x');

  -- mailbox insert fires create_system_tags + folder triggers automatically.
  INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary)
    VALUES (v_mb_id, v_user_id, v_domain_id, v_email, p_label, 'personal', TRUE);

  RETURN v_mb_id;
END;
$$;


--
-- Name: mk_shared_mailbox(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.mk_shared_mailbox(p_label text) RETURNS bigint
    LANGUAGE plpgsql
    AS $$
DECLARE
  v_mb_id     BIGINT := nextval('mk_account_mb_seq');
  v_domain_id BIGINT;
  v_email     TEXT   := p_label || '-' || v_mb_id || '@mk.test';
BEGIN
  INSERT INTO domains (name, is_local) VALUES ('mk.test', TRUE)
    ON CONFLICT (name) DO NOTHING;
  SELECT id INTO v_domain_id FROM domains WHERE name = 'mk.test';

  INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary)
    VALUES (v_mb_id, NULL, v_domain_id, v_email, p_label, 'personal', FALSE);

  RETURN v_mb_id;
END;
$$;
--
-- Name: normalize_list_id(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.normalize_list_id(p_raw text) RETURNS text
    LANGUAGE sql IMMUTABLE
    AS $$
  SELECT CASE
    WHEN p_raw IS NULL THEN NULL
    -- Extract the token inside angle-brackets if present (RFC 2919 §2 form)
    WHEN p_raw ~ '<[^>]+>' THEN lower(trim(substring(p_raw FROM '<([^>]+)>')))
    -- Plain bare value (no angle-brackets) — lowercase and trim
    ELSE lower(trim(p_raw))
  END;
$$;


--
-- Name: FUNCTION normalize_list_id(p_raw text); Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON FUNCTION public.normalize_list_id(p_raw text) IS 'Normalize an RFC 2919 List-Id header value to a bare lowercase domain token. Extracts the <...> token when present; otherwise lowercases and trims. Returns NULL when the input is NULL.  IMMUTABLE — safe to index.';


--
-- Name: notified_on(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notified_on(p_channel text) RETURNS SETOF text
    LANGUAGE sql STABLE
    AS $$
  SELECT payload FROM _test_notify_log WHERE channel = p_channel ORDER BY seq;
$$;
--
-- Name: notify_count(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notify_count(p_channel text) RETURNS integer
    LANGUAGE sql STABLE
    AS $$
  SELECT count(*)::INT FROM _test_notify_log WHERE channel = p_channel;
$$;
--
-- Name: notify_timezone_changed(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.notify_timezone_changed() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify(
        'timezone_changed',
        json_build_object(
            'tzid', COALESCE(NEW.tzid, OLD.tzid),
            'op',   TG_OP
        )::text
    );
    RETURN COALESCE(NEW, OLD);
END;
$$;
--
-- Name: prune_log_tables(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prune_log_tables() RETURNS TABLE(pruned_table text, rows_deleted integer)
    LANGUAGE plpgsql
    AS $$
DECLARE
  v_trace_days INT;
  v_audit_days INT;
  v_auth_event_days INT;
  v_webhook_days INT;
  v_deleted INT;
BEGIN
  -- Read retention settings from system_config
  SELECT (value #>> '{}')::INT INTO v_trace_days
  FROM system_config WHERE key = 'log_retention_message_trace_days';

  SELECT (value #>> '{}')::INT INTO v_audit_days
  FROM system_config WHERE key = 'log_retention_mailbox_audit_days';

  SELECT (value #>> '{}')::INT INTO v_auth_event_days
  FROM system_config WHERE key = 'log_retention_auth_event_days';

  SELECT (value #>> '{}')::INT INTO v_webhook_days
  FROM system_config WHERE key = 'log_retention_webhook_delivery_days';

  -- Prune message_trace if configured (> 0)
  IF v_trace_days IS NOT NULL AND v_trace_days > 0 THEN
    DELETE FROM message_trace WHERE occurred_at < now() - make_interval(days => v_trace_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    pruned_table := 'message_trace';
    rows_deleted := v_deleted;
    RETURN NEXT;
  END IF;

  -- mailbox_audit_log is WORM-protected (trg_audit_append_only): rows are never deleted.
  -- The log_retention_mailbox_audit_days config key is retained for future reference only.

  -- Prune auth_event_log if configured (> 0)
  IF v_auth_event_days IS NOT NULL AND v_auth_event_days > 0 THEN
    DELETE FROM auth_event_log WHERE occurred_at < now() - make_interval(days => v_auth_event_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    pruned_table := 'auth_event_log';
    rows_deleted := v_deleted;
    RETURN NEXT;
  END IF;

  -- Prune webhook_deliveries if configured (> 0)
  IF v_webhook_days IS NOT NULL AND v_webhook_days > 0 THEN
    DELETE FROM webhook_deliveries WHERE created_at < now() - make_interval(days => v_webhook_days);
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    pruned_table := 'webhook_deliveries';
    rows_deleted := v_deleted;
    RETURN NEXT;
  END IF;

  RETURN;
END;
$$;
--
-- Name: prune_saml_assertions(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prune_saml_assertions() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM used_saml_assertions WHERE used_at < now() - INTERVAL '24 hours';
END;
$$;


--
-- Name: prune_ws_subscriptions(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prune_ws_subscriptions() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM ws_subscriptions WHERE last_ping_at < now() - interval '5 minutes';
END;
$$;
--
-- Name: purge_spam_messages(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.purge_spam_messages() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
  v_row    RECORD;
  v_count  INT := 0;
  v_shared INT;
  v_purge_days INT;
  v_mb_purge_days INT;
BEGIN
  SELECT NULLIF((value #>> '{}')::INT, 0) INTO v_purge_days
  FROM system_config WHERE key = 'spam_purge_days';
  IF v_purge_days IS NULL THEN
    v_purge_days := 30;
  END IF;

  FOR v_row IN
    SELECT m.id, m.received_at, m.raw_ref, m.mailbox_id
    FROM messages m
    JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
    JOIN tags t ON t.id = mt.tag_id AND t.name = 'Spam'
    WHERE NOT m.is_deleted
      AND m.received_at < NOW() - (v_purge_days || ' days')::INTERVAL
  LOOP
    BEGIN
      -- Per-mailbox override: NULL = use global, 0 = skip this mailbox
      SELECT COALESCE(mb.spam_purge_days, v_purge_days) INTO v_mb_purge_days
      FROM mailboxes mb WHERE mb.id = v_row.mailbox_id;
      IF v_mb_purge_days = 0 THEN
        CONTINUE;
      END IF;
      IF v_row.received_at > NOW() - (v_mb_purge_days || ' days')::INTERVAL THEN
        CONTINUE;
      END IF;

      -- Deduplication-safe blob cleanup
      SELECT COUNT(*) INTO v_shared
      FROM messages
      WHERE raw_ref = v_row.raw_ref
        AND (id != v_row.id OR received_at != v_row.received_at);

      IF v_shared = 0 THEN
        INSERT INTO orphaned_message_blobs(raw_ref)
        VALUES (v_row.raw_ref)
        ON CONFLICT DO NOTHING;
      END IF;

      DELETE FROM messages
      WHERE id = v_row.id AND received_at = v_row.received_at;

      v_count := v_count + 1;
    EXCEPTION WHEN OTHERS THEN
      -- Held messages raise BZ015 from trg_messages_hold_check; skip.
      CONTINUE;
    END;
  END LOOP;

  RETURN v_count;
END;
$$;
--
-- Name: rate_limit_check(text, integer, integer, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.rate_limit_check(p_key text, p_max_attempts integer DEFAULT 20, p_window_min integer DEFAULT 15, p_block_min integer DEFAULT 60) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
  v_now       TIMESTAMPTZ := now();
  v_window    TIMESTAMPTZ := date_trunc('minute', v_now) - ((extract(minute FROM v_now)::INT % p_window_min) || ' minutes')::INTERVAL;
  v_count     INT;
  v_block     TIMESTAMPTZ;
BEGIN
  -- Check existing block
  SELECT blocked_until INTO v_block FROM rate_limit_counters
  WHERE key = p_key;

  IF v_block IS NOT NULL AND v_block > v_now THEN
    RETURN FALSE;
  END IF;

  -- Reset counter if window expired, otherwise increment
  INSERT INTO rate_limit_counters (key, window_start, count)
  VALUES (p_key, v_window, 1)
  ON CONFLICT (key)
  DO UPDATE SET
    count = CASE WHEN rate_limit_counters.window_start = v_window
                 THEN rate_limit_counters.count + 1 ELSE 1 END,
    window_start = v_window,
    blocked_until = CASE WHEN rate_limit_counters.window_start = v_window
                         THEN rate_limit_counters.blocked_until ELSE NULL END
  RETURNING count INTO v_count;

  -- Apply block if exceeded
  IF v_count > p_max_attempts THEN
    UPDATE rate_limit_counters
    SET blocked_until = v_now + (p_block_min || ' minutes')::INTERVAL
    WHERE key = p_key;
    RETURN FALSE;
  END IF;

  RETURN TRUE;
END;
$$;


--
-- Name: rate_limit_prune(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.rate_limit_prune() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
  DELETE FROM rate_limit_counters
  WHERE window_start < now() - interval '2 hours';
END;
$$;
--
-- Name: reset_sending_quotas(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.reset_sending_quotas() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE mailboxes
    SET sending_sent_today = 0, sending_quota_reset_at = CURRENT_DATE
    WHERE sending_quota_reset_at < CURRENT_DATE;
END;
$$;
--
-- Name: system_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_config (
    key text NOT NULL,
    value jsonb NOT NULL,
    encrypted boolean DEFAULT false NOT NULL,
    description text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by bigint
);


--
-- Name: set_system_config(text, jsonb, boolean, bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.set_system_config(p_key text, p_value jsonb, p_encrypted boolean DEFAULT false, p_updated_by bigint DEFAULT NULL::bigint) RETURNS SETOF public.system_config
    LANGUAGE plpgsql
    AS $$
BEGIN
  RETURN QUERY
    INSERT INTO system_config (key, value, encrypted, updated_by, updated_at)
    VALUES (p_key, p_value, p_encrypted, p_updated_by, now())
    ON CONFLICT (key) DO UPDATE SET
      value      = EXCLUDED.value,
      encrypted  = EXCLUDED.encrypted,
      updated_by = EXCLUDED.updated_by,
      updated_at = now()
    RETURNING *;
END;
$$;
--
-- Name: spam_train_notify(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.spam_train_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_is_spam BOOLEAN;
    v_user_id BIGINT;
    v_message_id BIGINT;
BEGIN
    -- Determine if this is a Spam tag (INSERT) or removal from Spam (DELETE).
    IF TG_OP = 'INSERT' THEN
        v_message_id := NEW.message_id;
        -- Check if the tag being added is the Spam system tag.
        SELECT EXISTS (
            SELECT 1 FROM tags WHERE id = NEW.tag_id
              AND name = 'Spam' AND tag_type = 'system' AND exclusive_group = 'location'
        ) INTO v_is_spam;
        IF NOT v_is_spam THEN
            RETURN NEW;
        END IF;
        -- Get user_id from the mailbox that owns this message.
        SELECT m.user_id INTO v_user_id
        FROM messages msg
        JOIN mailboxes m ON m.id = msg.mailbox_id
        WHERE msg.id = NEW.message_id;
    ELSIF TG_OP = 'DELETE' THEN
        v_message_id := OLD.message_id;
        -- Check if the tag being removed is the Spam system tag.
        SELECT EXISTS (
            SELECT 1 FROM tags WHERE id = OLD.tag_id
              AND name = 'Spam' AND tag_type = 'system' AND exclusive_group = 'location'
        ) INTO v_is_spam;
        IF NOT v_is_spam THEN
            RETURN OLD;
        END IF;
        SELECT m.user_id INTO v_user_id
        FROM messages msg
        JOIN mailboxes m ON m.id = msg.mailbox_id
        WHERE msg.id = OLD.message_id;
    END IF;

    IF v_is_spam AND v_user_id IS NOT NULL THEN
        PERFORM pg_notify('spam_train',
            json_build_object(
                'user_id', v_user_id,
                'message_id', v_message_id,
                'is_spam', (TG_OP = 'INSERT')
            )::text
        );
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$;
--
-- Name: tag_message(bigint, timestamp with time zone, text, bigint, text, boolean, timestamp with time zone, timestamp with time zone); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.tag_message(p_message_id bigint, p_received_at timestamp with time zone, p_tag_name text, p_mailbox_id bigint, p_added_by text DEFAULT 'user'::text, p_is_primary boolean DEFAULT false, p_snooze_until timestamp with time zone DEFAULT NULL::timestamp with time zone, p_scheduled_at timestamp with time zone DEFAULT NULL::timestamp with time zone) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_tag_id BIGINT;
BEGIN
    SELECT id INTO v_tag_id FROM tags
    WHERE mailbox_id = p_mailbox_id AND name = p_tag_name;

    IF v_tag_id IS NULL THEN
        RAISE EXCEPTION 'Tag % not found in mailbox %', p_tag_name, p_mailbox_id
          USING ERRCODE = 'BZ019', HINT = jsonb_build_object('type', 'tag_not_found', 'tag_name', p_tag_name, 'mailbox_id', p_mailbox_id)::TEXT;
    END IF;

    INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary, snooze_until, scheduled_at)
    VALUES (p_message_id, p_received_at, v_tag_id, p_added_by, p_is_primary, p_snooze_until, p_scheduled_at);
END;
$$;
--
-- Name: trg_admin_audit_checksum(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_admin_audit_checksum() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: trg_app_password_limit(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_app_password_limit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF (SELECT COUNT(*) FROM app_passwords
        WHERE user_id = NEW.user_id AND revoked_at IS NULL) >= 10 THEN
        RAISE EXCEPTION 'Maximum 10 app passwords per user'
            USING ERRCODE = 'BZ015',
            HINT = jsonb_build_object('type', 'app_password_limit', 'user_id', NEW.user_id)::TEXT;
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: trg_attachment_deleted(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_attachment_deleted() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  UPDATE blobs SET ref_count = ref_count - 1 WHERE sha256 = OLD.blob_sha256;
  RETURN OLD;
END;
$$;


--
-- Name: trg_audit_append_only(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_audit_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'Cannot UPDATE or DELETE audit records'
      USING ERRCODE = 'BZ017', HINT = '{"type":"audit_append_only"}';
    RETURN NULL;
END;
$$;


--
-- Name: trg_audit_log_immutable(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_audit_log_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: cannot UPDATE or DELETE';
END;
$$;


--
-- Name: trg_audit_log_notify(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_audit_log_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('audit:' || COALESCE(NEW.user_id::TEXT, 'anon'), json_build_object(
        'event_type', NEW.event_type,
        'source_ip', NEW.source_ip,
        'occurred_at', NEW.occurred_at,
        'metadata', NEW.metadata
    )::text);
    RETURN NEW;
END;
$$;


--
-- Name: trg_auth_methods_notify(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_auth_methods_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  PERFORM pg_notify('config_changed',
    json_build_object('key', 'auth_methods', 'slug', COALESCE(NEW.slug, OLD.slug),
                      'enabled', COALESCE(NEW.enabled, OLD.enabled))::text);
  RETURN COALESCE(NEW, OLD);
END;
$$;


--
-- Name: trg_blob_refcount_zero(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_blob_refcount_zero() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.ref_count = 0 THEN
    INSERT INTO blob_cleanup_queue (blob_sha256, scheduled_at)
    VALUES (NEW.sha256, now())
    ON CONFLICT (blob_sha256) DO UPDATE SET scheduled_at = now();
  END IF;
  RETURN NEW;
END;
$$;


--
-- Name: trg_crash_events_immutable(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_crash_events_immutable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.admin_notified IS DISTINCT FROM OLD.admin_notified THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'crash_events is append-only except for admin_notified'
    USING ERRCODE = 'BZ016', HINT = '{"type":"append_only","table":"crash_events"}';
END;
$$;


--
-- Name: trg_feature_notify(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_feature_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  PERFORM pg_notify('config_changed',
    json_build_object('key', NEW.key, 'enabled', NEW.enabled)::text);
  RETURN NEW;
END;
$$;


--
-- Name: trg_mailbox_after_insert(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_mailbox_after_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  PERFORM create_system_folders(NEW.id);
  RETURN NEW;
END;
$$;


--
-- Name: trg_mailbox_primary_enforce(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_mailbox_primary_enforce() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: trg_mailbox_quota_defaults(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_mailbox_quota_defaults() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_default_quota  BIGINT;
    v_default_send   INT;
BEGIN
    SELECT (value #>> '{}')::BIGINT INTO v_default_quota
    FROM system_config WHERE key = 'default_quota_bytes';
    SELECT (value #>> '{}')::INT INTO v_default_send
    FROM system_config WHERE key = 'default_sending_quota_day';

    UPDATE mailboxes SET
        -- Only override the storage default when the caller left it untouched
        -- (= the column's own DEFAULT). An explicit value is preserved.
        quota_bytes       = CASE WHEN NEW.quota_bytes = 53687091200
                                 THEN COALESCE(v_default_quota, 53687091200)
                                 ELSE NEW.quota_bytes END,
        sending_quota_day = CASE WHEN NEW.sending_quota_day = 500
                                 THEN COALESCE(v_default_send, 500)
                                 ELSE NEW.sending_quota_day END
    WHERE id = NEW.id;
    RETURN NULL;
END;
$$;


--
-- Name: trg_mailbox_tag_after_insert(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_mailbox_tag_after_insert() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM create_system_tags(NEW.id);
    RETURN NEW;
END;
$$;


--
-- Name: trg_message_tags_counters(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_message_tags_counters() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_is_read BOOL;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT is_read INTO v_is_read FROM messages
        WHERE id = NEW.message_id AND received_at = NEW.received_at;

        UPDATE tags SET
            total_count  = total_count + 1,
            unread_count = unread_count + CASE WHEN v_is_read THEN 0 ELSE 1 END,
            jmap_state   = jmap_state + 1
        WHERE id = NEW.tag_id;

    ELSIF TG_OP = 'DELETE' THEN
        SELECT is_read INTO v_is_read FROM messages
        WHERE id = OLD.message_id AND received_at = OLD.received_at;

        UPDATE tags SET
            total_count  = GREATEST(0, total_count - 1),
            unread_count = GREATEST(0, unread_count - CASE WHEN v_is_read THEN 0 ELSE 1 END),
            jmap_state   = jmap_state + 1
        WHERE id = OLD.tag_id;
    END IF;

    RETURN NULL;
END;
$$;


--
-- Name: trg_message_tags_exclusive(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_message_tags_exclusive() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_group TEXT;
BEGIN
    SELECT t.exclusive_group INTO v_group
    FROM tags t WHERE t.id = NEW.tag_id;

    IF v_group IS NOT NULL THEN
        DELETE FROM message_tags mt
        USING tags t
        WHERE mt.message_id = NEW.message_id
          AND mt.received_at = NEW.received_at
          AND mt.tag_id = t.id
          AND t.exclusive_group = v_group
          AND mt.tag_id != NEW.tag_id;
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: trg_message_tags_primary_sync(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_message_tags_primary_sync() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.is_primary THEN
        UPDATE messages SET folder_id = NEW.tag_id
        WHERE id = NEW.message_id AND received_at = NEW.received_at;
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: trg_messages_hold_check(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_messages_hold_check() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF OLD.held THEN
    RAISE EXCEPTION 'Cannot delete message % — mailbox is under litigation hold', OLD.id
      USING ERRCODE = 'BZ015', HINT = jsonb_build_object('type', 'litigation_hold', 'message_id', OLD.id)::TEXT;
  END IF;
  RETURN OLD;
END;
$$;


--
-- Name: trg_messages_tsv(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_messages_tsv() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF current_setting('app.skip_fts', true) = 'true' THEN
    RETURN NEW;
  END IF;
  NEW.body_tsv    := to_tsvector('simple', coalesce(NEW.body_text, ''));
  NEW.subject_tsv := to_tsvector('simple', coalesce(NEW.subject, ''));
  NEW.from_tsv    := to_tsvector('simple',
                       coalesce(NEW.from_addr, '') || ' ' || coalesce(NEW.from_name, ''));
  RETURN NEW;
END;
$$;


--
-- Name: trg_oauth_revoke_notify(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_oauth_revoke_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.revoked_at IS NOT NULL AND (OLD.revoked_at IS NULL OR OLD.revoked_at IS DISTINCT FROM NEW.revoked_at) THEN
        PERFORM pg_notify('token_revoked:' || NEW.user_id, json_build_object(
            'token_type', NEW.token_type,
            'revoked_at', NEW.revoked_at
        )::text);
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: trg_outbound_queue_dsn(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_outbound_queue_dsn() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.status = 'bounced' AND (OLD.status IS NULL OR OLD.status != 'bounced') THEN
        PERFORM enqueue_scheduled_action(
            'dsn',
            now(),
            jsonb_build_object('queue_id', NEW.id),
            NEW.mailbox_id,            -- owner (may be NULL; handler defer-resolves the sender)
            'dsn:' || NEW.id::TEXT     -- idempotency: a reclaim re-enqueue is a no-op
        );
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: trg_outbound_queue_status_guard(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_outbound_queue_status_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF OLD.status IN ('delivered', 'bounced') AND NEW.status != OLD.status THEN
    RAISE EXCEPTION 'Cannot change status of % item from % to %', OLD.id, OLD.status, NEW.status
      USING ERRCODE = 'BZ012', HINT = jsonb_build_object('type', 'immutable_status', 'id', OLD.id, 'from_status', OLD.status, 'to_status', NEW.status)::TEXT;
  END IF;
  RETURN NEW;
END;
$$;


--
-- Name: trg_read_receipt_never_guard(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_read_receipt_never_guard() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  v_mailbox_id BIGINT;
  v_user_id    BIGINT;
  v_policy     TEXT;
BEGIN
  -- message → mailbox (the row carries message_id only; no mailbox_id column).
  SELECT m.mailbox_id INTO v_mailbox_id FROM messages m WHERE m.id = NEW.message_id;
  IF v_mailbox_id IS NULL THEN
    RETURN NEW;  -- unresolvable message → fail-open (reducer is the primary gate).
  END IF;

  -- mailbox → owning user via the account_scope() seam (ADR-003). NULL for a
  -- shared/resource mailbox → no policy row → get_read_receipt_policy falls back
  -- to 'ask' (≠ 'never'), so the insert is allowed (fail-open).
  SELECT s.user_id INTO v_user_id FROM account_scope(v_mailbox_id) s;

  v_policy := get_read_receipt_policy(v_user_id);
  IF v_policy = 'never' THEN
    RAISE EXCEPTION 'Read receipt forbidden by recipient policy (never)'
      USING ERRCODE = 'BZ073',
            HINT = jsonb_build_object(
              'type', 'read_receipt_never',
              'message_id', NEW.message_id,
              'mailbox_id', v_mailbox_id
            )::TEXT;
  END IF;

  RETURN NEW;  -- always / ask (and any unresolvable case) → allow.
END;
$$;


--
-- Name: trg_rules_notify(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_rules_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    PERFORM pg_notify('rules_changed', json_build_object(
      'op', 'delete', 'mailbox_id', OLD.mailbox_id, 'rule_id', OLD.id)::text);
  ELSE
    PERFORM pg_notify('rules_changed', json_build_object(
      'op', lower(TG_OP), 'mailbox_id', NEW.mailbox_id, 'rule_id', NEW.id)::text);
  END IF;
  RETURN COALESCE(NEW, OLD);
END;
$$;


--
-- Name: trg_system_config_notify(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.trg_system_config_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  PERFORM pg_notify('config_changed',
    json_build_object('key', NEW.key, 'encrypted', NEW.encrypted)::text);
  RETURN NEW;
END;
$$;
--
-- Name: verify_audit_chain(bigint, bigint); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.verify_audit_chain(p_from_id bigint DEFAULT NULL::bigint, p_to_id bigint DEFAULT NULL::bigint) RETURNS TABLE(row_id bigint, valid boolean, occurred_at timestamp with time zone, action text)
    LANGUAGE plpgsql
    AS $$
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
$$;


--
-- Name: _test_notify_log_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public._test_notify_log_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: _test_notify_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public._test_notify_log (
    channel text NOT NULL,
    payload text NOT NULL,
    seq bigint DEFAULT nextval('public._test_notify_log_seq'::regclass) NOT NULL
);


--
-- Name: addressbooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.addressbooks (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    name text NOT NULL,
    description text,
    is_default boolean DEFAULT false NOT NULL,
    is_shared boolean DEFAULT false NOT NULL,
    jmap_state bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: addressbooks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.addressbooks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: addressbooks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.addressbooks_id_seq OWNED BY public.addressbooks.id;


--
-- Name: admin_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_audit_log (
    id bigint NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    user_id bigint,
    ip inet,
    action text NOT NULL,
    target_type text,
    target_id bigint,
    before_state jsonb,
    after_state jsonb,
    notes text
);


--
-- Name: admin_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.admin_audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: admin_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.admin_audit_log_id_seq OWNED BY public.admin_audit_log.id;


--
-- Name: admin_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_permissions (
    permission_key text NOT NULL,
    category text NOT NULL,
    description text NOT NULL,
    is_sensitive boolean DEFAULT false
);


--
-- Name: admin_role_assignments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_role_assignments (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    role_group_id bigint NOT NULL,
    domain_override bigint,
    granted_by bigint NOT NULL,
    granted_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone
);


--
-- Name: admin_role_assignments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.admin_role_assignments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: admin_role_assignments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.admin_role_assignments_id_seq OWNED BY public.admin_role_assignments.id;


--
-- Name: admin_role_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_role_groups (
    id bigint NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    permissions text[] DEFAULT '{}'::text[] NOT NULL,
    domain_scope bigint,
    is_builtin boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: admin_role_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.admin_role_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: admin_role_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.admin_role_groups_id_seq OWNED BY public.admin_role_groups.id;


--
-- Name: aliases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.aliases (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    email text NOT NULL,
    domain_id bigint NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    display_name text,
    signature text,
    reply_to text,
    bcc_send text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT aliases_email_check CHECK ((email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'::text))
);


--
-- Name: aliases_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.aliases_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: aliases_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.aliases_id_seq OWNED BY public.aliases.id;


--
-- Name: messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.messages (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    folder_id bigint NOT NULL,
    message_id text NOT NULL,
    subject text,
    from_addr text NOT NULL,
    from_name text,
    to_addrs jsonb DEFAULT '[]'::jsonb NOT NULL,
    cc_addrs jsonb DEFAULT '[]'::jsonb NOT NULL,
    bcc_addrs jsonb DEFAULT '[]'::jsonb NOT NULL,
    reply_to text,
    in_reply_to text,
    references_hdr text,
    body_text text,
    body_html text,
    body_tsv tsvector,
    subject_tsv tsvector,
    from_tsv tsvector,
    size_bytes bigint DEFAULT 0 NOT NULL,
    has_attachments boolean DEFAULT false NOT NULL,
    is_read boolean DEFAULT false NOT NULL,
    is_flagged boolean DEFAULT false NOT NULL,
    is_answered boolean DEFAULT false NOT NULL,
    is_draft boolean DEFAULT false NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    categories text[] DEFAULT '{}'::text[] NOT NULL,
    thread_id text NOT NULL,
    imap_uid bigint,
    imap_modseq bigint,
    spam_score real,
    spam_headers jsonb,
    spf_result text,
    dkim_result text,
    dmarc_result text,
    raw_ref text NOT NULL,
    held boolean DEFAULT false NOT NULL,
    sent_at timestamp with time zone,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    dkim_selector text,
    dkim_domain text,
    crypto_type text,
    smime_encrypt boolean DEFAULT false NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    sensitivity text,
    read_receipt_requested boolean DEFAULT false NOT NULL,
    delivery_receipt_requested boolean DEFAULT false NOT NULL,
    vote_options jsonb,
    scheduled_at timestamp with time zone,
    deleted_at timestamp with time zone,
    pinned_at timestamp with time zone,
    vote_response text,
    is_external boolean DEFAULT false NOT NULL,
    sender_display_name text,
    is_name_spoof boolean DEFAULT false NOT NULL,
    is_first_time boolean DEFAULT true NOT NULL,
    list_unsubscribe text,
    list_id text,
    flag_due_at timestamp with time zone,
    flag_reminder_at timestamp with time zone,
    CONSTRAINT messages_dkim_result_check CHECK ((dkim_result = ANY (ARRAY['pass'::text, 'fail'::text, 'none'::text, 'policy'::text, 'neutral'::text, 'temperror'::text, 'permerror'::text]))),
    CONSTRAINT messages_dmarc_result_check CHECK ((dmarc_result = ANY (ARRAY['pass'::text, 'fail'::text, 'none'::text, 'temperror'::text, 'permerror'::text]))),
    CONSTRAINT messages_priority_check CHECK ((priority = ANY (ARRAY['-1'::integer, 0, 1]))),
    CONSTRAINT messages_sensitivity_check CHECK ((sensitivity = ANY (ARRAY['normal'::text, 'personal'::text, 'private'::text, 'confidential'::text]))),
    CONSTRAINT messages_spf_result_check CHECK ((spf_result = ANY (ARRAY['pass'::text, 'fail'::text, 'softfail'::text, 'neutral'::text, 'none'::text, 'permerror'::text, 'temperror'::text])))
)
PARTITION BY RANGE (received_at);


--
-- Name: COLUMN messages.list_unsubscribe; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.messages.list_unsubscribe IS 'RFC 8058 List-Unsubscribe header value. Non-NULL means this message is a newsletter/bulk email eligible for one-click unsubscribe.';


--
-- Name: COLUMN messages.list_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.messages.list_id IS 'Normalized RFC 2919 List-Id header value (bare domain token, lowercase). Non-NULL ⇒ message belongs to a newsletter bundle groupable by this id. Populated at delivery time by deliver() and import_message() via normalize_list_id(). NULL for all regular (non-newsletter) messages.';


--
-- Name: antiphish_contact_graph; Type: MATERIALIZED VIEW; Schema: public; Owner: -
--

CREATE MATERIALIZED VIEW public.antiphish_contact_graph AS
 SELECT mailbox_id,
    from_addr AS sender_email,
    from_name AS sender_name,
    max(received_at) AS last_seen_at,
    count(*) AS message_count
   FROM public.messages m
  WHERE ((from_name IS NOT NULL) AND (from_name <> ''::text) AND (from_addr IS NOT NULL) AND (from_addr <> ''::text))
  GROUP BY mailbox_id, from_addr, from_name
  WITH NO DATA;


--
-- Name: app_passwords; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.app_passwords (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    name text NOT NULL,
    label text,
    token_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone
);


--
-- Name: app_passwords_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.app_passwords_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: app_passwords_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.app_passwords_id_seq OWNED BY public.app_passwords.id;


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id bigint NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    user_id bigint,
    source_ip inet,
    geo_country text,
    protocol text,
    event_type text NOT NULL,
    device_id text,
    session_id text,
    metadata jsonb
)
PARTITION BY RANGE (occurred_at);


--
-- Name: audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_log_id_seq OWNED BY public.audit_log.id;


--
-- Name: audit_log_2026_05; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log_2026_05 (
    id bigint DEFAULT nextval('public.audit_log_id_seq'::regclass) NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    user_id bigint,
    source_ip inet,
    geo_country text,
    protocol text,
    event_type text NOT NULL,
    device_id text,
    session_id text,
    metadata jsonb
);


--
-- Name: auth_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_attempts (
    id bigint NOT NULL,
    source_ip inet NOT NULL,
    target_username text NOT NULL,
    protocol text DEFAULT 'http'::text NOT NULL,
    outcome text NOT NULL,
    failure_reason text,
    geo_country text,
    device_fingerprint text,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT auth_attempts_outcome_check CHECK ((outcome = ANY (ARRAY['success'::text, 'failure'::text, 'captcha_needed'::text, 'threat_blocked'::text, 'geo_blocked'::text, 'lockout'::text, 'spray_detected'::text, 'rate_limited'::text])))
)
PARTITION BY RANGE (occurred_at);


--
-- Name: auth_attempts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.auth_attempts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: auth_attempts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.auth_attempts_id_seq OWNED BY public.auth_attempts.id;


--
-- Name: auth_attempts_2026_05; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_attempts_2026_05 (
    id bigint DEFAULT nextval('public.auth_attempts_id_seq'::regclass) NOT NULL,
    source_ip inet NOT NULL,
    target_username text NOT NULL,
    protocol text DEFAULT 'http'::text NOT NULL,
    outcome text NOT NULL,
    failure_reason text,
    geo_country text,
    device_fingerprint text,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT auth_attempts_outcome_check CHECK ((outcome = ANY (ARRAY['success'::text, 'failure'::text, 'captcha_needed'::text, 'threat_blocked'::text, 'geo_blocked'::text, 'lockout'::text, 'spray_detected'::text, 'rate_limited'::text])))
);


--
-- Name: auth_event_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_event_log (
    id bigint NOT NULL,
    user_id bigint,
    event text NOT NULL,
    provider text NOT NULL,
    email text,
    ip_address inet,
    details jsonb,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT auth_event_log_event_check CHECK ((event = ANY (ARRAY['login'::text, 'login_failed'::text]))),
    CONSTRAINT auth_event_log_provider_check CHECK ((provider = ANY (ARRAY['bcrypt'::text, 'app_password'::text, 'kerberos'::text, 'jwt'::text, 'ldap'::text, 'webauthn'::text, 'basic'::text])))
);


--
-- Name: auth_event_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.auth_event_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: auth_event_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.auth_event_log_id_seq OWNED BY public.auth_event_log.id;


--
-- Name: auth_lockouts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_lockouts (
    lockout_key text NOT NULL,
    failed_count integer DEFAULT 1 NOT NULL,
    locked_until timestamp with time zone NOT NULL,
    escalation_level integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: auth_methods; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_methods (
    id bigint NOT NULL,
    slug text NOT NULL,
    name text NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    config_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: auth_methods_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.auth_methods_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: auth_methods_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.auth_methods_id_seq OWNED BY public.auth_methods.id;


--
-- Name: blob_cleanup_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.blob_cleanup_queue (
    blob_sha256 text NOT NULL,
    scheduled_at timestamp with time zone DEFAULT now() NOT NULL,
    delay_minutes integer DEFAULT 5 NOT NULL
);


--
-- Name: blobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.blobs (
    sha256 text NOT NULL,
    minio_ref text NOT NULL,
    size_bytes bigint NOT NULL,
    content_type text,
    ref_count integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT blobs_ref_count_check CHECK ((ref_count >= 0))
);


--
-- Name: calendar_acls; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_acls (
    calendar_id bigint NOT NULL,
    user_id bigint NOT NULL,
    permission text NOT NULL,
    CONSTRAINT calendar_acls_permission_check CHECK ((permission = ANY (ARRAY['freebusy'::text, 'read'::text, 'write'::text, 'admin'::text])))
);


--
-- Name: calendar_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendar_events (
    id bigint NOT NULL,
    calendar_id bigint NOT NULL,
    uid text NOT NULL,
    component_type text DEFAULT 'VEVENT'::text NOT NULL,
    title text NOT NULL,
    description text,
    location text,
    url text,
    start_at timestamp with time zone,
    end_at timestamp with time zone,
    all_day boolean DEFAULT false NOT NULL,
    timezone text,
    priority integer,
    percent_complete integer,
    completed_at timestamp with time zone,
    due_at timestamp with time zone,
    rrule text,
    rdate timestamp with time zone[],
    exdate timestamp with time zone[],
    recurrence_id timestamp with time zone,
    status text DEFAULT 'confirmed'::text NOT NULL,
    transp text DEFAULT 'OPAQUE'::text NOT NULL,
    is_meeting boolean DEFAULT false NOT NULL,
    meeting_url text,
    organizer_email text,
    organizer_name text,
    sequence integer DEFAULT 0 NOT NULL,
    valarm jsonb,
    jmap_state bigint DEFAULT 0 NOT NULL,
    etag text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    parent_event_uid text,
    recurrence_override timestamp with time zone,
    CONSTRAINT calendar_events_component_type_check CHECK ((component_type = ANY (ARRAY['VEVENT'::text, 'VTODO'::text, 'VJOURNAL'::text]))),
    CONSTRAINT calendar_events_percent_complete_check CHECK (((percent_complete >= 0) AND (percent_complete <= 100))),
    CONSTRAINT calendar_events_priority_check CHECK (((priority >= 0) AND (priority <= 9))),
    CONSTRAINT calendar_events_status_check CHECK ((status = ANY (ARRAY['confirmed'::text, 'tentative'::text, 'cancelled'::text, 'needs-action'::text, 'in-progress'::text, 'completed'::text]))),
    CONSTRAINT calendar_events_transp_check CHECK ((transp = ANY (ARRAY['OPAQUE'::text, 'TRANSPARENT'::text])))
);


--
-- Name: calendar_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.calendar_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: calendar_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.calendar_events_id_seq OWNED BY public.calendar_events.id;


--
-- Name: calendars; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.calendars (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    name text NOT NULL,
    color text,
    description text,
    timezone text DEFAULT 'UTC'::text NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    is_shared boolean DEFAULT false NOT NULL,
    ical_feed_url text,
    jmap_state bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    resource_type text DEFAULT 'personal'::text,
    booking_policy text DEFAULT 'auto-accept'::text,
    capacity integer,
    CONSTRAINT calendars_booking_policy_check CHECK ((booking_policy = ANY (ARRAY['auto-accept'::text, 'manual'::text, 'decline-conflict'::text]))),
    CONSTRAINT calendars_resource_type_check CHECK ((resource_type = ANY (ARRAY['personal'::text, 'room'::text, 'equipment'::text])))
);


--
-- Name: calendars_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.calendars_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: calendars_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.calendars_id_seq OWNED BY public.calendars.id;


--
-- Name: common_passwords; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.common_passwords (
    id bigint NOT NULL,
    password_hash bytea NOT NULL
);


--
-- Name: common_passwords_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.common_passwords_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: common_passwords_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.common_passwords_id_seq OWNED BY public.common_passwords.id;


--
-- Name: conditional_access_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.conditional_access_policies (
    id bigint NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    scope_type text DEFAULT 'global'::text NOT NULL,
    scope_target text DEFAULT ''::text NOT NULL,
    conditions jsonb DEFAULT '{}'::jsonb NOT NULL,
    actions jsonb DEFAULT '{"action": "allow"}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT conditional_access_policies_scope_type_check CHECK ((scope_type = ANY (ARRAY['global'::text, 'user'::text, 'group'::text])))
);


--
-- Name: conditional_access_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.conditional_access_policies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: conditional_access_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.conditional_access_policies_id_seq OWNED BY public.conditional_access_policies.id;


--
-- Name: contact_group_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.contact_group_members (
    id bigint NOT NULL,
    group_id bigint NOT NULL,
    contact_id bigint,
    email text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT cgm_one_target CHECK ((num_nonnulls(contact_id, email) = 1))
);


--
-- Name: contact_group_members_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.contact_group_members_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: contact_group_members_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.contact_group_members_id_seq OWNED BY public.contact_group_members.id;


--
-- Name: contact_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.contact_groups (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    name text NOT NULL,
    jmap_state bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: contact_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.contact_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: contact_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.contact_groups_id_seq OWNED BY public.contact_groups.id;


--
-- Name: contacts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.contacts (
    id bigint NOT NULL,
    addressbook_id bigint NOT NULL,
    vcard_uid text NOT NULL,
    display_name text NOT NULL,
    first_name text,
    last_name text,
    company text,
    job_title text,
    department text,
    emails jsonb DEFAULT '[]'::jsonb NOT NULL,
    phones jsonb DEFAULT '[]'::jsonb NOT NULL,
    addresses jsonb DEFAULT '[]'::jsonb NOT NULL,
    urls jsonb DEFAULT '[]'::jsonb NOT NULL,
    instant_msgs jsonb DEFAULT '[]'::jsonb NOT NULL,
    notes text,
    birthday date,
    anniversary date,
    avatar_sha256 text,
    categories text[] DEFAULT '{}'::text[] NOT NULL,
    etag text DEFAULT ''::text NOT NULL,
    jmap_state bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT contacts_emails_check CHECK (((emails IS NULL) OR (jsonb_typeof(emails) = 'array'::text)))
);


--
-- Name: contacts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.contacts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: contacts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.contacts_id_seq OWNED BY public.contacts.id;


--
-- Name: crash_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.crash_events (
    id bigint NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    component text NOT NULL,
    severity text NOT NULL,
    description text NOT NULL,
    previous_state jsonb,
    recovery_action text,
    recovered_at timestamp with time zone,
    admin_notified boolean DEFAULT false NOT NULL,
    notes text,
    CONSTRAINT crash_events_severity_check CHECK ((severity = ANY (ARRAY['warn'::text, 'error'::text, 'fatal'::text])))
);


--
-- Name: crash_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.crash_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: crash_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.crash_events_id_seq OWNED BY public.crash_events.id;


--
-- Name: cron_run_log; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.cron_run_log (
    id bigint NOT NULL,
    task_name text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    duration_ms integer,
    status text NOT NULL,
    error_message text,
    sql_text text,
    CONSTRAINT cron_run_log_status_check CHECK ((status = ANY (ARRAY['success'::text, 'error'::text, 'panic'::text, 'timeout'::text])))
);


--
-- Name: cron_run_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE UNLOGGED SEQUENCE public.cron_run_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cron_run_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cron_run_log_id_seq OWNED BY public.cron_run_log.id;


--
-- Name: departments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.departments (
    id bigint NOT NULL,
    name text NOT NULL,
    parent_id bigint,
    path text NOT NULL,
    ldap_ou text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT departments_name_check CHECK ((name <> ''::text))
);


--
-- Name: departments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.departments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: departments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.departments_id_seq OWNED BY public.departments.id;


--
-- Name: deployment_steps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.deployment_steps (
    step_name text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    output text,
    error text,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    CONSTRAINT deployment_steps_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'done'::text, 'failed'::text])))
);


--
-- Name: device_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_events (
    id bigint NOT NULL,
    device_id bigint,
    event_type text NOT NULL,
    event_data jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    severity text DEFAULT 'info'::text,
    details jsonb DEFAULT '{}'::jsonb,
    occurred_at timestamp with time zone DEFAULT now()
);


--
-- Name: device_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.device_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: device_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.device_events_id_seq OWNED BY public.device_events.id;


--
-- Name: device_policy; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_policy (
    id bigint NOT NULL,
    device_id bigint,
    policy_key text NOT NULL,
    policy_value text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    applied_at timestamp with time zone
);


--
-- Name: device_policy_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_policy_groups (
    id bigint NOT NULL,
    group_type text NOT NULL,
    group_id bigint NOT NULL,
    policy_key text NOT NULL,
    policy_value text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT device_policy_groups_group_type_check CHECK ((group_type = ANY (ARRAY['department'::text, 'role'::text, 'domain'::text, 'security_group'::text])))
);


--
-- Name: device_policy_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.device_policy_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: device_policy_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.device_policy_groups_id_seq OWNED BY public.device_policy_groups.id;


--
-- Name: device_policy_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.device_policy_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: device_policy_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.device_policy_id_seq OWNED BY public.device_policy.id;


--
-- Name: device_registry; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_registry (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    device_hash text NOT NULL,
    user_agent text,
    ip_prefix text,
    country text,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    auth_count integer DEFAULT 1 NOT NULL,
    flagged boolean DEFAULT false NOT NULL,
    trust_tier text DEFAULT 'unknown'::text NOT NULL,
    device_fingerprint uuid,
    device_secret text,
    CONSTRAINT device_registry_trust_tier_check CHECK ((trust_tier = ANY (ARRAY['managed'::text, 'known'::text, 'unknown'::text, 'risky'::text])))
);


--
-- Name: device_registry_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.device_registry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: device_registry_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.device_registry_id_seq OWNED BY public.device_registry.id;


--
-- Name: device_telemetry; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_telemetry (
    id bigint NOT NULL,
    device_id bigint NOT NULL,
    app_version text,
    os_version text,
    crash_count integer DEFAULT 0 NOT NULL,
    uptime_hours integer,
    feature_usage jsonb DEFAULT '{}'::jsonb NOT NULL,
    reported_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: device_telemetry_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.device_telemetry_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: device_telemetry_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.device_telemetry_id_seq OWNED BY public.device_telemetry.id;


--
-- Name: devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.devices (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    device_name text,
    platform text,
    os_version text,
    app_version text,
    fingerprint text NOT NULL,
    hmac_secret text NOT NULL,
    compliance_status text DEFAULT 'unknown'::text NOT NULL,
    wipe_requested boolean DEFAULT false NOT NULL,
    last_seen timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    push_token_enc bytea,
    push_provider text,
    device_public_key bytea,
    push_enabled boolean DEFAULT true NOT NULL,
    revoked_at timestamp with time zone
);


--
-- Name: devices_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.devices_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: devices_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.devices_id_seq OWNED BY public.devices.id;


--
-- Name: directory_connectors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.directory_connectors (
    id bigint NOT NULL,
    connector_type text NOT NULL,
    name text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    attribute_map jsonb DEFAULT '{}'::jsonb NOT NULL,
    sync_cursor text,
    sync_interval_s integer DEFAULT 900 NOT NULL,
    last_sync_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT directory_connectors_connector_type_check CHECK ((connector_type = ANY (ARRAY['ad'::text, 'local'::text, 'ldap'::text])))
);


--
-- Name: directory_connectors_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.directory_connectors_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: directory_connectors_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.directory_connectors_id_seq OWNED BY public.directory_connectors.id;


--
-- Name: distribution_group_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.distribution_group_members (
    group_id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    source text DEFAULT 'manual'::text NOT NULL,
    CONSTRAINT distribution_group_members_source_check CHECK ((source = ANY (ARRAY['manual'::text, 'sso'::text, 'scim'::text])))
);


--
-- Name: distribution_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.distribution_groups (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    is_dynamic boolean DEFAULT false NOT NULL,
    dynamic_filter jsonb,
    moderated boolean DEFAULT false NOT NULL,
    moderator_mailbox_id bigint,
    allow_external_senders boolean DEFAULT false NOT NULL,
    delivery_report_to_owner boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    scim_external_id text
);


--
-- Name: distribution_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.distribution_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: distribution_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.distribution_groups_id_seq OWNED BY public.distribution_groups.id;


--
-- Name: dlp_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dlp_policies (
    id bigint NOT NULL,
    domain_id bigint,
    name text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    action text DEFAULT 'block'::text NOT NULL,
    regex_patterns text[] DEFAULT '{}'::text[] NOT NULL,
    keywords text[] DEFAULT '{}'::text[] NOT NULL,
    min_confidence real DEFAULT 0.7 NOT NULL,
    blocked_file_types text[] DEFAULT '{}'::text[] NOT NULL,
    max_attachment_size bigint DEFAULT 0 NOT NULL,
    applies_to_all boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_pattern boolean DEFAULT false NOT NULL,
    CONSTRAINT dlp_policies_action_check CHECK ((action = ANY (ARRAY['block'::text, 'warn'::text, 'quarantine'::text, 'notify_admin'::text]))),
    CONSTRAINT dlp_policies_min_confidence_check CHECK (((min_confidence >= (0)::double precision) AND (min_confidence <= (1)::double precision)))
);


--
-- Name: dlp_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dlp_policies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dlp_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dlp_policies_id_seq OWNED BY public.dlp_policies.id;


--
-- Name: dlp_policy_targets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dlp_policy_targets (
    policy_id bigint NOT NULL,
    mailbox_id bigint NOT NULL
);


--
-- Name: dlp_violations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dlp_violations (
    id bigint NOT NULL,
    policy_id bigint NOT NULL,
    message_id bigint,
    mailbox_id bigint NOT NULL,
    violation_type text NOT NULL,
    matched_text text,
    action_taken text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: dlp_violations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dlp_violations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dlp_violations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dlp_violations_id_seq OWNED BY public.dlp_violations.id;


--
-- Name: dmarc_forensic_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dmarc_forensic_reports (
    id bigint NOT NULL,
    message_id bigint,
    from_domain text NOT NULL,
    report_uri text NOT NULL,
    subject text,
    from_addr text,
    spf_result text,
    dkim_result text,
    dmarc_result text,
    raw_body text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: dmarc_forensic_reports_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dmarc_forensic_reports_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dmarc_forensic_reports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dmarc_forensic_reports_id_seq OWNED BY public.dmarc_forensic_reports.id;


--
-- Name: dmarc_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dmarc_reports (
    id bigint NOT NULL,
    domain text NOT NULL,
    report_uri text NOT NULL,
    begin_time timestamp with time zone NOT NULL,
    end_time timestamp with time zone NOT NULL,
    total_count integer DEFAULT 0 NOT NULL,
    count_none integer DEFAULT 0 NOT NULL,
    count_pass integer DEFAULT 0 NOT NULL,
    count_fail integer DEFAULT 0 NOT NULL,
    count_temperror integer DEFAULT 0 NOT NULL,
    count_permperror integer DEFAULT 0 NOT NULL,
    policy_domain text,
    policy_pct integer DEFAULT 100 NOT NULL,
    spf_pass_count integer DEFAULT 0 NOT NULL,
    dkim_pass_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: dmarc_reports_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dmarc_reports_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dmarc_reports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dmarc_reports_id_seq OWNED BY public.dmarc_reports.id;


--
-- Name: domain_signing_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.domain_signing_keys (
    id bigint NOT NULL,
    domain_id bigint NOT NULL,
    selector text NOT NULL,
    algorithm text DEFAULT 'rsa-sha256'::text NOT NULL,
    public_key_pem text NOT NULL,
    private_key_pem text NOT NULL,
    key_size integer DEFAULT 2048 NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    rotated_at timestamp with time zone,
    CONSTRAINT domain_signing_keys_algorithm_check CHECK ((algorithm = ANY (ARRAY['rsa-sha256'::text, 'ed25519-sha256'::text])))
);


--
-- Name: domain_signing_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.domain_signing_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: domain_signing_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.domain_signing_keys_id_seq OWNED BY public.domain_signing_keys.id;


--
-- Name: domains; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.domains (
    id bigint NOT NULL,
    name text NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    is_local boolean DEFAULT true NOT NULL,
    catch_all_mailbox_id bigint,
    dkim_selector text,
    dkim_private_key_enc text,
    dkim_key_expires_at timestamp with time zone,
    spf_record text,
    dmarc_policy text DEFAULT 'none'::text NOT NULL,
    dmarc_rua text,
    dmarc_ruf text,
    dmarc_pct integer DEFAULT 100 NOT NULL,
    mta_sts_policy text DEFAULT 'none'::text NOT NULL,
    max_message_bytes bigint DEFAULT 52428800 NOT NULL,
    quota_bytes bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    sandbox_enabled boolean DEFAULT false NOT NULL,
    sandbox_action text DEFAULT 'quarantine'::text NOT NULL,
    sandbox_file_types text DEFAULT '*'::text NOT NULL,
    CONSTRAINT domains_dmarc_policy_check CHECK ((dmarc_policy = ANY (ARRAY['none'::text, 'quarantine'::text, 'reject'::text]))),
    CONSTRAINT domains_mta_sts_policy_check CHECK ((mta_sts_policy = ANY (ARRAY['none'::text, 'testing'::text, 'enforce'::text]))),
    CONSTRAINT domains_name_check CHECK ((name ~* '^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$'::text)),
    CONSTRAINT domains_sandbox_action_check CHECK ((sandbox_action = ANY (ARRAY['reject'::text, 'quarantine'::text]))),
    CONSTRAINT domains_sandbox_file_types_check CHECK ((sandbox_file_types <> ''::text))
);


--
-- Name: domains_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.domains_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: domains_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.domains_id_seq OWNED BY public.domains.id;


--
-- Name: ediscovery_cases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ediscovery_cases (
    id bigint NOT NULL,
    name text NOT NULL,
    description text,
    status text DEFAULT 'active'::text NOT NULL,
    created_by bigint NOT NULL,
    closed_at timestamp with time zone,
    closed_by bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ediscovery_cases_status_check CHECK ((status = ANY (ARRAY['active'::text, 'closed'::text])))
);


--
-- Name: ediscovery_cases_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ediscovery_cases_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ediscovery_cases_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ediscovery_cases_id_seq OWNED BY public.ediscovery_cases.id;


--
-- Name: ediscovery_searches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ediscovery_searches (
    id bigint NOT NULL,
    name text NOT NULL,
    created_by bigint NOT NULL,
    query jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    result_count integer,
    export_ref text,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    case_id bigint,
    CONSTRAINT ediscovery_query_check CHECK ((jsonb_typeof(query) = 'object'::text)),
    CONSTRAINT ediscovery_searches_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'complete'::text, 'failed'::text])))
);


--
-- Name: ediscovery_searches_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ediscovery_searches_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ediscovery_searches_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ediscovery_searches_id_seq OWNED BY public.ediscovery_searches.id;


--
-- Name: email_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_templates (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    name text NOT NULL,
    subject text,
    body_text text,
    body_html text,
    is_default boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: email_templates_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.email_templates_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: email_templates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.email_templates_id_seq OWNED BY public.email_templates.id;


--
-- Name: event_attendees; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_attendees (
    id bigint NOT NULL,
    event_id bigint NOT NULL,
    email text NOT NULL,
    name text,
    role text DEFAULT 'required'::text NOT NULL,
    status text DEFAULT 'needs-action'::text NOT NULL,
    rsvp boolean DEFAULT true NOT NULL,
    CONSTRAINT event_attendees_role_check CHECK ((role = ANY (ARRAY['organizer'::text, 'required'::text, 'optional'::text, 'resource'::text]))),
    CONSTRAINT event_attendees_status_check CHECK ((status = ANY (ARRAY['needs-action'::text, 'accepted'::text, 'declined'::text, 'tentative'::text])))
);


--
-- Name: event_attendees_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.event_attendees_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: event_attendees_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.event_attendees_id_seq OWNED BY public.event_attendees.id;


--
-- Name: external_sender_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.external_sender_config (
    domain_id bigint NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    warn_text text,
    warn_color text DEFAULT '#FFD60A'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE external_sender_config; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.external_sender_config IS 'Per-domain external sender banner overrides. NULL warn_text → use system_config external_sender.warn_text.';


--
-- Name: feature_toggles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.feature_toggles (
    key text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    description text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: field_policy; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.field_policy (
    user_id bigint NOT NULL,
    field text NOT NULL,
    policy text NOT NULL,
    set_at timestamp with time zone DEFAULT now() NOT NULL,
    set_by bigint,
    CONSTRAINT field_policy_policy_check CHECK ((policy = ANY (ARRAY['local_only'::text, 'ad_managed'::text])))
);


--
-- Name: folders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.folders (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    parent_id bigint,
    name text NOT NULL,
    role text,
    path text NOT NULL,
    sort_order integer DEFAULT 0 NOT NULL,
    total_count integer DEFAULT 0 NOT NULL,
    unread_count integer DEFAULT 0 NOT NULL,
    size_bytes bigint DEFAULT 0 NOT NULL,
    imap_uid_validity bigint DEFAULT (EXTRACT(epoch FROM now()))::bigint NOT NULL,
    imap_uid_next bigint DEFAULT 1 NOT NULL,
    imap_modseq bigint DEFAULT 1 NOT NULL,
    subscribed boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT folders_name_check CHECK ((name <> ''::text)),
    CONSTRAINT folders_role_check CHECK ((role = ANY (ARRAY['inbox'::text, 'trash'::text, 'spam'::text, 'junk'::text, 'sent'::text, 'drafts'::text, 'archive'::text, 'templates'::text, 'outbox'::text]))),
    CONSTRAINT folders_size_bytes_check CHECK ((size_bytes >= 0)),
    CONSTRAINT folders_total_count_check CHECK ((total_count >= 0)),
    CONSTRAINT folders_unread_count_check CHECK ((unread_count >= 0))
);


--
-- Name: folders_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.folders_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: folders_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.folders_id_seq OWNED BY public.folders.id;


--
-- Name: geo_country_tiers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.geo_country_tiers (
    country_code text NOT NULL,
    tier text DEFAULT 'low'::text NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT geo_country_tiers_country_code_check CHECK (((length(country_code) = 2) AND (country_code = upper(country_code)))),
    CONSTRAINT geo_country_tiers_tier_check CHECK ((tier = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text, 'critical'::text])))
);


--
-- Name: greylist; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.greylist (
    ip inet NOT NULL,
    sender text NOT NULL,
    recipient text NOT NULL,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    pass_count integer DEFAULT 0 NOT NULL,
    whitelisted boolean DEFAULT false NOT NULL
);


--
-- Name: greylist_whitelist; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.greylist_whitelist (
    id bigint NOT NULL,
    entry_type text NOT NULL,
    entry_value text NOT NULL,
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT greylist_whitelist_entry_type_check CHECK ((entry_type = ANY (ARRAY['ip'::text, 'domain'::text, 'email'::text])))
);


--
-- Name: greylist_whitelist_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.greylist_whitelist_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: greylist_whitelist_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.greylist_whitelist_id_seq OWNED BY public.greylist_whitelist.id;


--
-- Name: health_alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.health_alerts (
    check_name text NOT NULL,
    alert_sent_at timestamp with time zone,
    suppressed boolean DEFAULT false NOT NULL,
    acknowledged_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: health_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.health_history (
    id bigint NOT NULL,
    checked_at timestamp with time zone DEFAULT now() NOT NULL,
    check_name text NOT NULL,
    status text NOT NULL,
    value numeric,
    threshold numeric,
    details text,
    CONSTRAINT health_history_details_check CHECK ((length(details) <= 4000)),
    CONSTRAINT health_history_status_check CHECK ((status = ANY (ARRAY['ok'::text, 'warn'::text, 'error'::text])))
);


--
-- Name: health_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.health_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: health_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.health_history_id_seq OWNED BY public.health_history.id;


--
-- Name: identity_sync_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_sync_log (
    id bigint NOT NULL,
    sync_at timestamp with time zone DEFAULT now() NOT NULL,
    source text NOT NULL,
    users_checked integer DEFAULT 0 NOT NULL,
    users_updated integer DEFAULT 0 NOT NULL,
    users_created integer DEFAULT 0 NOT NULL,
    users_disabled integer DEFAULT 0 NOT NULL,
    fields_skipped integer DEFAULT 0 NOT NULL,
    conflicts_found integer DEFAULT 0 NOT NULL,
    duration_ms integer,
    error text,
    details jsonb,
    CONSTRAINT identity_sync_log_source_check CHECK ((source = ANY (ARRAY['ad'::text, 'ldap'::text, 'manual'::text])))
);


--
-- Name: identity_sync_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.identity_sync_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: identity_sync_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.identity_sync_log_id_seq OWNED BY public.identity_sync_log.id;


--
-- Name: imap_modseq_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.imap_modseq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ip_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ip_rules (
    id bigint NOT NULL,
    cidr inet NOT NULL,
    action text NOT NULL,
    description text NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by bigint,
    CONSTRAINT ip_rules_action_check CHECK ((action = ANY (ARRAY['allow'::text, 'block'::text])))
);


--
-- Name: ip_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ip_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ip_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ip_rules_id_seq OWNED BY public.ip_rules.id;


--
-- Name: journal_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.journal_queue (
    id bigint NOT NULL,
    message_id text NOT NULL,
    envelope_from text NOT NULL,
    envelope_to text NOT NULL,
    raw_ref text NOT NULL,
    journal_mailbox_id bigint NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    delivered_at timestamp with time zone,
    journal_report_ref character varying,
    CONSTRAINT journal_queue_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'delivered'::text, 'failed'::text])))
);


--
-- Name: journal_queue_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.journal_queue_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: journal_queue_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.journal_queue_id_seq OWNED BY public.journal_queue.id;


--
-- Name: journaling_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.journaling_policies (
    id bigint NOT NULL,
    domain_id bigint,
    direction text NOT NULL,
    journal_mailbox_id bigint NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT journaling_policies_direction_check CHECK ((direction = ANY (ARRAY['inbound'::text, 'outbound'::text, 'both'::text])))
);


--
-- Name: journaling_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.journaling_policies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: journaling_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.journaling_policies_id_seq OWNED BY public.journaling_policies.id;


--
-- Name: link_protect_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.link_protect_audit (
    id bigint NOT NULL,
    url_hash text NOT NULL,
    verdict text NOT NULL,
    scanner text NOT NULL,
    message_id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    client_ip text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: link_protect_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.link_protect_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: link_protect_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.link_protect_audit_id_seq OWNED BY public.link_protect_audit.id;


--
-- Name: login_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.login_events (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    device_fingerprint uuid,
    device_name text,
    platform text,
    source_ip inet,
    location text,
    success boolean NOT NULL,
    fail_reason text,
    occurred_at timestamp with time zone DEFAULT now()
);


--
-- Name: login_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.login_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: login_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.login_events_id_seq OWNED BY public.login_events.id;


--
-- Name: mailbox_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mailbox_audit_log (
    id bigint NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    mailbox_id bigint NOT NULL,
    actor_user_id bigint,
    action text NOT NULL,
    message_id bigint,
    details jsonb
)
PARTITION BY RANGE (occurred_at);


--
-- Name: mailbox_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mailbox_audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mailbox_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mailbox_audit_log_id_seq OWNED BY public.mailbox_audit_log.id;


--
-- Name: mailbox_audit_log_2026_06; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mailbox_audit_log_2026_06 (
    id bigint DEFAULT nextval('public.mailbox_audit_log_id_seq'::regclass) NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    mailbox_id bigint NOT NULL,
    actor_user_id bigint,
    action text NOT NULL,
    message_id bigint,
    details jsonb
);


--
-- Name: mailbox_audit_log_2026_07; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mailbox_audit_log_2026_07 (
    id bigint DEFAULT nextval('public.mailbox_audit_log_id_seq'::regclass) NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    mailbox_id bigint NOT NULL,
    actor_user_id bigint,
    action text NOT NULL,
    message_id bigint,
    details jsonb
);


--
-- Name: mailbox_audit_log_default; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mailbox_audit_log_default (
    id bigint DEFAULT nextval('public.mailbox_audit_log_id_seq'::regclass) NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    mailbox_id bigint NOT NULL,
    actor_user_id bigint,
    action text NOT NULL,
    message_id bigint,
    details jsonb
);


--
-- Name: mailbox_delegates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mailbox_delegates (
    mailbox_id bigint NOT NULL,
    user_id bigint NOT NULL,
    permission text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    granted_by bigint NOT NULL,
    CONSTRAINT mailbox_delegates_permission_check CHECK ((permission = ANY (ARRAY['read'::text, 'send_as'::text, 'send_on_behalf'::text, 'full_access'::text, 'manage_calendar'::text])))
);


--
-- Name: mailboxes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mailboxes (
    id bigint NOT NULL,
    user_id bigint,
    domain_id bigint NOT NULL,
    email text NOT NULL,
    type text DEFAULT 'personal'::text NOT NULL,
    display_name text NOT NULL,
    is_primary boolean DEFAULT false NOT NULL,
    quota_bytes bigint DEFAULT '53687091200'::bigint NOT NULL,
    used_bytes bigint DEFAULT 0 NOT NULL,
    sending_quota_day integer DEFAULT 500 NOT NULL,
    sending_sent_today integer DEFAULT 0 NOT NULL,
    sending_quota_reset_at date DEFAULT CURRENT_DATE NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    receive_enabled boolean DEFAULT true NOT NULL,
    hidden_from_gal boolean DEFAULT false NOT NULL,
    litigation_hold boolean DEFAULT false NOT NULL,
    hold_since timestamp with time zone,
    hold_reason text,
    hold_set_by bigint,
    deleted_purge_days integer,
    spam_purge_days integer,
    spam_folder_enabled boolean DEFAULT true NOT NULL,
    spam_sensitivity text DEFAULT 'medium'::text NOT NULL,
    resource_type text,
    resource_capacity integer,
    auto_accept_meetings boolean DEFAULT false NOT NULL,
    max_meeting_hours integer,
    booking_window_days integer DEFAULT 365 NOT NULL,
    jmap_email_state bigint DEFAULT 0 NOT NULL,
    jmap_mailbox_state bigint DEFAULT 0 NOT NULL,
    jmap_thread_state bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    jmap_tag_state bigint DEFAULT 0 NOT NULL,
    quarantine_self_service boolean DEFAULT true NOT NULL,
    jmap_reminder_state bigint DEFAULT 0 NOT NULL,
    CONSTRAINT mailboxes_resource_capacity_check CHECK (((resource_capacity IS NULL) OR (resource_capacity >= 0))),
    CONSTRAINT mailboxes_resource_type_check CHECK ((resource_type = ANY (ARRAY['room'::text, 'equipment'::text]))),
    CONSTRAINT mailboxes_sending_sent_today_nonneg CHECK ((sending_sent_today >= 0)),
    CONSTRAINT mailboxes_shared_not_primary CHECK (((is_primary = false) OR (user_id IS NOT NULL))),
    CONSTRAINT mailboxes_spam_sensitivity_check CHECK ((spam_sensitivity = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text]))),
    CONSTRAINT mailboxes_type_check CHECK ((type = 'personal'::text)),
    CONSTRAINT mailboxes_used_bytes_nonneg CHECK ((used_bytes >= 0))
);


--
-- Name: mailboxes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mailboxes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mailboxes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mailboxes_id_seq OWNED BY public.mailboxes.id;


--
-- Name: managed_devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_devices (
    device_hash text NOT NULL,
    user_id bigint NOT NULL,
    device_name text DEFAULT ''::text NOT NULL,
    os_type text DEFAULT ''::text NOT NULL,
    os_version text DEFAULT ''::text NOT NULL,
    enrolled_at timestamp with time zone DEFAULT now() NOT NULL,
    last_checkin_at timestamp with time zone DEFAULT now() NOT NULL,
    compliance_status text DEFAULT 'compliant'::text NOT NULL,
    CONSTRAINT managed_devices_compliance_status_check CHECK ((compliance_status = ANY (ARRAY['compliant'::text, 'non_compliant'::text, 'unknown'::text]))),
    CONSTRAINT managed_devices_os_type_check CHECK ((os_type = ANY (ARRAY[''::text, 'ios'::text, 'android'::text, 'macos'::text, 'windows'::text, 'linux'::text])))
);


--
-- Name: mdm_device_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mdm_device_state (
    device_id uuid NOT NULL,
    user_id bigint NOT NULL,
    platform text NOT NULL,
    device_name text DEFAULT ''::text NOT NULL,
    os_version text DEFAULT ''::text NOT NULL,
    app_version text DEFAULT ''::text NOT NULL,
    passcode_set boolean DEFAULT false NOT NULL,
    passcode_compliant boolean DEFAULT false NOT NULL,
    encryption_enabled boolean DEFAULT false NOT NULL,
    jailbroken boolean DEFAULT false NOT NULL,
    jailbreak_method text DEFAULT ''::text NOT NULL,
    compliance_status text DEFAULT 'unknown'::text NOT NULL,
    non_compliance_reasons text[] DEFAULT '{}'::text[] NOT NULL,
    grace_until timestamp with time zone,
    wipe_requested text DEFAULT 'none'::text NOT NULL,
    wipe_level text,
    wipe_requested_at timestamp with time zone,
    wipe_acked_at timestamp with time zone,
    last_checkin_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mdm_device_state_compliance_status_check CHECK ((compliance_status = ANY (ARRAY['compliant'::text, 'non_compliant'::text, 'quarantined'::text, 'grace'::text]))),
    CONSTRAINT mdm_device_state_platform_check CHECK ((platform = ANY (ARRAY['ios'::text, 'android'::text]))),
    CONSTRAINT mdm_device_state_wipe_level_check CHECK ((wipe_level = ANY (ARRAY['account'::text, 'device'::text]))),
    CONSTRAINT mdm_device_state_wipe_requested_check CHECK ((wipe_requested = ANY (ARRAY['none'::text, 'pending'::text, 'acknowledged'::text, 'executed'::text])))
);


--
-- Name: mdm_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mdm_policies (
    id bigint NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    scope_type text NOT NULL,
    scope_id bigint,
    enabled boolean DEFAULT true NOT NULL,
    passcode_min_length integer DEFAULT 6 NOT NULL,
    passcode_complexity text DEFAULT 'numeric'::text NOT NULL,
    passcode_max_age_days integer DEFAULT 90 NOT NULL,
    passcode_history_count integer DEFAULT 5 NOT NULL,
    max_failed_attempts integer DEFAULT 10 NOT NULL,
    inactivity_lock_mins integer DEFAULT 5 NOT NULL,
    block_screenshots boolean DEFAULT false NOT NULL,
    block_copy_paste boolean DEFAULT false NOT NULL,
    require_device_encryption boolean DEFAULT true NOT NULL,
    min_os_version_ios text DEFAULT ''::text NOT NULL,
    min_os_version_android text DEFAULT ''::text NOT NULL,
    jailbreak_action text DEFAULT 'quarantine'::text NOT NULL,
    heartbeat_interval_secs integer DEFAULT 3600 NOT NULL,
    grace_period_mins integer DEFAULT 60 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mdm_policies_jailbreak_action_check CHECK ((jailbreak_action = ANY (ARRAY['block'::text, 'quarantine'::text, 'warn_log'::text, 'none'::text]))),
    CONSTRAINT mdm_policies_passcode_complexity_check CHECK ((passcode_complexity = ANY (ARRAY['none'::text, 'numeric'::text, 'alphanumeric'::text, 'complex'::text]))),
    CONSTRAINT mdm_policies_scope_type_check CHECK ((scope_type = ANY (ARRAY['global'::text, 'group'::text, 'user'::text])))
);


--
-- Name: mdm_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mdm_policies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mdm_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mdm_policies_id_seq OWNED BY public.mdm_policies.id;


--
-- Name: message_attachments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_attachments (
    id bigint NOT NULL,
    message_id bigint NOT NULL,
    received_at timestamp with time zone NOT NULL,
    blob_sha256 text NOT NULL,
    filename text,
    content_id text,
    content_type text NOT NULL,
    disposition text DEFAULT 'attachment'::text NOT NULL,
    size_bytes bigint NOT NULL,
    CONSTRAINT message_attachments_disposition_check CHECK ((disposition = ANY (ARRAY['attachment'::text, 'inline'::text])))
);


--
-- Name: message_attachments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.message_attachments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: message_attachments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.message_attachments_id_seq OWNED BY public.message_attachments.id;


--
-- Name: message_recalls; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_recalls (
    message_id text NOT NULL,
    recalled_by bigint,
    recalled_at timestamp with time zone DEFAULT now() NOT NULL,
    copy_count integer DEFAULT 0 NOT NULL,
    cannot_count integer DEFAULT 0 NOT NULL
);


--
-- Name: message_retention_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_retention_tags (
    message_id bigint NOT NULL,
    received_at timestamp with time zone NOT NULL,
    policy_id bigint NOT NULL,
    expires_at timestamp with time zone
);


--
-- Name: message_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_tags (
    message_id bigint NOT NULL,
    received_at timestamp with time zone NOT NULL,
    tag_id bigint NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    added_by text,
    snooze_until timestamp with time zone,
    scheduled_at timestamp with time zone,
    is_primary boolean DEFAULT false NOT NULL
)
PARTITION BY RANGE (received_at);


--
-- Name: message_tags_default; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_tags_default (
    message_id bigint NOT NULL,
    received_at timestamp with time zone NOT NULL,
    tag_id bigint NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    added_by text,
    snooze_until timestamp with time zone,
    scheduled_at timestamp with time zone,
    is_primary boolean DEFAULT false NOT NULL
);


--
-- Name: message_trace; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_trace (
    id bigint NOT NULL,
    message_id text NOT NULL,
    event text NOT NULL,
    from_addr text NOT NULL,
    rcpt_addr text NOT NULL,
    remote_host text,
    details jsonb,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT message_trace_event_check CHECK ((event = ANY (ARRAY['received'::text, 'delivered'::text, 'bounced'::text, 'deferred'::text, 'spam_filtered'::text, 'rule_applied'::text, 'quarantined'::text, 'held'::text, 'archived'::text, 'expired'::text])))
)
PARTITION BY RANGE (occurred_at);


--
-- Name: message_trace_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.message_trace_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: message_trace_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.message_trace_id_seq OWNED BY public.message_trace.id;


--
-- Name: message_trace_2026_06; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_trace_2026_06 (
    id bigint DEFAULT nextval('public.message_trace_id_seq'::regclass) NOT NULL,
    message_id text NOT NULL,
    event text NOT NULL,
    from_addr text NOT NULL,
    rcpt_addr text NOT NULL,
    remote_host text,
    details jsonb,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT message_trace_event_check CHECK ((event = ANY (ARRAY['received'::text, 'delivered'::text, 'bounced'::text, 'deferred'::text, 'spam_filtered'::text, 'rule_applied'::text, 'quarantined'::text, 'held'::text, 'archived'::text, 'expired'::text])))
);


--
-- Name: message_trace_2026_07; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_trace_2026_07 (
    id bigint DEFAULT nextval('public.message_trace_id_seq'::regclass) NOT NULL,
    message_id text NOT NULL,
    event text NOT NULL,
    from_addr text NOT NULL,
    rcpt_addr text NOT NULL,
    remote_host text,
    details jsonb,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT message_trace_event_check CHECK ((event = ANY (ARRAY['received'::text, 'delivered'::text, 'bounced'::text, 'deferred'::text, 'spam_filtered'::text, 'rule_applied'::text, 'quarantined'::text, 'held'::text, 'archived'::text, 'expired'::text])))
);


--
-- Name: message_trace_default; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_trace_default (
    id bigint DEFAULT nextval('public.message_trace_id_seq'::regclass) NOT NULL,
    message_id text NOT NULL,
    event text NOT NULL,
    from_addr text NOT NULL,
    rcpt_addr text NOT NULL,
    remote_host text,
    details jsonb,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT message_trace_event_check CHECK ((event = ANY (ARRAY['received'::text, 'delivered'::text, 'bounced'::text, 'deferred'::text, 'spam_filtered'::text, 'rule_applied'::text, 'quarantined'::text, 'held'::text, 'archived'::text, 'expired'::text])))
);


--
-- Name: messages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.messages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: messages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.messages_id_seq OWNED BY public.messages.id;


--
-- Name: messages_2026_06; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.messages_2026_06 (
    id bigint DEFAULT nextval('public.messages_id_seq'::regclass) NOT NULL,
    mailbox_id bigint NOT NULL,
    folder_id bigint NOT NULL,
    message_id text NOT NULL,
    subject text,
    from_addr text NOT NULL,
    from_name text,
    to_addrs jsonb DEFAULT '[]'::jsonb NOT NULL,
    cc_addrs jsonb DEFAULT '[]'::jsonb NOT NULL,
    bcc_addrs jsonb DEFAULT '[]'::jsonb NOT NULL,
    reply_to text,
    in_reply_to text,
    references_hdr text,
    body_text text,
    body_html text,
    body_tsv tsvector,
    subject_tsv tsvector,
    from_tsv tsvector,
    size_bytes bigint DEFAULT 0 NOT NULL,
    has_attachments boolean DEFAULT false NOT NULL,
    is_read boolean DEFAULT false NOT NULL,
    is_flagged boolean DEFAULT false NOT NULL,
    is_answered boolean DEFAULT false NOT NULL,
    is_draft boolean DEFAULT false NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    categories text[] DEFAULT '{}'::text[] NOT NULL,
    thread_id text NOT NULL,
    imap_uid bigint,
    imap_modseq bigint,
    spam_score real,
    spam_headers jsonb,
    spf_result text,
    dkim_result text,
    dmarc_result text,
    raw_ref text NOT NULL,
    held boolean DEFAULT false NOT NULL,
    sent_at timestamp with time zone,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    dkim_selector text,
    dkim_domain text,
    crypto_type text,
    smime_encrypt boolean DEFAULT false NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    sensitivity text,
    read_receipt_requested boolean DEFAULT false NOT NULL,
    delivery_receipt_requested boolean DEFAULT false NOT NULL,
    vote_options jsonb,
    scheduled_at timestamp with time zone,
    deleted_at timestamp with time zone,
    pinned_at timestamp with time zone,
    vote_response text,
    is_external boolean DEFAULT false NOT NULL,
    sender_display_name text,
    is_name_spoof boolean DEFAULT false NOT NULL,
    is_first_time boolean DEFAULT true NOT NULL,
    list_unsubscribe text,
    list_id text,
    flag_due_at timestamp with time zone,
    flag_reminder_at timestamp with time zone,
    CONSTRAINT messages_dkim_result_check CHECK ((dkim_result = ANY (ARRAY['pass'::text, 'fail'::text, 'none'::text, 'policy'::text, 'neutral'::text, 'temperror'::text, 'permerror'::text]))),
    CONSTRAINT messages_dmarc_result_check CHECK ((dmarc_result = ANY (ARRAY['pass'::text, 'fail'::text, 'none'::text, 'temperror'::text, 'permerror'::text]))),
    CONSTRAINT messages_priority_check CHECK ((priority = ANY (ARRAY['-1'::integer, 0, 1]))),
    CONSTRAINT messages_sensitivity_check CHECK ((sensitivity = ANY (ARRAY['normal'::text, 'personal'::text, 'private'::text, 'confidential'::text]))),
    CONSTRAINT messages_spf_result_check CHECK ((spf_result = ANY (ARRAY['pass'::text, 'fail'::text, 'softfail'::text, 'neutral'::text, 'none'::text, 'permerror'::text, 'temperror'::text])))
);


--
-- Name: messages_2026_07; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.messages_2026_07 (
    id bigint DEFAULT nextval('public.messages_id_seq'::regclass) NOT NULL,
    mailbox_id bigint NOT NULL,
    folder_id bigint NOT NULL,
    message_id text NOT NULL,
    subject text,
    from_addr text NOT NULL,
    from_name text,
    to_addrs jsonb DEFAULT '[]'::jsonb NOT NULL,
    cc_addrs jsonb DEFAULT '[]'::jsonb NOT NULL,
    bcc_addrs jsonb DEFAULT '[]'::jsonb NOT NULL,
    reply_to text,
    in_reply_to text,
    references_hdr text,
    body_text text,
    body_html text,
    body_tsv tsvector,
    subject_tsv tsvector,
    from_tsv tsvector,
    size_bytes bigint DEFAULT 0 NOT NULL,
    has_attachments boolean DEFAULT false NOT NULL,
    is_read boolean DEFAULT false NOT NULL,
    is_flagged boolean DEFAULT false NOT NULL,
    is_answered boolean DEFAULT false NOT NULL,
    is_draft boolean DEFAULT false NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    categories text[] DEFAULT '{}'::text[] NOT NULL,
    thread_id text NOT NULL,
    imap_uid bigint,
    imap_modseq bigint,
    spam_score real,
    spam_headers jsonb,
    spf_result text,
    dkim_result text,
    dmarc_result text,
    raw_ref text NOT NULL,
    held boolean DEFAULT false NOT NULL,
    sent_at timestamp with time zone,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    dkim_selector text,
    dkim_domain text,
    crypto_type text,
    smime_encrypt boolean DEFAULT false NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    sensitivity text,
    read_receipt_requested boolean DEFAULT false NOT NULL,
    delivery_receipt_requested boolean DEFAULT false NOT NULL,
    vote_options jsonb,
    scheduled_at timestamp with time zone,
    deleted_at timestamp with time zone,
    pinned_at timestamp with time zone,
    vote_response text,
    is_external boolean DEFAULT false NOT NULL,
    sender_display_name text,
    is_name_spoof boolean DEFAULT false NOT NULL,
    is_first_time boolean DEFAULT true NOT NULL,
    list_unsubscribe text,
    list_id text,
    flag_due_at timestamp with time zone,
    flag_reminder_at timestamp with time zone,
    CONSTRAINT messages_dkim_result_check CHECK ((dkim_result = ANY (ARRAY['pass'::text, 'fail'::text, 'none'::text, 'policy'::text, 'neutral'::text, 'temperror'::text, 'permerror'::text]))),
    CONSTRAINT messages_dmarc_result_check CHECK ((dmarc_result = ANY (ARRAY['pass'::text, 'fail'::text, 'none'::text, 'temperror'::text, 'permerror'::text]))),
    CONSTRAINT messages_priority_check CHECK ((priority = ANY (ARRAY['-1'::integer, 0, 1]))),
    CONSTRAINT messages_sensitivity_check CHECK ((sensitivity = ANY (ARRAY['normal'::text, 'personal'::text, 'private'::text, 'confidential'::text]))),
    CONSTRAINT messages_spf_result_check CHECK ((spf_result = ANY (ARRAY['pass'::text, 'fail'::text, 'softfail'::text, 'neutral'::text, 'none'::text, 'permerror'::text, 'temperror'::text])))
);


--
-- Name: messages_default; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.messages_default (
    id bigint DEFAULT nextval('public.messages_id_seq'::regclass) NOT NULL,
    mailbox_id bigint NOT NULL,
    folder_id bigint NOT NULL,
    message_id text NOT NULL,
    subject text,
    from_addr text NOT NULL,
    from_name text,
    to_addrs jsonb DEFAULT '[]'::jsonb NOT NULL,
    cc_addrs jsonb DEFAULT '[]'::jsonb NOT NULL,
    bcc_addrs jsonb DEFAULT '[]'::jsonb NOT NULL,
    reply_to text,
    in_reply_to text,
    references_hdr text,
    body_text text,
    body_html text,
    body_tsv tsvector,
    subject_tsv tsvector,
    from_tsv tsvector,
    size_bytes bigint DEFAULT 0 NOT NULL,
    has_attachments boolean DEFAULT false NOT NULL,
    is_read boolean DEFAULT false NOT NULL,
    is_flagged boolean DEFAULT false NOT NULL,
    is_answered boolean DEFAULT false NOT NULL,
    is_draft boolean DEFAULT false NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    categories text[] DEFAULT '{}'::text[] NOT NULL,
    thread_id text NOT NULL,
    imap_uid bigint,
    imap_modseq bigint,
    spam_score real,
    spam_headers jsonb,
    spf_result text,
    dkim_result text,
    dmarc_result text,
    raw_ref text NOT NULL,
    held boolean DEFAULT false NOT NULL,
    sent_at timestamp with time zone,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    dkim_selector text,
    dkim_domain text,
    crypto_type text,
    smime_encrypt boolean DEFAULT false NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    sensitivity text,
    read_receipt_requested boolean DEFAULT false NOT NULL,
    delivery_receipt_requested boolean DEFAULT false NOT NULL,
    vote_options jsonb,
    scheduled_at timestamp with time zone,
    deleted_at timestamp with time zone,
    pinned_at timestamp with time zone,
    vote_response text,
    is_external boolean DEFAULT false NOT NULL,
    sender_display_name text,
    is_name_spoof boolean DEFAULT false NOT NULL,
    is_first_time boolean DEFAULT true NOT NULL,
    list_unsubscribe text,
    list_id text,
    flag_due_at timestamp with time zone,
    flag_reminder_at timestamp with time zone,
    CONSTRAINT messages_dkim_result_check CHECK ((dkim_result = ANY (ARRAY['pass'::text, 'fail'::text, 'none'::text, 'policy'::text, 'neutral'::text, 'temperror'::text, 'permerror'::text]))),
    CONSTRAINT messages_dmarc_result_check CHECK ((dmarc_result = ANY (ARRAY['pass'::text, 'fail'::text, 'none'::text, 'temperror'::text, 'permerror'::text]))),
    CONSTRAINT messages_priority_check CHECK ((priority = ANY (ARRAY['-1'::integer, 0, 1]))),
    CONSTRAINT messages_sensitivity_check CHECK ((sensitivity = ANY (ARRAY['normal'::text, 'personal'::text, 'private'::text, 'confidential'::text]))),
    CONSTRAINT messages_spf_result_check CHECK ((spf_result = ANY (ARRAY['pass'::text, 'fail'::text, 'softfail'::text, 'neutral'::text, 'none'::text, 'permerror'::text, 'temperror'::text])))
);


--
-- Name: migration_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.migration_jobs (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    source_type text NOT NULL,
    source_config_enc bytea,
    target_mailbox_id bigint,
    conflict_strategy text DEFAULT 'skip'::text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    progress jsonb DEFAULT '{}'::jsonb NOT NULL,
    error_log jsonb DEFAULT '[]'::jsonb NOT NULL,
    resume_cursor text,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT migration_jobs_conflict_strategy_check CHECK ((conflict_strategy = ANY (ARRAY['skip'::text, 'overwrite'::text, 'rename'::text]))),
    CONSTRAINT migration_jobs_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'testing'::text, 'fetching'::text, 'importing'::text, 'paused'::text, 'completed'::text, 'cancelled'::text, 'failed'::text])))
);


--
-- Name: migration_jobs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.migration_jobs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: migration_jobs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.migration_jobs_id_seq OWNED BY public.migration_jobs.id;


--
-- Name: mk_account_mb_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mk_account_mb_seq
    START WITH 90000
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mk_account_user_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mk_account_user_seq
    START WITH 70000
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mta_sts_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mta_sts_policies (
    domain text NOT NULL,
    policy_json jsonb NOT NULL,
    fetched_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: oauth_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_tokens (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    client_id text,
    token_hash bytea NOT NULL,
    token_type text NOT NULL,
    scope text[] DEFAULT '{}'::text[],
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoked_by bigint,
    previous_token_hash bytea,
    last_used_at timestamp with time zone,
    last_used_protocol text,
    rotated_at timestamp with time zone,
    CONSTRAINT oauth_tokens_token_type_check CHECK ((token_type = ANY (ARRAY['access'::text, 'refresh'::text, 'xoauth2'::text, 'app_password'::text, 'authorization_code'::text])))
);


--
-- Name: oauth_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.oauth_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: oauth_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.oauth_tokens_id_seq OWNED BY public.oauth_tokens.id;


--
-- Name: oidc_auth_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.oidc_auth_requests (
    id text NOT NULL,
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    state text NOT NULL,
    nonce text,
    code_challenge text,
    code_challenge_method text,
    scopes text[] NOT NULL,
    user_id bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '00:10:00'::interval) NOT NULL
);


--
-- Name: oidc_clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_clients (
    id text NOT NULL,
    name text NOT NULL,
    secret text NOT NULL,
    redirect_uris text[] NOT NULL,
    grant_types text[] DEFAULT '{authorization_code,refresh_token}'::text[] NOT NULL,
    scopes text[] DEFAULT '{openid,profile,email}'::text[] NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    client_type text DEFAULT 'confidential'::text NOT NULL
);


--
-- Name: oidc_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_tokens (
    id text NOT NULL,
    client_id text NOT NULL,
    user_id bigint NOT NULL,
    subject text NOT NULL,
    refresh_token_hash text,
    scopes text[] NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: orphaned_message_blobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.orphaned_message_blobs (
    raw_ref text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: outbound_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.outbound_queue (
    id bigint NOT NULL,
    message_id text NOT NULL,
    from_addr text NOT NULL,
    rcpt_addrs text[] NOT NULL,
    raw_ref text NOT NULL,
    dkim_signed boolean DEFAULT false NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error text,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    delivered_at timestamp with time zone,
    mailbox_id bigint,
    dedup_key text,
    forward_unwrap_links boolean DEFAULT false NOT NULL,
    CONSTRAINT outbound_queue_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'sending'::text, 'delivered'::text, 'bounced'::text, 'deferred'::text])))
);


--
-- Name: outbound_queue_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.outbound_queue_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: outbound_queue_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.outbound_queue_id_seq OWNED BY public.outbound_queue.id;


--
-- Name: outbound_queue_hot; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.outbound_queue_hot (
    id bigint DEFAULT nextval('public.outbound_queue_id_seq'::regclass) NOT NULL,
    message_id text NOT NULL,
    from_addr text NOT NULL,
    rcpt_addrs text[] NOT NULL,
    raw_ref text NOT NULL,
    dkim_signed boolean DEFAULT false NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error text,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    delivered_at timestamp with time zone,
    mailbox_id bigint,
    dedup_key text,
    forward_unwrap_links boolean DEFAULT false NOT NULL
);


--
-- Name: passkey_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.passkey_credentials (
    id bytea NOT NULL,
    user_id bigint NOT NULL,
    public_key bytea NOT NULL,
    attestation_type text DEFAULT 'none'::text NOT NULL,
    sign_count integer DEFAULT 0 NOT NULL,
    device_name text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone
);


--
-- Name: password_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.password_history (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    password_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: password_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.password_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: password_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.password_history_id_seq OWNED BY public.password_history.id;


--
-- Name: push_devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_devices (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    push_provider text NOT NULL,
    push_token_enc bytea NOT NULL,
    device_name text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    CONSTRAINT push_devices_push_provider_check CHECK ((push_provider = ANY (ARRAY['webpush'::text, 'apns'::text, 'fcm'::text])))
);


--
-- Name: push_devices_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.push_devices_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: push_devices_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.push_devices_id_seq OWNED BY public.push_devices.id;


--
-- Name: push_mfa_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.push_mfa_challenges (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    challenge_code text NOT NULL,
    nonce bytea NOT NULL,
    session_id text,
    expires_at timestamp with time zone NOT NULL,
    verified_at timestamp with time zone,
    failed_attempts integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: push_mfa_challenges_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.push_mfa_challenges_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: push_mfa_challenges_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.push_mfa_challenges_id_seq OWNED BY public.push_mfa_challenges.id;


--
-- Name: quarantined_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.quarantined_messages (
    id bigint NOT NULL,
    message_id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    original_tag text NOT NULL,
    reason text NOT NULL,
    reason_type text DEFAULT 'virus'::text NOT NULL,
    virus_name text,
    preview_token text DEFAULT (gen_random_uuid())::text NOT NULL,
    quarantined_at timestamp with time zone DEFAULT now() NOT NULL,
    released_at timestamp with time zone,
    released_by bigint,
    rejected_at timestamp with time zone,
    rejected_by bigint,
    notified_at timestamp with time zone,
    CONSTRAINT quarantined_messages_reason_type_check CHECK ((reason_type = ANY (ARRAY['virus'::text, 'dlp'::text, 'admin'::text, 'sandbox'::text])))
);


--
-- Name: quarantined_messages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.quarantined_messages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: quarantined_messages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.quarantined_messages_id_seq OWNED BY public.quarantined_messages.id;


--
-- Name: quick_steps; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.quick_steps (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    name text NOT NULL,
    icon text DEFAULT 'Zap'::text NOT NULL,
    "position" integer DEFAULT 0 NOT NULL,
    actions jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT quick_steps_actions_check CHECK ((jsonb_typeof(actions) = 'array'::text))
);


--
-- Name: quick_steps_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.quick_steps_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: quick_steps_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.quick_steps_id_seq OWNED BY public.quick_steps.id;


--
-- Name: rate_limit_counters; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.rate_limit_counters (
    key text NOT NULL,
    count integer DEFAULT 0 NOT NULL,
    window_start timestamp with time zone DEFAULT now() NOT NULL,
    blocked_until timestamp with time zone
);


--
-- Name: read_receipts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.read_receipts (
    id bigint NOT NULL,
    message_id bigint NOT NULL,
    received_at timestamp with time zone NOT NULL,
    recipient_email text NOT NULL,
    read_at timestamp with time zone DEFAULT now() NOT NULL,
    user_agent text,
    ip_address text
);


--
-- Name: read_receipts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.read_receipts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: read_receipts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.read_receipts_id_seq OWNED BY public.read_receipts.id;


--
-- Name: reminders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.reminders (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    source_type text NOT NULL,
    source_id bigint NOT NULL,
    fire_at timestamp with time zone NOT NULL,
    fired_at timestamp with time zone,
    dismissed_at timestamp with time zone,
    snoozed_until timestamp with time zone,
    title text NOT NULL,
    body text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT reminders_source_type_check CHECK ((source_type = ANY (ARRAY['event'::text, 'task'::text, 'flag'::text])))
);


--
-- Name: reminders_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.reminders_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: reminders_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.reminders_id_seq OWNED BY public.reminders.id;


--
-- Name: retention_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.retention_policies (
    id bigint NOT NULL,
    name text NOT NULL,
    description text,
    retain_days integer,
    action text DEFAULT 'delete'::text NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    domain_id bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT retention_policies_action_check CHECK ((action = ANY (ARRAY['delete'::text, 'archive'::text, 'hold'::text]))),
    CONSTRAINT retention_policies_retain_days_check CHECK (((retain_days IS NULL) OR (retain_days > 0)))
);


--
-- Name: retention_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.retention_policies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: retention_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.retention_policies_id_seq OWNED BY public.retention_policies.id;


--
-- Name: rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rules (
    id bigint NOT NULL,
    user_id bigint,
    mailbox_id bigint,
    name text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    run_on text DEFAULT 'server'::text NOT NULL,
    is_transport_rule boolean DEFAULT false NOT NULL,
    conditions jsonb DEFAULT '[]'::jsonb NOT NULL,
    actions jsonb DEFAULT '[]'::jsonb NOT NULL,
    stop_processing boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT rules_actions_check CHECK ((jsonb_typeof(actions) = 'array'::text)),
    CONSTRAINT rules_conditions_check CHECK ((jsonb_typeof(conditions) = ANY (ARRAY['array'::text, 'object'::text]))),
    CONSTRAINT rules_priority_check CHECK (((priority >= 0) AND (priority <= 100))),
    CONSTRAINT rules_run_on_check CHECK ((run_on = ANY (ARRAY['server'::text, 'client'::text, 'both'::text])))
);


--
-- Name: rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.rules_id_seq OWNED BY public.rules.id;


--
-- Name: saml_sp_registrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.saml_sp_registrations (
    id bigint NOT NULL,
    idp_entity_id text NOT NULL,
    idp_metadata_url text,
    idp_sso_url text NOT NULL,
    idp_cert_enc bytea NOT NULL,
    sp_entity_id text NOT NULL,
    sp_acs_url text NOT NULL,
    attribute_map jsonb DEFAULT '{}'::jsonb NOT NULL,
    jit_enabled boolean DEFAULT false NOT NULL,
    group_attribute text DEFAULT 'memberOf'::text,
    group_mappings jsonb,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: saml_sp_registrations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.saml_sp_registrations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: saml_sp_registrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.saml_sp_registrations_id_seq OWNED BY public.saml_sp_registrations.id;


--
-- Name: scheduled_action_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scheduled_action_log (
    id bigint NOT NULL,
    action_id uuid NOT NULL,
    at timestamp with time zone DEFAULT now() NOT NULL,
    from_status text,
    to_status text NOT NULL,
    worker text,
    outcome text,
    note text
);


--
-- Name: scheduled_action_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.scheduled_action_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scheduled_action_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scheduled_action_log_id_seq OWNED BY public.scheduled_action_log.id;


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version integer NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: scim_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scim_tokens (
    id bigint NOT NULL,
    name text NOT NULL,
    token_hash text NOT NULL,
    expires_at timestamp with time zone,
    deletion_policy text DEFAULT 'soft'::text NOT NULL,
    attribute_mapping jsonb DEFAULT '{}'::jsonb NOT NULL,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text,
    revoked_at timestamp with time zone,
    CONSTRAINT scim_tokens_deletion_policy_check CHECK ((deletion_policy = ANY (ARRAY['soft'::text, 'hard'::text])))
);


--
-- Name: scim_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.scim_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scim_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scim_tokens_id_seq OWNED BY public.scim_tokens.id;


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.sessions (
    id text DEFAULT (gen_random_uuid())::text NOT NULL,
    user_id bigint NOT NULL,
    token_hash bytea,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    ip inet,
    user_agent text,
    auth_method text,
    ad_grace_until timestamp with time zone,
    CONSTRAINT sessions_auth_method_check CHECK ((auth_method = ANY (ARRAY['password'::text, 'webauthn'::text, 'kerberos'::text, 'saml'::text, 'oidc'::text, 'totp'::text])))
);


--
-- Name: signatures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.signatures (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    name text NOT NULL,
    body_text text,
    body_html text,
    is_default boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: signatures_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.signatures_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: signatures_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.signatures_id_seq OWNED BY public.signatures.id;


--
-- Name: signing_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.signing_keys (
    id bigint NOT NULL,
    kid text NOT NULL,
    alg text NOT NULL,
    public_jwk jsonb NOT NULL,
    private_key_enc bytea NOT NULL,
    status text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    rotated_at timestamp with time zone,
    CONSTRAINT signing_keys_status_check CHECK ((status = ANY (ARRAY['active'::text, 'retiring'::text, 'retired'::text])))
);


--
-- Name: signing_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.signing_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: signing_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.signing_keys_id_seq OWNED BY public.signing_keys.id;


--
-- Name: smtp_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.smtp_sessions (
    id text NOT NULL,
    remote_ip inet NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    state text DEFAULT 'greeting'::text NOT NULL,
    ehlo_hostname text,
    mail_from text,
    rcpt_to text[] DEFAULT '{}'::text[] NOT NULL,
    tls_enabled boolean DEFAULT false NOT NULL,
    tls_version text,
    authenticated boolean DEFAULT false NOT NULL,
    auth_user_id bigint,
    spf_result text,
    bytes_received bigint DEFAULT 0 NOT NULL,
    CONSTRAINT smtp_sessions_state_check CHECK ((state = ANY (ARRAY['greeting'::text, 'ehlo'::text, 'mail_from'::text, 'rcpt_to'::text, 'data'::text, 'quit'::text])))
);


--
-- Name: storage_dr_scans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.storage_dr_scans (
    id bigint NOT NULL,
    status text DEFAULT 'running'::text NOT NULL,
    total_scanned bigint DEFAULT 0 NOT NULL,
    orphaned_count bigint DEFAULT 0 NOT NULL,
    missing_count bigint DEFAULT 0 NOT NULL,
    reimported_count bigint DEFAULT 0 NOT NULL,
    details jsonb DEFAULT '[]'::jsonb,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    refcount_drift_count bigint DEFAULT 0 NOT NULL,
    CONSTRAINT storage_dr_scans_status_check CHECK ((status = ANY (ARRAY['running'::text, 'completed'::text, 'failed'::text])))
);


--
-- Name: storage_dr_scans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.storage_dr_scans_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: storage_dr_scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.storage_dr_scans_id_seq OWNED BY public.storage_dr_scans.id;


--
-- Name: storage_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.storage_migrations (
    id bigint NOT NULL,
    source_driver text NOT NULL,
    target_driver text NOT NULL,
    status text DEFAULT 'dual_write'::text NOT NULL,
    total_blobs bigint,
    migrated bigint DEFAULT 0,
    last_key text,
    error_message text,
    started_at timestamp with time zone DEFAULT now(),
    completed_at timestamp with time zone,
    CONSTRAINT storage_migrations_status_check CHECK ((status = ANY (ARRAY['dual_write'::text, 'backfill'::text, 'cutover'::text, 'completed'::text, 'failed'::text, 'cancelled'::text])))
);


--
-- Name: storage_migrations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.storage_migrations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: storage_migrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.storage_migrations_id_seq OWNED BY public.storage_migrations.id;


--
-- Name: sync_conflicts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sync_conflicts (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    field text NOT NULL,
    local_value text,
    remote_value text,
    source text NOT NULL,
    detected_at timestamp with time zone DEFAULT now() NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by bigint,
    resolution text,
    CONSTRAINT sync_conflicts_resolution_check CHECK ((resolution = ANY (ARRAY['kept_local'::text, 'accepted_remote'::text, 'merged'::text]))),
    CONSTRAINT sync_conflicts_source_check CHECK ((source = ANY (ARRAY['ad'::text, 'ldap'::text])))
);


--
-- Name: sync_conflicts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sync_conflicts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sync_conflicts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sync_conflicts_id_seq OWNED BY public.sync_conflicts.id;


--
-- Name: tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tags (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    parent_id bigint,
    name text NOT NULL,
    color text,
    icon text,
    sort_order integer DEFAULT 0 NOT NULL,
    tag_type text DEFAULT 'user'::text NOT NULL,
    exclusive_group text,
    is_default boolean DEFAULT false NOT NULL,
    total_count integer DEFAULT 0 NOT NULL,
    unread_count integer DEFAULT 0 NOT NULL,
    size_bytes bigint DEFAULT 0 NOT NULL,
    imap_expose boolean DEFAULT true NOT NULL,
    imap_name text,
    imap_uid_validity bigint DEFAULT (EXTRACT(epoch FROM now()))::bigint NOT NULL,
    imap_uid_next bigint DEFAULT 1 NOT NULL,
    imap_modseq bigint DEFAULT 1 NOT NULL,
    jmap_state bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tags_exclusive_group_check CHECK ((exclusive_group = ANY (ARRAY['location'::text, 'snooze'::text, 'quarantine'::text]))),
    CONSTRAINT tags_name_check CHECK ((name <> ''::text)),
    CONSTRAINT tags_size_bytes_check CHECK ((size_bytes >= 0)),
    CONSTRAINT tags_tag_type_check CHECK ((tag_type = ANY (ARRAY['system'::text, 'user'::text, 'smart'::text]))),
    CONSTRAINT tags_total_count_check CHECK ((total_count >= 0)),
    CONSTRAINT tags_unread_count_check CHECK ((unread_count >= 0))
);


--
-- Name: tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tags_id_seq OWNED BY public.tags.id;


--
-- Name: tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tasks (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    parent_id bigint,
    title text NOT NULL,
    description text,
    status text DEFAULT 'needs-action'::text NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    due_at timestamp with time zone,
    reminder_at timestamp with time zone,
    completed_at timestamp with time zone,
    assignee_user_id bigint,
    linked_message_id bigint,
    linked_message_received_at timestamp with time zone,
    linked_event_id bigint,
    categories text[] DEFAULT '{}'::text[] NOT NULL,
    rrule text,
    jmap_state bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tasks_priority_check CHECK ((priority = ANY (ARRAY[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]))),
    CONSTRAINT tasks_status_check CHECK ((status = ANY (ARRAY['needs-action'::text, 'in-progress'::text, 'completed'::text, 'cancelled'::text])))
);


--
-- Name: tasks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tasks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tasks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tasks_id_seq OWNED BY public.tasks.id;


--
-- Name: threat_feed_blocks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_feed_blocks (
    cidr inet NOT NULL,
    source text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: upgrade_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.upgrade_history (
    id bigint NOT NULL,
    from_version text NOT NULL,
    to_version text NOT NULL,
    binary_sha256 text DEFAULT ''::text NOT NULL,
    mode text NOT NULL,
    ddl_classification text NOT NULL,
    breaking_changes jsonb DEFAULT '[]'::jsonb,
    new_migrations text[] DEFAULT '{}'::text[],
    status text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    downtime_ms integer DEFAULT 0,
    error_message text,
    previous_binary_path text,
    CONSTRAINT upgrade_history_ddl_classification_check CHECK ((ddl_classification = ANY (ARRAY['additive_only'::text, 'has_breaking'::text]))),
    CONSTRAINT upgrade_history_mode_check CHECK ((mode = ANY (ARRAY['hot_reload'::text, 'full_restart'::text]))),
    CONSTRAINT upgrade_history_status_check CHECK ((status = ANY (ARRAY['success'::text, 'failed'::text, 'rolled_back'::text])))
);


--
-- Name: upgrade_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.upgrade_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: upgrade_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.upgrade_history_id_seq OWNED BY public.upgrade_history.id;


--
-- Name: used_password_reset_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.used_password_reset_tokens (
    token_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: used_saml_assertions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.used_saml_assertions (
    assertion_id text NOT NULL,
    used_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: user_app_entitlements; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_app_entitlements (
    user_id bigint NOT NULL,
    app text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by bigint,
    CONSTRAINT user_app_entitlements_app_check CHECK ((app = ANY (ARRAY['mail'::text, 'calendar'::text, 'contacts'::text, 'tasks'::text])))
);


--
-- Name: TABLE user_app_entitlements; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.user_app_entitlements IS 'Per-user app access overrides. Absent row = allowed (default-allow). enabled=FALSE blocks the user from the named app regardless of global toggle. Schema is compatible with additive group/global precedence layers (S11).';


--
-- Name: user_devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_devices (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    device_name text NOT NULL,
    platform text NOT NULL,
    push_token_enc text,
    push_provider text,
    last_seen_at timestamp with time zone,
    last_seen_ip inet,
    wipe_requested boolean DEFAULT false NOT NULL,
    wipe_type text,
    wipe_at timestamp with time zone,
    registered_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_devices_platform_check CHECK ((platform = ANY (ARRAY['ios'::text, 'android'::text, 'web'::text, 'desktop'::text]))),
    CONSTRAINT user_devices_push_provider_check CHECK ((push_provider = ANY (ARRAY['apns'::text, 'fcm'::text, 'webpush'::text]))),
    CONSTRAINT user_devices_wipe_type_check CHECK ((wipe_type = ANY (ARRAY['selective'::text, 'full'::text])))
);


--
-- Name: user_devices_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_devices_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_devices_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_devices_id_seq OWNED BY public.user_devices.id;


--
-- Name: user_imap_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_imap_settings (
    user_id bigint NOT NULL,
    expose_all boolean DEFAULT false NOT NULL,
    exposed_tag_ids bigint[] DEFAULT '{}'::bigint[] NOT NULL,
    folder_separator text DEFAULT '/'::text NOT NULL,
    show_subscribed_only boolean DEFAULT true NOT NULL
);


--
-- Name: user_notification_prefs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_notification_prefs (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    device_fingerprint uuid,
    push_enabled boolean DEFAULT true,
    push_sound text DEFAULT 'default'::text,
    stop_push_when_desktop_online boolean DEFAULT false,
    dnd_start time without time zone,
    dnd_end time without time zone,
    dnd_days smallint DEFAULT 127,
    mail_notifications text DEFAULT 'all'::text,
    calendar_reminders boolean DEFAULT true,
    task_reminders boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    read_receipt_policy text DEFAULT 'ask'::text NOT NULL,
    CONSTRAINT user_notification_prefs_mail_notifications_check CHECK ((mail_notifications = ANY (ARRAY['all'::text, 'important'::text, 'off'::text]))),
    CONSTRAINT user_notification_prefs_read_receipt_policy_check CHECK ((read_receipt_policy = ANY (ARRAY['ask'::text, 'always'::text, 'never'::text])))
);


--
-- Name: user_notification_prefs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_notification_prefs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_notification_prefs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_notification_prefs_id_seq OWNED BY public.user_notification_prefs.id;


--
-- Name: user_sender_list; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_sender_list (
    user_id bigint NOT NULL,
    sender text NOT NULL,
    list_type text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_sender_list_list_type_check CHECK ((list_type = ANY (ARRAY['safe'::text, 'blocked'::text])))
);


--
-- Name: user_signatures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_signatures (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    alias_email text NOT NULL,
    signature_html text DEFAULT ''::text NOT NULL,
    signature_text text DEFAULT ''::text NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    default_for text DEFAULT 'none'::text NOT NULL,
    CONSTRAINT user_signatures_default_for_check CHECK ((default_for = ANY (ARRAY['new'::text, 'reply'::text, 'both'::text, 'none'::text])))
);


--
-- Name: TABLE user_signatures; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.user_signatures IS 'Per-alias HTML/text signatures. One row per (user, alias_email) pair. Clients pick the signature matching the From address in compose.';


--
-- Name: user_signatures_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_signatures_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_signatures_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_signatures_id_seq OWNED BY public.user_signatures.id;


--
-- Name: user_smime_certs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_smime_certs (
    id bigint NOT NULL,
    user_id bigint NOT NULL,
    label text DEFAULT ''::text NOT NULL,
    cert_pem text NOT NULL,
    private_key_enc text,
    issued_at timestamp with time zone,
    expires_at timestamp with time zone,
    is_default boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: user_smime_certs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_smime_certs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_smime_certs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_smime_certs_id_seq OWNED BY public.user_smime_certs.id;


--
-- Name: user_spam_model; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_spam_model (
    user_id bigint NOT NULL,
    model_bytes bytea NOT NULL,
    trained_at timestamp with time zone DEFAULT now() NOT NULL,
    sample_count integer DEFAULT 0 NOT NULL,
    disabled boolean DEFAULT false NOT NULL,
    fp_count bigint DEFAULT 0 NOT NULL,
    fn_count bigint DEFAULT 0 NOT NULL,
    classified_count bigint DEFAULT 0 NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id bigint NOT NULL,
    username text NOT NULL,
    domain_id bigint NOT NULL,
    email text NOT NULL,
    display_name text NOT NULL,
    first_name text,
    last_name text,
    job_title text,
    phone text,
    manager_id bigint,
    department_id bigint,
    avatar_sha256 text,
    password_hash text,
    must_change_password boolean DEFAULT false NOT NULL,
    is_local_admin boolean DEFAULT false NOT NULL,
    ad_object_guid uuid,
    ad_usn_changed bigint,
    ad_sam_account text,
    ad_upn text,
    sync_source text DEFAULT 'local'::text NOT NULL,
    local_overrides jsonb DEFAULT '{}'::jsonb NOT NULL,
    last_synced_at timestamp with time zone,
    krb5_principal text,
    saml_name_id text,
    saml_session_index text,
    saml_idp_entity_id text,
    oidc_subject text,
    oidc_issuer text,
    oidc_provider text,
    webauthn_credentials jsonb DEFAULT '[]'::jsonb NOT NULL,
    webauthn_user_handle bytea,
    totp_secret_enc text,
    totp_enabled boolean DEFAULT false NOT NULL,
    totp_enabled_at timestamp with time zone,
    last_totp_used_at timestamp with time zone,
    totp_failed_attempts integer DEFAULT 0 NOT NULL,
    totp_locked_until timestamp with time zone,
    mfa_exempt boolean DEFAULT false NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    is_admin boolean DEFAULT false NOT NULL,
    last_login_at timestamp with time zone,
    last_login_ip inet,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    admin_role text,
    push_mfa_enabled boolean DEFAULT false NOT NULL,
    totp_backup_codes_enc text[],
    last_login_country text,
    scim_external_id text,
    view_prefs jsonb,
    external_sender_warning boolean DEFAULT true NOT NULL,
    CONSTRAINT users_admin_role_check CHECK ((admin_role = ANY (ARRAY['super_admin'::text, 'user_admin'::text, 'read_only'::text, 'auditor'::text]))),
    CONSTRAINT users_display_name_check CHECK ((display_name <> ''::text)),
    CONSTRAINT users_email_check CHECK ((email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'::text)),
    CONSTRAINT users_sync_source_check CHECK ((sync_source = ANY (ARRAY['local'::text, 'ad'::text, 'ldap'::text, 'scim'::text, 'sso'::text]))),
    CONSTRAINT users_username_check CHECK ((username <> ''::text))
);


--
-- Name: COLUMN users.view_prefs; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.view_prefs IS 'Per-user view preferences: {default_view, reading_pane, sender_images, ext_sender_warning, smart_mute}. NULL → use defaults on the client.';


--
-- Name: COLUMN users.external_sender_warning; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.external_sender_warning IS 'Per-user toggle for external sender warning banners. TRUE = show amber warning on messages from outside the organization.';


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: vacation_replies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vacation_replies (
    sender_email text NOT NULL,
    mailbox_id bigint NOT NULL,
    vacation_start date NOT NULL,
    replied_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: vote_responses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vote_responses (
    id bigint NOT NULL,
    message_id bigint NOT NULL,
    received_at timestamp with time zone NOT NULL,
    voter_email text NOT NULL,
    vote_option text NOT NULL,
    voted_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: vote_responses_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vote_responses_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vote_responses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vote_responses_id_seq OWNED BY public.vote_responses.id;


--
-- Name: vt_timezone; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vt_timezone (
    id bigint NOT NULL,
    calendar_id bigint NOT NULL,
    tzid text NOT NULL,
    standard jsonb,
    daylight jsonb
);


--
-- Name: vt_timezone_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vt_timezone_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vt_timezone_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vt_timezone_id_seq OWNED BY public.vt_timezone.id;


--
-- Name: webhook_deliveries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_deliveries (
    id bigint NOT NULL,
    subscription_id bigint NOT NULL,
    event_id text NOT NULL,
    event_type text NOT NULL,
    request_body jsonb NOT NULL,
    response_code integer,
    response_body text,
    latency_ms integer,
    attempt integer DEFAULT 1 NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT webhook_deliveries_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'success'::text, 'failed'::text, 'exhausted'::text])))
);


--
-- Name: webhook_deliveries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.webhook_deliveries_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: webhook_deliveries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.webhook_deliveries_id_seq OWNED BY public.webhook_deliveries.id;


--
-- Name: webhook_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_subscriptions (
    id bigint NOT NULL,
    user_id bigint,
    url text NOT NULL,
    secret text NOT NULL,
    prev_secret text,
    event_types jsonb DEFAULT '[]'::jsonb NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    retry_enabled boolean DEFAULT true NOT NULL,
    max_retries integer DEFAULT 12 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: webhook_subscriptions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.webhook_subscriptions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: webhook_subscriptions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.webhook_subscriptions_id_seq OWNED BY public.webhook_subscriptions.id;


--
-- Name: ws_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.ws_subscriptions (
    connection_id text NOT NULL,
    session_id text NOT NULL,
    user_id bigint NOT NULL,
    mailbox_ids bigint[] DEFAULT '{}'::bigint[] NOT NULL,
    calendar_ids bigint[] DEFAULT '{}'::bigint[] NOT NULL,
    subscribed_at timestamp with time zone DEFAULT now() NOT NULL,
    last_ping_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: audit_log_2026_05; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log ATTACH PARTITION public.audit_log_2026_05 FOR VALUES FROM ('2026-05-01 00:00:00+08') TO ('2026-06-01 00:00:00+08');


--
-- Name: auth_attempts_2026_05; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_attempts ATTACH PARTITION public.auth_attempts_2026_05 FOR VALUES FROM ('2026-05-01 00:00:00+08') TO ('2026-06-01 00:00:00+08');


--
-- Name: mailbox_audit_log_2026_06; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailbox_audit_log ATTACH PARTITION public.mailbox_audit_log_2026_06 FOR VALUES FROM ('2026-06-01 00:00:00+08') TO ('2026-07-01 00:00:00+08');


--
-- Name: mailbox_audit_log_2026_07; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailbox_audit_log ATTACH PARTITION public.mailbox_audit_log_2026_07 FOR VALUES FROM ('2026-07-01 00:00:00+08') TO ('2026-08-01 00:00:00+08');


--
-- Name: mailbox_audit_log_default; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailbox_audit_log ATTACH PARTITION public.mailbox_audit_log_default DEFAULT;


--
-- Name: message_tags_default; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_tags ATTACH PARTITION public.message_tags_default DEFAULT;


--
-- Name: message_trace_2026_06; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_trace ATTACH PARTITION public.message_trace_2026_06 FOR VALUES FROM ('2026-06-01 00:00:00+08') TO ('2026-07-01 00:00:00+08');


--
-- Name: message_trace_2026_07; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_trace ATTACH PARTITION public.message_trace_2026_07 FOR VALUES FROM ('2026-07-01 00:00:00+08') TO ('2026-08-01 00:00:00+08');


--
-- Name: message_trace_default; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_trace ATTACH PARTITION public.message_trace_default DEFAULT;


--
-- Name: messages_2026_06; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages ATTACH PARTITION public.messages_2026_06 FOR VALUES FROM ('2026-06-01 00:00:00+08') TO ('2026-07-01 00:00:00+08');


--
-- Name: messages_2026_07; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages ATTACH PARTITION public.messages_2026_07 FOR VALUES FROM ('2026-07-01 00:00:00+08') TO ('2026-08-01 00:00:00+08');


--
-- Name: messages_default; Type: TABLE ATTACH; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages ATTACH PARTITION public.messages_default DEFAULT;


--
-- Name: addressbooks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.addressbooks ALTER COLUMN id SET DEFAULT nextval('public.addressbooks_id_seq'::regclass);


--
-- Name: admin_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_audit_log ALTER COLUMN id SET DEFAULT nextval('public.admin_audit_log_id_seq'::regclass);


--
-- Name: admin_role_assignments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_role_assignments ALTER COLUMN id SET DEFAULT nextval('public.admin_role_assignments_id_seq'::regclass);


--
-- Name: admin_role_groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_role_groups ALTER COLUMN id SET DEFAULT nextval('public.admin_role_groups_id_seq'::regclass);


--
-- Name: aliases id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aliases ALTER COLUMN id SET DEFAULT nextval('public.aliases_id_seq'::regclass);


--
-- Name: app_passwords id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_passwords ALTER COLUMN id SET DEFAULT nextval('public.app_passwords_id_seq'::regclass);


--
-- Name: audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log ALTER COLUMN id SET DEFAULT nextval('public.audit_log_id_seq'::regclass);


--
-- Name: auth_attempts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_attempts ALTER COLUMN id SET DEFAULT nextval('public.auth_attempts_id_seq'::regclass);


--
-- Name: auth_event_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_event_log ALTER COLUMN id SET DEFAULT nextval('public.auth_event_log_id_seq'::regclass);


--
-- Name: auth_methods id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_methods ALTER COLUMN id SET DEFAULT nextval('public.auth_methods_id_seq'::regclass);


--
-- Name: calendar_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_events ALTER COLUMN id SET DEFAULT nextval('public.calendar_events_id_seq'::regclass);


--
-- Name: calendars id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendars ALTER COLUMN id SET DEFAULT nextval('public.calendars_id_seq'::regclass);


--
-- Name: common_passwords id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.common_passwords ALTER COLUMN id SET DEFAULT nextval('public.common_passwords_id_seq'::regclass);


--
-- Name: conditional_access_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conditional_access_policies ALTER COLUMN id SET DEFAULT nextval('public.conditional_access_policies_id_seq'::regclass);


--
-- Name: contact_group_members id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_group_members ALTER COLUMN id SET DEFAULT nextval('public.contact_group_members_id_seq'::regclass);


--
-- Name: contact_groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_groups ALTER COLUMN id SET DEFAULT nextval('public.contact_groups_id_seq'::regclass);


--
-- Name: contacts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts ALTER COLUMN id SET DEFAULT nextval('public.contacts_id_seq'::regclass);


--
-- Name: crash_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.crash_events ALTER COLUMN id SET DEFAULT nextval('public.crash_events_id_seq'::regclass);


--
-- Name: cron_run_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cron_run_log ALTER COLUMN id SET DEFAULT nextval('public.cron_run_log_id_seq'::regclass);


--
-- Name: departments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.departments ALTER COLUMN id SET DEFAULT nextval('public.departments_id_seq'::regclass);


--
-- Name: device_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_events ALTER COLUMN id SET DEFAULT nextval('public.device_events_id_seq'::regclass);


--
-- Name: device_policy id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_policy ALTER COLUMN id SET DEFAULT nextval('public.device_policy_id_seq'::regclass);


--
-- Name: device_policy_groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_policy_groups ALTER COLUMN id SET DEFAULT nextval('public.device_policy_groups_id_seq'::regclass);


--
-- Name: device_registry id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_registry ALTER COLUMN id SET DEFAULT nextval('public.device_registry_id_seq'::regclass);


--
-- Name: device_telemetry id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_telemetry ALTER COLUMN id SET DEFAULT nextval('public.device_telemetry_id_seq'::regclass);


--
-- Name: devices id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.devices ALTER COLUMN id SET DEFAULT nextval('public.devices_id_seq'::regclass);


--
-- Name: directory_connectors id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.directory_connectors ALTER COLUMN id SET DEFAULT nextval('public.directory_connectors_id_seq'::regclass);


--
-- Name: distribution_groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distribution_groups ALTER COLUMN id SET DEFAULT nextval('public.distribution_groups_id_seq'::regclass);


--
-- Name: dlp_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dlp_policies ALTER COLUMN id SET DEFAULT nextval('public.dlp_policies_id_seq'::regclass);


--
-- Name: dlp_violations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dlp_violations ALTER COLUMN id SET DEFAULT nextval('public.dlp_violations_id_seq'::regclass);


--
-- Name: dmarc_forensic_reports id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dmarc_forensic_reports ALTER COLUMN id SET DEFAULT nextval('public.dmarc_forensic_reports_id_seq'::regclass);


--
-- Name: dmarc_reports id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dmarc_reports ALTER COLUMN id SET DEFAULT nextval('public.dmarc_reports_id_seq'::regclass);


--
-- Name: domain_signing_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domain_signing_keys ALTER COLUMN id SET DEFAULT nextval('public.domain_signing_keys_id_seq'::regclass);


--
-- Name: domains id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domains ALTER COLUMN id SET DEFAULT nextval('public.domains_id_seq'::regclass);


--
-- Name: ediscovery_cases id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ediscovery_cases ALTER COLUMN id SET DEFAULT nextval('public.ediscovery_cases_id_seq'::regclass);


--
-- Name: ediscovery_searches id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ediscovery_searches ALTER COLUMN id SET DEFAULT nextval('public.ediscovery_searches_id_seq'::regclass);


--
-- Name: email_templates id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_templates ALTER COLUMN id SET DEFAULT nextval('public.email_templates_id_seq'::regclass);


--
-- Name: event_attendees id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_attendees ALTER COLUMN id SET DEFAULT nextval('public.event_attendees_id_seq'::regclass);


--
-- Name: folders id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.folders ALTER COLUMN id SET DEFAULT nextval('public.folders_id_seq'::regclass);


--
-- Name: greylist_whitelist id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.greylist_whitelist ALTER COLUMN id SET DEFAULT nextval('public.greylist_whitelist_id_seq'::regclass);


--
-- Name: health_history id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.health_history ALTER COLUMN id SET DEFAULT nextval('public.health_history_id_seq'::regclass);


--
-- Name: identity_sync_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_sync_log ALTER COLUMN id SET DEFAULT nextval('public.identity_sync_log_id_seq'::regclass);


--
-- Name: ip_rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_rules ALTER COLUMN id SET DEFAULT nextval('public.ip_rules_id_seq'::regclass);


--
-- Name: journal_queue id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.journal_queue ALTER COLUMN id SET DEFAULT nextval('public.journal_queue_id_seq'::regclass);


--
-- Name: journaling_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.journaling_policies ALTER COLUMN id SET DEFAULT nextval('public.journaling_policies_id_seq'::regclass);


--
-- Name: link_protect_audit id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.link_protect_audit ALTER COLUMN id SET DEFAULT nextval('public.link_protect_audit_id_seq'::regclass);


--
-- Name: login_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_events ALTER COLUMN id SET DEFAULT nextval('public.login_events_id_seq'::regclass);


--
-- Name: mailbox_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailbox_audit_log ALTER COLUMN id SET DEFAULT nextval('public.mailbox_audit_log_id_seq'::regclass);


--
-- Name: mailboxes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailboxes ALTER COLUMN id SET DEFAULT nextval('public.mailboxes_id_seq'::regclass);


--
-- Name: mdm_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mdm_policies ALTER COLUMN id SET DEFAULT nextval('public.mdm_policies_id_seq'::regclass);


--
-- Name: message_attachments id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_attachments ALTER COLUMN id SET DEFAULT nextval('public.message_attachments_id_seq'::regclass);


--
-- Name: message_trace id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_trace ALTER COLUMN id SET DEFAULT nextval('public.message_trace_id_seq'::regclass);


--
-- Name: messages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages ALTER COLUMN id SET DEFAULT nextval('public.messages_id_seq'::regclass);


--
-- Name: migration_jobs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.migration_jobs ALTER COLUMN id SET DEFAULT nextval('public.migration_jobs_id_seq'::regclass);


--
-- Name: oauth_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_tokens ALTER COLUMN id SET DEFAULT nextval('public.oauth_tokens_id_seq'::regclass);


--
-- Name: outbound_queue id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.outbound_queue ALTER COLUMN id SET DEFAULT nextval('public.outbound_queue_id_seq'::regclass);


--
-- Name: password_history id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_history ALTER COLUMN id SET DEFAULT nextval('public.password_history_id_seq'::regclass);


--
-- Name: push_devices id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_devices ALTER COLUMN id SET DEFAULT nextval('public.push_devices_id_seq'::regclass);


--
-- Name: push_mfa_challenges id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_mfa_challenges ALTER COLUMN id SET DEFAULT nextval('public.push_mfa_challenges_id_seq'::regclass);


--
-- Name: quarantined_messages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quarantined_messages ALTER COLUMN id SET DEFAULT nextval('public.quarantined_messages_id_seq'::regclass);


--
-- Name: quick_steps id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quick_steps ALTER COLUMN id SET DEFAULT nextval('public.quick_steps_id_seq'::regclass);


--
-- Name: read_receipts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.read_receipts ALTER COLUMN id SET DEFAULT nextval('public.read_receipts_id_seq'::regclass);


--
-- Name: reminders id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reminders ALTER COLUMN id SET DEFAULT nextval('public.reminders_id_seq'::regclass);


--
-- Name: retention_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.retention_policies ALTER COLUMN id SET DEFAULT nextval('public.retention_policies_id_seq'::regclass);


--
-- Name: rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rules ALTER COLUMN id SET DEFAULT nextval('public.rules_id_seq'::regclass);


--
-- Name: saml_sp_registrations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_sp_registrations ALTER COLUMN id SET DEFAULT nextval('public.saml_sp_registrations_id_seq'::regclass);


--
-- Name: scheduled_action_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduled_action_log ALTER COLUMN id SET DEFAULT nextval('public.scheduled_action_log_id_seq'::regclass);


--
-- Name: scim_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scim_tokens ALTER COLUMN id SET DEFAULT nextval('public.scim_tokens_id_seq'::regclass);


--
-- Name: signatures id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signatures ALTER COLUMN id SET DEFAULT nextval('public.signatures_id_seq'::regclass);


--
-- Name: signing_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signing_keys ALTER COLUMN id SET DEFAULT nextval('public.signing_keys_id_seq'::regclass);


--
-- Name: storage_dr_scans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.storage_dr_scans ALTER COLUMN id SET DEFAULT nextval('public.storage_dr_scans_id_seq'::regclass);


--
-- Name: storage_migrations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.storage_migrations ALTER COLUMN id SET DEFAULT nextval('public.storage_migrations_id_seq'::regclass);


--
-- Name: sync_conflicts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sync_conflicts ALTER COLUMN id SET DEFAULT nextval('public.sync_conflicts_id_seq'::regclass);


--
-- Name: tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags ALTER COLUMN id SET DEFAULT nextval('public.tags_id_seq'::regclass);


--
-- Name: tasks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks ALTER COLUMN id SET DEFAULT nextval('public.tasks_id_seq'::regclass);


--
-- Name: upgrade_history id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.upgrade_history ALTER COLUMN id SET DEFAULT nextval('public.upgrade_history_id_seq'::regclass);


--
-- Name: user_devices id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_devices ALTER COLUMN id SET DEFAULT nextval('public.user_devices_id_seq'::regclass);


--
-- Name: user_notification_prefs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_notification_prefs ALTER COLUMN id SET DEFAULT nextval('public.user_notification_prefs_id_seq'::regclass);


--
-- Name: user_signatures id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_signatures ALTER COLUMN id SET DEFAULT nextval('public.user_signatures_id_seq'::regclass);


--
-- Name: user_smime_certs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_smime_certs ALTER COLUMN id SET DEFAULT nextval('public.user_smime_certs_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Name: vote_responses id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vote_responses ALTER COLUMN id SET DEFAULT nextval('public.vote_responses_id_seq'::regclass);


--
-- Name: vt_timezone id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vt_timezone ALTER COLUMN id SET DEFAULT nextval('public.vt_timezone_id_seq'::regclass);


--
-- Name: webhook_deliveries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries ALTER COLUMN id SET DEFAULT nextval('public.webhook_deliveries_id_seq'::regclass);


--
-- Name: webhook_subscriptions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_subscriptions ALTER COLUMN id SET DEFAULT nextval('public.webhook_subscriptions_id_seq'::regclass);


--
-- Name: addressbooks addressbooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.addressbooks
    ADD CONSTRAINT addressbooks_pkey PRIMARY KEY (id);


--
-- Name: admin_audit_log admin_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_audit_log
    ADD CONSTRAINT admin_audit_log_pkey PRIMARY KEY (id);


--
-- Name: admin_permissions admin_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_permissions
    ADD CONSTRAINT admin_permissions_pkey PRIMARY KEY (permission_key);


--
-- Name: admin_role_assignments admin_role_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_role_assignments
    ADD CONSTRAINT admin_role_assignments_pkey PRIMARY KEY (id);


--
-- Name: admin_role_assignments admin_role_assignments_user_id_role_group_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_role_assignments
    ADD CONSTRAINT admin_role_assignments_user_id_role_group_id_key UNIQUE (user_id, role_group_id);


--
-- Name: admin_role_groups admin_role_groups_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_role_groups
    ADD CONSTRAINT admin_role_groups_name_key UNIQUE (name);


--
-- Name: admin_role_groups admin_role_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_role_groups
    ADD CONSTRAINT admin_role_groups_pkey PRIMARY KEY (id);


--
-- Name: aliases aliases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aliases
    ADD CONSTRAINT aliases_pkey PRIMARY KEY (id);


--
-- Name: app_passwords app_passwords_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_passwords
    ADD CONSTRAINT app_passwords_pkey PRIMARY KEY (id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: audit_log_2026_05 audit_log_2026_05_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log_2026_05
    ADD CONSTRAINT audit_log_2026_05_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: auth_attempts auth_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_attempts
    ADD CONSTRAINT auth_attempts_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: auth_attempts_2026_05 auth_attempts_2026_05_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_attempts_2026_05
    ADD CONSTRAINT auth_attempts_2026_05_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: auth_event_log auth_event_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_event_log
    ADD CONSTRAINT auth_event_log_pkey PRIMARY KEY (id);


--
-- Name: auth_lockouts auth_lockouts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_lockouts
    ADD CONSTRAINT auth_lockouts_pkey PRIMARY KEY (lockout_key);


--
-- Name: auth_methods auth_methods_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_methods
    ADD CONSTRAINT auth_methods_pkey PRIMARY KEY (id);


--
-- Name: auth_methods auth_methods_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_methods
    ADD CONSTRAINT auth_methods_slug_key UNIQUE (slug);


--
-- Name: blob_cleanup_queue blob_cleanup_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.blob_cleanup_queue
    ADD CONSTRAINT blob_cleanup_queue_pkey PRIMARY KEY (blob_sha256);


--
-- Name: blobs blobs_minio_ref_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.blobs
    ADD CONSTRAINT blobs_minio_ref_key UNIQUE (minio_ref);


--
-- Name: blobs blobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.blobs
    ADD CONSTRAINT blobs_pkey PRIMARY KEY (sha256);


--
-- Name: calendar_acls calendar_acls_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_acls
    ADD CONSTRAINT calendar_acls_pkey PRIMARY KEY (calendar_id, user_id);


--
-- Name: calendar_events calendar_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_events
    ADD CONSTRAINT calendar_events_pkey PRIMARY KEY (id);


--
-- Name: calendars calendars_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendars
    ADD CONSTRAINT calendars_pkey PRIMARY KEY (id);


--
-- Name: common_passwords common_passwords_password_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.common_passwords
    ADD CONSTRAINT common_passwords_password_hash_key UNIQUE (password_hash);


--
-- Name: common_passwords common_passwords_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.common_passwords
    ADD CONSTRAINT common_passwords_pkey PRIMARY KEY (id);


--
-- Name: conditional_access_policies conditional_access_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conditional_access_policies
    ADD CONSTRAINT conditional_access_policies_pkey PRIMARY KEY (id);


--
-- Name: contact_group_members contact_group_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_group_members
    ADD CONSTRAINT contact_group_members_pkey PRIMARY KEY (id);


--
-- Name: contact_groups contact_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_groups
    ADD CONSTRAINT contact_groups_pkey PRIMARY KEY (id);


--
-- Name: contacts contacts_addressbook_id_vcard_uid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts
    ADD CONSTRAINT contacts_addressbook_id_vcard_uid_key UNIQUE (addressbook_id, vcard_uid);


--
-- Name: contacts contacts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts
    ADD CONSTRAINT contacts_pkey PRIMARY KEY (id);


--
-- Name: crash_events crash_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.crash_events
    ADD CONSTRAINT crash_events_pkey PRIMARY KEY (id);


--
-- Name: cron_run_log cron_run_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cron_run_log
    ADD CONSTRAINT cron_run_log_pkey PRIMARY KEY (id);


--
-- Name: departments departments_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_path_key UNIQUE (path);


--
-- Name: departments departments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_pkey PRIMARY KEY (id);


--
-- Name: deployment_steps deployment_steps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.deployment_steps
    ADD CONSTRAINT deployment_steps_pkey PRIMARY KEY (step_name);


--
-- Name: device_events device_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_events
    ADD CONSTRAINT device_events_pkey PRIMARY KEY (id);


--
-- Name: device_policy device_policy_device_id_policy_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_policy
    ADD CONSTRAINT device_policy_device_id_policy_key_key UNIQUE (device_id, policy_key);


--
-- Name: device_policy_groups device_policy_groups_group_type_group_id_policy_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_policy_groups
    ADD CONSTRAINT device_policy_groups_group_type_group_id_policy_key_key UNIQUE (group_type, group_id, policy_key);


--
-- Name: device_policy_groups device_policy_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_policy_groups
    ADD CONSTRAINT device_policy_groups_pkey PRIMARY KEY (id);


--
-- Name: device_policy device_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_policy
    ADD CONSTRAINT device_policy_pkey PRIMARY KEY (id);


--
-- Name: device_registry device_registry_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_registry
    ADD CONSTRAINT device_registry_pkey PRIMARY KEY (id);


--
-- Name: device_registry device_registry_user_id_device_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_registry
    ADD CONSTRAINT device_registry_user_id_device_hash_key UNIQUE (user_id, device_hash);


--
-- Name: device_telemetry device_telemetry_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_telemetry
    ADD CONSTRAINT device_telemetry_pkey PRIMARY KEY (id);


--
-- Name: devices devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (id);


--
-- Name: devices devices_user_id_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_user_id_fingerprint_key UNIQUE (user_id, fingerprint);


--
-- Name: directory_connectors directory_connectors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.directory_connectors
    ADD CONSTRAINT directory_connectors_pkey PRIMARY KEY (id);


--
-- Name: distribution_group_members distribution_group_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distribution_group_members
    ADD CONSTRAINT distribution_group_members_pkey PRIMARY KEY (group_id, mailbox_id);


--
-- Name: distribution_groups distribution_groups_mailbox_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distribution_groups
    ADD CONSTRAINT distribution_groups_mailbox_id_key UNIQUE (mailbox_id);


--
-- Name: distribution_groups distribution_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distribution_groups
    ADD CONSTRAINT distribution_groups_pkey PRIMARY KEY (id);


--
-- Name: dlp_policies dlp_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dlp_policies
    ADD CONSTRAINT dlp_policies_pkey PRIMARY KEY (id);


--
-- Name: dlp_policy_targets dlp_policy_targets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dlp_policy_targets
    ADD CONSTRAINT dlp_policy_targets_pkey PRIMARY KEY (policy_id, mailbox_id);


--
-- Name: dlp_violations dlp_violations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dlp_violations
    ADD CONSTRAINT dlp_violations_pkey PRIMARY KEY (id);


--
-- Name: dmarc_forensic_reports dmarc_forensic_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dmarc_forensic_reports
    ADD CONSTRAINT dmarc_forensic_reports_pkey PRIMARY KEY (id);


--
-- Name: dmarc_reports dmarc_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dmarc_reports
    ADD CONSTRAINT dmarc_reports_pkey PRIMARY KEY (id);


--
-- Name: domain_signing_keys domain_signing_keys_domain_id_selector_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domain_signing_keys
    ADD CONSTRAINT domain_signing_keys_domain_id_selector_key UNIQUE (domain_id, selector);


--
-- Name: domain_signing_keys domain_signing_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domain_signing_keys
    ADD CONSTRAINT domain_signing_keys_pkey PRIMARY KEY (id);


--
-- Name: domains domains_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_name_key UNIQUE (name);


--
-- Name: domains domains_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_pkey PRIMARY KEY (id);


--
-- Name: ediscovery_cases ediscovery_cases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ediscovery_cases
    ADD CONSTRAINT ediscovery_cases_pkey PRIMARY KEY (id);


--
-- Name: ediscovery_searches ediscovery_searches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ediscovery_searches
    ADD CONSTRAINT ediscovery_searches_pkey PRIMARY KEY (id);


--
-- Name: email_templates email_templates_mailbox_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_templates
    ADD CONSTRAINT email_templates_mailbox_id_name_key UNIQUE (mailbox_id, name);


--
-- Name: email_templates email_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_templates
    ADD CONSTRAINT email_templates_pkey PRIMARY KEY (id);


--
-- Name: event_attendees event_attendees_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_attendees
    ADD CONSTRAINT event_attendees_pkey PRIMARY KEY (id);


--
-- Name: external_sender_config external_sender_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_sender_config
    ADD CONSTRAINT external_sender_config_pkey PRIMARY KEY (domain_id);


--
-- Name: feature_toggles feature_toggles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feature_toggles
    ADD CONSTRAINT feature_toggles_pkey PRIMARY KEY (key);


--
-- Name: field_policy field_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.field_policy
    ADD CONSTRAINT field_policy_pkey PRIMARY KEY (user_id, field);


--
-- Name: folders folders_mailbox_id_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.folders
    ADD CONSTRAINT folders_mailbox_id_path_key UNIQUE (mailbox_id, path);


--
-- Name: folders folders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.folders
    ADD CONSTRAINT folders_pkey PRIMARY KEY (id);


--
-- Name: geo_country_tiers geo_country_tiers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.geo_country_tiers
    ADD CONSTRAINT geo_country_tiers_pkey PRIMARY KEY (country_code);


--
-- Name: greylist greylist_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.greylist
    ADD CONSTRAINT greylist_pkey PRIMARY KEY (ip, sender, recipient);


--
-- Name: greylist_whitelist greylist_whitelist_entry_type_entry_value_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.greylist_whitelist
    ADD CONSTRAINT greylist_whitelist_entry_type_entry_value_key UNIQUE (entry_type, entry_value);


--
-- Name: greylist_whitelist greylist_whitelist_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.greylist_whitelist
    ADD CONSTRAINT greylist_whitelist_pkey PRIMARY KEY (id);


--
-- Name: health_alerts health_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.health_alerts
    ADD CONSTRAINT health_alerts_pkey PRIMARY KEY (check_name);


--
-- Name: health_history health_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.health_history
    ADD CONSTRAINT health_history_pkey PRIMARY KEY (id);


--
-- Name: identity_sync_log identity_sync_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_sync_log
    ADD CONSTRAINT identity_sync_log_pkey PRIMARY KEY (id);


--
-- Name: ip_rules ip_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_rules
    ADD CONSTRAINT ip_rules_pkey PRIMARY KEY (id);


--
-- Name: journal_queue journal_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.journal_queue
    ADD CONSTRAINT journal_queue_pkey PRIMARY KEY (id);


--
-- Name: journaling_policies journaling_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.journaling_policies
    ADD CONSTRAINT journaling_policies_pkey PRIMARY KEY (id);


--
-- Name: link_protect_audit link_protect_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.link_protect_audit
    ADD CONSTRAINT link_protect_audit_pkey PRIMARY KEY (id);


--
-- Name: login_events login_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_events
    ADD CONSTRAINT login_events_pkey PRIMARY KEY (id);


--
-- Name: mailbox_audit_log mailbox_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailbox_audit_log
    ADD CONSTRAINT mailbox_audit_log_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: mailbox_audit_log_2026_06 mailbox_audit_log_2026_06_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailbox_audit_log_2026_06
    ADD CONSTRAINT mailbox_audit_log_2026_06_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: mailbox_audit_log_2026_07 mailbox_audit_log_2026_07_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailbox_audit_log_2026_07
    ADD CONSTRAINT mailbox_audit_log_2026_07_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: mailbox_audit_log_default mailbox_audit_log_default_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailbox_audit_log_default
    ADD CONSTRAINT mailbox_audit_log_default_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: mailbox_delegates mailbox_delegates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailbox_delegates
    ADD CONSTRAINT mailbox_delegates_pkey PRIMARY KEY (mailbox_id, user_id, permission);


--
-- Name: mailboxes mailboxes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailboxes
    ADD CONSTRAINT mailboxes_pkey PRIMARY KEY (id);


--
-- Name: managed_devices managed_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_devices
    ADD CONSTRAINT managed_devices_pkey PRIMARY KEY (device_hash);


--
-- Name: mdm_device_state mdm_device_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mdm_device_state
    ADD CONSTRAINT mdm_device_state_pkey PRIMARY KEY (device_id);


--
-- Name: mdm_policies mdm_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mdm_policies
    ADD CONSTRAINT mdm_policies_pkey PRIMARY KEY (id);


--
-- Name: message_attachments message_attachments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_attachments
    ADD CONSTRAINT message_attachments_pkey PRIMARY KEY (id);


--
-- Name: message_recalls message_recalls_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_recalls
    ADD CONSTRAINT message_recalls_pkey PRIMARY KEY (message_id);


--
-- Name: message_retention_tags message_retention_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_retention_tags
    ADD CONSTRAINT message_retention_tags_pkey PRIMARY KEY (message_id, received_at);


--
-- Name: message_tags message_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_tags
    ADD CONSTRAINT message_tags_pkey PRIMARY KEY (message_id, received_at, tag_id);


--
-- Name: message_tags_default message_tags_default_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_tags_default
    ADD CONSTRAINT message_tags_default_pkey PRIMARY KEY (message_id, received_at, tag_id);


--
-- Name: message_trace message_trace_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_trace
    ADD CONSTRAINT message_trace_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: message_trace_2026_06 message_trace_2026_06_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_trace_2026_06
    ADD CONSTRAINT message_trace_2026_06_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: message_trace_2026_07 message_trace_2026_07_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_trace_2026_07
    ADD CONSTRAINT message_trace_2026_07_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: message_trace_default message_trace_default_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_trace_default
    ADD CONSTRAINT message_trace_default_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id, received_at);


--
-- Name: messages_2026_06 messages_2026_06_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages_2026_06
    ADD CONSTRAINT messages_2026_06_pkey PRIMARY KEY (id, received_at);


--
-- Name: messages_2026_07 messages_2026_07_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages_2026_07
    ADD CONSTRAINT messages_2026_07_pkey PRIMARY KEY (id, received_at);


--
-- Name: messages_default messages_default_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages_default
    ADD CONSTRAINT messages_default_pkey PRIMARY KEY (id, received_at);


--
-- Name: migration_jobs migration_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.migration_jobs
    ADD CONSTRAINT migration_jobs_pkey PRIMARY KEY (id);


--
-- Name: mta_sts_policies mta_sts_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mta_sts_policies
    ADD CONSTRAINT mta_sts_policies_pkey PRIMARY KEY (domain);


--
-- Name: oauth_tokens oauth_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_tokens
    ADD CONSTRAINT oauth_tokens_pkey PRIMARY KEY (id);


--
-- Name: oidc_auth_requests oidc_auth_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_auth_requests
    ADD CONSTRAINT oidc_auth_requests_pkey PRIMARY KEY (id);


--
-- Name: oidc_clients oidc_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_clients
    ADD CONSTRAINT oidc_clients_pkey PRIMARY KEY (id);


--
-- Name: oidc_tokens oidc_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_tokens
    ADD CONSTRAINT oidc_tokens_pkey PRIMARY KEY (id);


--
-- Name: orphaned_message_blobs orphaned_message_blobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.orphaned_message_blobs
    ADD CONSTRAINT orphaned_message_blobs_pkey PRIMARY KEY (raw_ref);


--
-- Name: outbound_queue_hot outbound_queue_hot_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.outbound_queue_hot
    ADD CONSTRAINT outbound_queue_hot_pkey PRIMARY KEY (id);


--
-- Name: outbound_queue outbound_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.outbound_queue
    ADD CONSTRAINT outbound_queue_pkey PRIMARY KEY (id);


--
-- Name: passkey_credentials passkey_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.passkey_credentials
    ADD CONSTRAINT passkey_credentials_pkey PRIMARY KEY (id);


--
-- Name: password_history password_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_history
    ADD CONSTRAINT password_history_pkey PRIMARY KEY (id);


--
-- Name: push_devices push_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_devices
    ADD CONSTRAINT push_devices_pkey PRIMARY KEY (id);


--
-- Name: push_mfa_challenges push_mfa_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_mfa_challenges
    ADD CONSTRAINT push_mfa_challenges_pkey PRIMARY KEY (id);


--
-- Name: quarantined_messages quarantined_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quarantined_messages
    ADD CONSTRAINT quarantined_messages_pkey PRIMARY KEY (id);


--
-- Name: quarantined_messages quarantined_messages_preview_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quarantined_messages
    ADD CONSTRAINT quarantined_messages_preview_token_key UNIQUE (preview_token);


--
-- Name: quick_steps quick_steps_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quick_steps
    ADD CONSTRAINT quick_steps_pkey PRIMARY KEY (id);


--
-- Name: rate_limit_counters rate_limit_counters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rate_limit_counters
    ADD CONSTRAINT rate_limit_counters_pkey PRIMARY KEY (key);


--
-- Name: read_receipts read_receipts_message_id_received_at_recipient_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.read_receipts
    ADD CONSTRAINT read_receipts_message_id_received_at_recipient_email_key UNIQUE (message_id, received_at, recipient_email);


--
-- Name: read_receipts read_receipts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.read_receipts
    ADD CONSTRAINT read_receipts_pkey PRIMARY KEY (id);


--
-- Name: reminders reminders_mailbox_id_source_type_source_id_fire_at_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reminders
    ADD CONSTRAINT reminders_mailbox_id_source_type_source_id_fire_at_key UNIQUE (mailbox_id, source_type, source_id, fire_at);


--
-- Name: reminders reminders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reminders
    ADD CONSTRAINT reminders_pkey PRIMARY KEY (id);


--
-- Name: retention_policies retention_policies_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.retention_policies
    ADD CONSTRAINT retention_policies_name_key UNIQUE (name);


--
-- Name: retention_policies retention_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.retention_policies
    ADD CONSTRAINT retention_policies_pkey PRIMARY KEY (id);


--
-- Name: rules rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_pkey PRIMARY KEY (id);


--
-- Name: saml_sp_registrations saml_sp_registrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saml_sp_registrations
    ADD CONSTRAINT saml_sp_registrations_pkey PRIMARY KEY (id);


--
-- Name: scheduled_action_log scheduled_action_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduled_action_log
    ADD CONSTRAINT scheduled_action_log_pkey PRIMARY KEY (id);


--
-- Name: scheduled_actions scheduled_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduled_actions
    ADD CONSTRAINT scheduled_actions_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: scim_tokens scim_tokens_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scim_tokens
    ADD CONSTRAINT scim_tokens_name_key UNIQUE (name);


--
-- Name: scim_tokens scim_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scim_tokens
    ADD CONSTRAINT scim_tokens_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_token_hash_key UNIQUE (token_hash);


--
-- Name: signatures signatures_mailbox_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signatures
    ADD CONSTRAINT signatures_mailbox_id_name_key UNIQUE (mailbox_id, name);


--
-- Name: signatures signatures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signatures
    ADD CONSTRAINT signatures_pkey PRIMARY KEY (id);


--
-- Name: signing_keys signing_keys_kid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signing_keys
    ADD CONSTRAINT signing_keys_kid_key UNIQUE (kid);


--
-- Name: signing_keys signing_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signing_keys
    ADD CONSTRAINT signing_keys_pkey PRIMARY KEY (id);


--
-- Name: smtp_sessions smtp_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smtp_sessions
    ADD CONSTRAINT smtp_sessions_pkey PRIMARY KEY (id);


--
-- Name: storage_dr_scans storage_dr_scans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.storage_dr_scans
    ADD CONSTRAINT storage_dr_scans_pkey PRIMARY KEY (id);


--
-- Name: storage_migrations storage_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.storage_migrations
    ADD CONSTRAINT storage_migrations_pkey PRIMARY KEY (id);


--
-- Name: sync_conflicts sync_conflicts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sync_conflicts
    ADD CONSTRAINT sync_conflicts_pkey PRIMARY KEY (id);


--
-- Name: system_config system_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_config
    ADD CONSTRAINT system_config_pkey PRIMARY KEY (key);


--
-- Name: tags tags_mailbox_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_mailbox_id_name_key UNIQUE (mailbox_id, name);


--
-- Name: tags tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_pkey PRIMARY KEY (id);


--
-- Name: tasks tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT tasks_pkey PRIMARY KEY (id);


--
-- Name: threat_feed_blocks threat_feed_blocks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_feed_blocks
    ADD CONSTRAINT threat_feed_blocks_pkey PRIMARY KEY (cidr);


--
-- Name: upgrade_history upgrade_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.upgrade_history
    ADD CONSTRAINT upgrade_history_pkey PRIMARY KEY (id);


--
-- Name: used_password_reset_tokens used_password_reset_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.used_password_reset_tokens
    ADD CONSTRAINT used_password_reset_tokens_pkey PRIMARY KEY (token_hash);


--
-- Name: used_saml_assertions used_saml_assertions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.used_saml_assertions
    ADD CONSTRAINT used_saml_assertions_pkey PRIMARY KEY (assertion_id);


--
-- Name: user_app_entitlements user_app_entitlements_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_app_entitlements
    ADD CONSTRAINT user_app_entitlements_pkey PRIMARY KEY (user_id, app);


--
-- Name: user_devices user_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_devices
    ADD CONSTRAINT user_devices_pkey PRIMARY KEY (id);


--
-- Name: user_imap_settings user_imap_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_imap_settings
    ADD CONSTRAINT user_imap_settings_pkey PRIMARY KEY (user_id);


--
-- Name: user_notification_prefs user_notification_prefs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_notification_prefs
    ADD CONSTRAINT user_notification_prefs_pkey PRIMARY KEY (id);


--
-- Name: user_notification_prefs user_notification_prefs_user_id_device_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_notification_prefs
    ADD CONSTRAINT user_notification_prefs_user_id_device_fingerprint_key UNIQUE (user_id, device_fingerprint);


--
-- Name: user_sender_list user_sender_list_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sender_list
    ADD CONSTRAINT user_sender_list_pkey PRIMARY KEY (user_id, sender, list_type);


--
-- Name: user_signatures user_signatures_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_signatures
    ADD CONSTRAINT user_signatures_pkey PRIMARY KEY (id);


--
-- Name: user_smime_certs user_smime_certs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_smime_certs
    ADD CONSTRAINT user_smime_certs_pkey PRIMARY KEY (id);


--
-- Name: user_smime_certs user_smime_certs_user_id_label_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_smime_certs
    ADD CONSTRAINT user_smime_certs_user_id_label_key UNIQUE (user_id, label);


--
-- Name: user_spam_model user_spam_model_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_spam_model
    ADD CONSTRAINT user_spam_model_pkey PRIMARY KEY (user_id);


--
-- Name: users users_ad_object_guid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_ad_object_guid_key UNIQUE (ad_object_guid);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_domain_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_domain_id_key UNIQUE (username, domain_id);


--
-- Name: vacation_replies vacation_replies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vacation_replies
    ADD CONSTRAINT vacation_replies_pkey PRIMARY KEY (sender_email, mailbox_id, vacation_start);


--
-- Name: vacation_settings vacation_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vacation_settings
    ADD CONSTRAINT vacation_settings_pkey PRIMARY KEY (mailbox_id);


--
-- Name: vote_responses vote_responses_message_id_received_at_voter_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vote_responses
    ADD CONSTRAINT vote_responses_message_id_received_at_voter_email_key UNIQUE (message_id, received_at, voter_email);


--
-- Name: vote_responses vote_responses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vote_responses
    ADD CONSTRAINT vote_responses_pkey PRIMARY KEY (id);


--
-- Name: vt_timezone vt_timezone_calendar_id_tzid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vt_timezone
    ADD CONSTRAINT vt_timezone_calendar_id_tzid_key UNIQUE (calendar_id, tzid);


--
-- Name: vt_timezone vt_timezone_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vt_timezone
    ADD CONSTRAINT vt_timezone_pkey PRIMARY KEY (id);


--
-- Name: webhook_deliveries webhook_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_pkey PRIMARY KEY (id);


--
-- Name: webhook_subscriptions webhook_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_subscriptions
    ADD CONSTRAINT webhook_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: ws_subscriptions ws_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ws_subscriptions
    ADD CONSTRAINT ws_subscriptions_pkey PRIMARY KEY (connection_id);


--
-- Name: addressbooks_default_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX addressbooks_default_idx ON public.addressbooks USING btree (mailbox_id) WHERE is_default;


--
-- Name: addressbooks_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX addressbooks_mailbox_idx ON public.addressbooks USING btree (mailbox_id);


--
-- Name: admin_audit_target_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_audit_target_idx ON public.admin_audit_log USING btree (target_type, target_id, occurred_at DESC);


--
-- Name: admin_audit_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_audit_time_idx ON public.admin_audit_log USING btree (occurred_at DESC);


--
-- Name: admin_audit_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_audit_user_idx ON public.admin_audit_log USING btree (user_id, occurred_at DESC);


--
-- Name: aliases_email_lower_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX aliases_email_lower_idx ON public.aliases USING btree (lower(email));


--
-- Name: aliases_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX aliases_mailbox_idx ON public.aliases USING btree (mailbox_id);


--
-- Name: antiphish_contact_graph_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX antiphish_contact_graph_idx ON public.antiphish_contact_graph USING btree (mailbox_id, sender_email);


--
-- Name: app_passwords_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX app_passwords_user_idx ON public.app_passwords USING btree (user_id) WHERE (revoked_at IS NULL);


--
-- Name: attachments_blob_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX attachments_blob_idx ON public.message_attachments USING btree (blob_sha256);


--
-- Name: attachments_cid_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX attachments_cid_idx ON public.message_attachments USING btree (content_id) WHERE (content_id IS NOT NULL);


--
-- Name: attachments_message_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX attachments_message_idx ON public.message_attachments USING btree (message_id, received_at);


--
-- Name: attendees_email_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX attendees_email_idx ON public.event_attendees USING btree (email);


--
-- Name: attendees_event_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX attendees_event_idx ON public.event_attendees USING btree (event_id);


--
-- Name: audit_log_event_type_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_event_type_idx ON ONLY public.audit_log USING btree (event_type, occurred_at DESC);


--
-- Name: audit_log_2026_05_event_type_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_2026_05_event_type_occurred_at_idx ON public.audit_log_2026_05 USING btree (event_type, occurred_at DESC);


--
-- Name: audit_log_ip_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_ip_idx ON ONLY public.audit_log USING btree (source_ip, occurred_at DESC);


--
-- Name: audit_log_2026_05_source_ip_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_2026_05_source_ip_occurred_at_idx ON public.audit_log_2026_05 USING btree (source_ip, occurred_at DESC);


--
-- Name: audit_log_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_user_idx ON ONLY public.audit_log USING btree (user_id, occurred_at DESC);


--
-- Name: audit_log_2026_05_user_id_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_2026_05_user_id_occurred_at_idx ON public.audit_log_2026_05 USING btree (user_id, occurred_at DESC);


--
-- Name: auth_attempts_ip_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_attempts_ip_time_idx ON ONLY public.auth_attempts USING btree (source_ip, occurred_at DESC);


--
-- Name: auth_attempts_2026_05_source_ip_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_attempts_2026_05_source_ip_occurred_at_idx ON public.auth_attempts_2026_05 USING btree (source_ip, occurred_at DESC);


--
-- Name: auth_attempts_user_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_attempts_user_time_idx ON ONLY public.auth_attempts USING btree (target_username, occurred_at DESC);


--
-- Name: auth_attempts_2026_05_target_username_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_attempts_2026_05_target_username_occurred_at_idx ON public.auth_attempts_2026_05 USING btree (target_username, occurred_at DESC);


--
-- Name: auth_event_log_email_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_event_log_email_idx ON public.auth_event_log USING btree (email) WHERE (email IS NOT NULL);


--
-- Name: auth_event_log_ip_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_event_log_ip_idx ON public.auth_event_log USING btree (ip_address) WHERE (ip_address IS NOT NULL);


--
-- Name: auth_event_log_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_event_log_time_idx ON public.auth_event_log USING btree (occurred_at DESC);


--
-- Name: auth_event_log_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_event_log_user_idx ON public.auth_event_log USING btree (user_id, occurred_at DESC);


--
-- Name: auth_methods_priority_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX auth_methods_priority_idx ON public.auth_methods USING btree (priority) WHERE (enabled = true);


--
-- Name: ca_policies_priority_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ca_policies_priority_idx ON public.conditional_access_policies USING btree (priority);


--
-- Name: ca_policies_priority_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ca_policies_priority_unique_idx ON public.conditional_access_policies USING btree (priority) WHERE enabled;


--
-- Name: calendar_acls_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_acls_user_idx ON public.calendar_acls USING btree (user_id);


--
-- Name: calendar_events_calendar_id_uid_recurrence_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX calendar_events_calendar_id_uid_recurrence_key ON public.calendar_events USING btree (calendar_id, uid, recurrence_override) NULLS NOT DISTINCT;


--
-- Name: calendar_events_parent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendar_events_parent_idx ON public.calendar_events USING btree (parent_event_uid, recurrence_override) WHERE (parent_event_uid IS NOT NULL);


--
-- Name: calendars_default_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX calendars_default_idx ON public.calendars USING btree (mailbox_id) WHERE is_default;


--
-- Name: calendars_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendars_mailbox_idx ON public.calendars USING btree (mailbox_id);


--
-- Name: calendars_resource_type_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX calendars_resource_type_idx ON public.calendars USING btree (resource_type) WHERE (resource_type <> 'personal'::text);


--
-- Name: cgm_contact_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX cgm_contact_uniq ON public.contact_group_members USING btree (group_id, contact_id) WHERE (contact_id IS NOT NULL);


--
-- Name: cgm_email_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX cgm_email_uniq ON public.contact_group_members USING btree (group_id, lower(email)) WHERE (email IS NOT NULL);


--
-- Name: cgm_group_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX cgm_group_idx ON public.contact_group_members USING btree (group_id);


--
-- Name: contact_groups_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX contact_groups_mailbox_idx ON public.contact_groups USING btree (mailbox_id);


--
-- Name: contact_groups_name_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX contact_groups_name_idx ON public.contact_groups USING btree (mailbox_id, lower(name));


--
-- Name: contacts_addressbook_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX contacts_addressbook_idx ON public.contacts USING btree (addressbook_id);


--
-- Name: contacts_avatar_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX contacts_avatar_idx ON public.contacts USING btree (avatar_sha256) WHERE (avatar_sha256 IS NOT NULL);


--
-- Name: contacts_categories_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX contacts_categories_idx ON public.contacts USING gin (categories);


--
-- Name: contacts_company_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX contacts_company_idx ON public.contacts USING btree (company) WHERE (company IS NOT NULL);


--
-- Name: contacts_display_name_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX contacts_display_name_idx ON public.contacts USING btree (display_name);


--
-- Name: contacts_name_trgm_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX contacts_name_trgm_idx ON public.contacts USING gin (display_name public.gin_trgm_ops);


--
-- Name: contacts_vcard_uid_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX contacts_vcard_uid_idx ON public.contacts USING btree (vcard_uid);


--
-- Name: departments_parent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX departments_parent_idx ON public.departments USING btree (parent_id);


--
-- Name: departments_path_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX departments_path_idx ON public.departments USING btree (path);


--
-- Name: device_registry_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX device_registry_user_idx ON public.device_registry USING btree (user_id);


--
-- Name: devices_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX devices_user_idx ON public.devices USING btree (user_id);


--
-- Name: dg_members_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dg_members_mailbox_idx ON public.distribution_group_members USING btree (mailbox_id);


--
-- Name: dg_scim_external_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX dg_scim_external_id_idx ON public.distribution_groups USING btree (scim_external_id) WHERE (scim_external_id IS NOT NULL);


--
-- Name: dir_connectors_type_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dir_connectors_type_idx ON public.directory_connectors USING btree (connector_type);


--
-- Name: dlp_policies_domain_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dlp_policies_domain_idx ON public.dlp_policies USING btree (domain_id, enabled, priority);


--
-- Name: dmarc_forensic_domain_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dmarc_forensic_domain_idx ON public.dmarc_forensic_reports USING btree (from_domain);


--
-- Name: dmarc_reports_domain_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dmarc_reports_domain_idx ON public.dmarc_reports USING btree (domain);


--
-- Name: dmarc_reports_domain_period_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX dmarc_reports_domain_period_idx ON public.dmarc_reports USING btree (domain, begin_time, end_time);


--
-- Name: dmarc_reports_period_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dmarc_reports_period_idx ON public.dmarc_reports USING btree (begin_time);


--
-- Name: domains_local_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX domains_local_idx ON public.domains USING btree (is_local) WHERE (is_local = true);


--
-- Name: domains_name_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX domains_name_idx ON public.domains USING btree (name);


--
-- Name: domains_primary_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX domains_primary_uniq ON public.domains USING btree ((true)) WHERE is_primary;


--
-- Name: dsk_domain_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX dsk_domain_active_idx ON public.domain_signing_keys USING btree (domain_id, active);


--
-- Name: ediscovery_cases_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ediscovery_cases_status_idx ON public.ediscovery_cases USING btree (status);


--
-- Name: ediscovery_searches_case_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ediscovery_searches_case_idx ON public.ediscovery_searches USING btree (case_id);


--
-- Name: event_attendees_event_email_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX event_attendees_event_email_uniq ON public.event_attendees USING btree (event_id, lower(email));


--
-- Name: events_calendar_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_calendar_idx ON public.calendar_events USING btree (calendar_id);


--
-- Name: events_range_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_range_idx ON public.calendar_events USING btree (start_at, end_at);


--
-- Name: events_uid_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX events_uid_idx ON public.calendar_events USING btree (uid);


--
-- Name: field_policy_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX field_policy_user_idx ON public.field_policy USING btree (user_id);


--
-- Name: folders_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX folders_mailbox_idx ON public.folders USING btree (mailbox_id);


--
-- Name: folders_parent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX folders_parent_idx ON public.folders USING btree (parent_id) WHERE (parent_id IS NOT NULL);


--
-- Name: folders_role_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX folders_role_idx ON public.folders USING btree (mailbox_id, role) WHERE (role IS NOT NULL);


--
-- Name: greylist_first_seen_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX greylist_first_seen_idx ON public.greylist USING btree (first_seen);


--
-- Name: greylist_whitelist_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX greylist_whitelist_idx ON public.greylist USING btree (sender) WHERE whitelisted;


--
-- Name: health_history_name_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX health_history_name_idx ON public.health_history USING btree (check_name, checked_at DESC);


--
-- Name: identity_sync_log_source_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_sync_log_source_idx ON public.identity_sync_log USING btree (source, sync_at DESC);


--
-- Name: identity_sync_log_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_sync_log_time_idx ON public.identity_sync_log USING btree (sync_at DESC);


--
-- Name: idx_cron_run_log_task; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cron_run_log_task ON public.cron_run_log USING btree (task_name, started_at DESC);


--
-- Name: idx_device_events_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_events_device ON public.device_events USING btree (device_id, created_at DESC);


--
-- Name: idx_device_events_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_events_time ON public.device_events USING btree (occurred_at);


--
-- Name: idx_device_events_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_events_type ON public.device_events USING btree (event_type);


--
-- Name: idx_device_policy_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_policy_device ON public.device_policy USING btree (device_id);


--
-- Name: idx_device_policy_groups_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_policy_groups_lookup ON public.device_policy_groups USING btree (group_type, group_id);


--
-- Name: idx_device_policy_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_policy_key ON public.device_policy USING btree (policy_key);


--
-- Name: idx_link_protect_audit_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_link_protect_audit_created_at ON public.link_protect_audit USING btree (created_at);


--
-- Name: idx_link_protect_audit_url_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_link_protect_audit_url_hash ON public.link_protect_audit USING btree (url_hash);


--
-- Name: idx_login_events_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_login_events_ip ON public.login_events USING btree (source_ip);


--
-- Name: idx_login_events_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_login_events_user ON public.login_events USING btree (user_id, occurred_at DESC);


--
-- Name: idx_mdm_device_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mdm_device_status ON public.mdm_device_state USING btree (compliance_status);


--
-- Name: idx_mdm_device_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mdm_device_user ON public.mdm_device_state USING btree (user_id);


--
-- Name: idx_mdm_device_wipe; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mdm_device_wipe ON public.mdm_device_state USING btree (wipe_requested) WHERE (wipe_requested = 'pending'::text);


--
-- Name: idx_mdm_policies_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mdm_policies_priority ON public.mdm_policies USING btree (priority DESC);


--
-- Name: idx_mdm_policies_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mdm_policies_scope ON public.mdm_policies USING btree (scope_type, scope_id) WHERE enabled;


--
-- Name: idx_notification_prefs_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notification_prefs_user ON public.user_notification_prefs USING btree (user_id);


--
-- Name: idx_role_assignments_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_assignments_role ON public.admin_role_assignments USING btree (role_group_id);


--
-- Name: idx_role_assignments_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_assignments_user ON public.admin_role_assignments USING btree (user_id);


--
-- Name: idx_telemetry_device; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_telemetry_device ON public.device_telemetry USING btree (device_id, reported_at DESC);


--
-- Name: idx_telemetry_reported_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_telemetry_reported_at ON public.device_telemetry USING btree (reported_at);


--
-- Name: idx_upgrade_history_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_upgrade_history_started ON public.upgrade_history USING btree (started_at DESC);


--
-- Name: idx_user_sender_list_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_sender_list_user ON public.user_sender_list USING btree (user_id);


--
-- Name: idx_user_signatures_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_signatures_user ON public.user_signatures USING btree (user_id);


--
-- Name: idx_user_signatures_user_alias; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_user_signatures_user_alias ON public.user_signatures USING btree (user_id, alias_email);


--
-- Name: idx_users_email_lower; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_email_lower ON public.users USING btree (lower(email));


--
-- Name: ip_rules_action_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ip_rules_action_idx ON public.ip_rules USING btree (action);


--
-- Name: ip_rules_cidr_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ip_rules_cidr_idx ON public.ip_rules USING gist (cidr inet_ops);


--
-- Name: journal_queue_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX journal_queue_pending_idx ON public.journal_queue USING btree (status) WHERE (status = 'pending'::text);


--
-- Name: journaling_policies_lookup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX journaling_policies_lookup_idx ON public.journaling_policies USING btree (domain_id, direction, enabled);


--
-- Name: mailbox_audit_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mailbox_audit_mailbox_idx ON ONLY public.mailbox_audit_log USING btree (mailbox_id, occurred_at DESC);


--
-- Name: mailbox_audit_log_2026_06_mailbox_id_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mailbox_audit_log_2026_06_mailbox_id_occurred_at_idx ON public.mailbox_audit_log_2026_06 USING btree (mailbox_id, occurred_at DESC);


--
-- Name: mailbox_audit_log_2026_07_mailbox_id_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mailbox_audit_log_2026_07_mailbox_id_occurred_at_idx ON public.mailbox_audit_log_2026_07 USING btree (mailbox_id, occurred_at DESC);


--
-- Name: mailbox_audit_log_default_mailbox_id_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mailbox_audit_log_default_mailbox_id_occurred_at_idx ON public.mailbox_audit_log_default USING btree (mailbox_id, occurred_at DESC);


--
-- Name: mailboxes_domain_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mailboxes_domain_idx ON public.mailboxes USING btree (domain_id);


--
-- Name: mailboxes_email_lower_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX mailboxes_email_lower_idx ON public.mailboxes USING btree (lower(email));


--
-- Name: mailboxes_hold_set_by_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mailboxes_hold_set_by_idx ON public.mailboxes USING btree (hold_set_by) WHERE (hold_set_by IS NOT NULL);


--
-- Name: mailboxes_type_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mailboxes_type_idx ON public.mailboxes USING btree (type);


--
-- Name: mailboxes_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mailboxes_user_idx ON public.mailboxes USING btree (user_id) WHERE (user_id IS NOT NULL);


--
-- Name: mailboxes_user_primary_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX mailboxes_user_primary_idx ON public.mailboxes USING btree (user_id) WHERE is_primary;


--
-- Name: managed_devices_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_devices_user_idx ON public.managed_devices USING btree (user_id);


--
-- Name: message_recalls_recalled_by_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_recalls_recalled_by_idx ON public.message_recalls USING btree (recalled_by);


--
-- Name: message_tags_primary_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_tags_primary_idx ON ONLY public.message_tags USING btree (message_id, received_at) WHERE is_primary;


--
-- Name: message_tags_default_message_id_received_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_tags_default_message_id_received_at_idx ON public.message_tags_default USING btree (message_id, received_at) WHERE is_primary;


--
-- Name: message_tags_scheduled_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_tags_scheduled_idx ON ONLY public.message_tags USING btree (scheduled_at) WHERE (scheduled_at IS NOT NULL);


--
-- Name: message_tags_default_scheduled_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_tags_default_scheduled_at_idx ON public.message_tags_default USING btree (scheduled_at) WHERE (scheduled_at IS NOT NULL);


--
-- Name: message_tags_snooze_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_tags_snooze_idx ON ONLY public.message_tags USING btree (snooze_until) WHERE (snooze_until IS NOT NULL);


--
-- Name: message_tags_default_snooze_until_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_tags_default_snooze_until_idx ON public.message_tags_default USING btree (snooze_until) WHERE (snooze_until IS NOT NULL);


--
-- Name: message_tags_tag_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_tags_tag_idx ON ONLY public.message_tags USING btree (tag_id, received_at DESC);


--
-- Name: message_tags_default_tag_id_received_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_tags_default_tag_id_received_at_idx ON public.message_tags_default USING btree (tag_id, received_at DESC);


--
-- Name: trace_from_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX trace_from_idx ON ONLY public.message_trace USING btree (from_addr, occurred_at DESC);


--
-- Name: message_trace_2026_06_from_addr_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_trace_2026_06_from_addr_occurred_at_idx ON public.message_trace_2026_06 USING btree (from_addr, occurred_at DESC);


--
-- Name: trace_message_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX trace_message_id_idx ON ONLY public.message_trace USING btree (message_id);


--
-- Name: message_trace_2026_06_message_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_trace_2026_06_message_id_idx ON public.message_trace_2026_06 USING btree (message_id);


--
-- Name: trace_occurred_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX trace_occurred_idx ON ONLY public.message_trace USING btree (occurred_at DESC);


--
-- Name: message_trace_2026_06_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_trace_2026_06_occurred_at_idx ON public.message_trace_2026_06 USING btree (occurred_at DESC);


--
-- Name: trace_rcpt_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX trace_rcpt_idx ON ONLY public.message_trace USING btree (rcpt_addr, occurred_at DESC);


--
-- Name: message_trace_2026_06_rcpt_addr_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_trace_2026_06_rcpt_addr_occurred_at_idx ON public.message_trace_2026_06 USING btree (rcpt_addr, occurred_at DESC);


--
-- Name: message_trace_2026_07_from_addr_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_trace_2026_07_from_addr_occurred_at_idx ON public.message_trace_2026_07 USING btree (from_addr, occurred_at DESC);


--
-- Name: message_trace_2026_07_message_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_trace_2026_07_message_id_idx ON public.message_trace_2026_07 USING btree (message_id);


--
-- Name: message_trace_2026_07_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_trace_2026_07_occurred_at_idx ON public.message_trace_2026_07 USING btree (occurred_at DESC);


--
-- Name: message_trace_2026_07_rcpt_addr_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_trace_2026_07_rcpt_addr_occurred_at_idx ON public.message_trace_2026_07 USING btree (rcpt_addr, occurred_at DESC);


--
-- Name: message_trace_default_from_addr_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_trace_default_from_addr_occurred_at_idx ON public.message_trace_default USING btree (from_addr, occurred_at DESC);


--
-- Name: message_trace_default_message_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_trace_default_message_id_idx ON public.message_trace_default USING btree (message_id);


--
-- Name: message_trace_default_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_trace_default_occurred_at_idx ON public.message_trace_default USING btree (occurred_at DESC);


--
-- Name: message_trace_default_rcpt_addr_occurred_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX message_trace_default_rcpt_addr_occurred_at_idx ON public.message_trace_default USING btree (rcpt_addr, occurred_at DESC);


--
-- Name: messages_body_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_body_tsv_idx ON ONLY public.messages USING gin (body_tsv);


--
-- Name: messages_2026_06_body_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_body_tsv_idx ON public.messages_2026_06 USING gin (body_tsv);


--
-- Name: messages_categories_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_categories_idx ON ONLY public.messages USING gin (categories);


--
-- Name: messages_2026_06_categories_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_categories_idx ON public.messages_2026_06 USING gin (categories);


--
-- Name: messages_flag_reminder_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_flag_reminder_idx ON ONLY public.messages USING btree (flag_reminder_at) WHERE (flag_reminder_at IS NOT NULL);


--
-- Name: messages_2026_06_flag_reminder_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_flag_reminder_at_idx ON public.messages_2026_06 USING btree (flag_reminder_at) WHERE (flag_reminder_at IS NOT NULL);


--
-- Name: messages_from_addr_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_from_addr_idx ON ONLY public.messages USING btree (from_addr);


--
-- Name: messages_2026_06_from_addr_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_from_addr_idx ON public.messages_2026_06 USING btree (from_addr);


--
-- Name: messages_from_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_from_tsv_idx ON ONLY public.messages USING gin (from_tsv);


--
-- Name: messages_2026_06_from_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_from_tsv_idx ON public.messages_2026_06 USING gin (from_tsv);


--
-- Name: messages_in_reply_to_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_in_reply_to_idx ON ONLY public.messages USING btree (in_reply_to) WHERE (in_reply_to IS NOT NULL);


--
-- Name: messages_2026_06_in_reply_to_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_in_reply_to_idx ON public.messages_2026_06 USING btree (in_reply_to) WHERE (in_reply_to IS NOT NULL);


--
-- Name: messages_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_deleted_at_idx ON ONLY public.messages USING btree (mailbox_id, deleted_at) WHERE is_deleted;


--
-- Name: messages_2026_06_mailbox_id_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_mailbox_id_deleted_at_idx ON public.messages_2026_06 USING btree (mailbox_id, deleted_at) WHERE is_deleted;


--
-- Name: messages_is_read_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_is_read_idx ON ONLY public.messages USING btree (mailbox_id, folder_id) WHERE (NOT is_read);


--
-- Name: messages_2026_06_mailbox_id_folder_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_mailbox_id_folder_id_idx ON public.messages_2026_06 USING btree (mailbox_id, folder_id) WHERE (NOT is_read);


--
-- Name: messages_is_deleted_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_is_deleted_idx ON ONLY public.messages USING btree (mailbox_id, folder_id) WHERE is_deleted;


--
-- Name: messages_2026_06_mailbox_id_folder_id_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_mailbox_id_folder_id_idx1 ON public.messages_2026_06 USING btree (mailbox_id, folder_id) WHERE is_deleted;


--
-- Name: messages_mailbox_folder_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_mailbox_folder_idx ON ONLY public.messages USING btree (mailbox_id, folder_id, received_at DESC);


--
-- Name: messages_2026_06_mailbox_id_folder_id_received_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_mailbox_id_folder_id_received_at_idx ON public.messages_2026_06 USING btree (mailbox_id, folder_id, received_at DESC);


--
-- Name: messages_is_flagged_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_is_flagged_idx ON ONLY public.messages USING btree (mailbox_id) WHERE is_flagged;


--
-- Name: messages_2026_06_mailbox_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_mailbox_id_idx ON public.messages_2026_06 USING btree (mailbox_id) WHERE is_flagged;


--
-- Name: messages_held_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_held_idx ON ONLY public.messages USING btree (mailbox_id) WHERE held;


--
-- Name: messages_2026_06_mailbox_id_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_mailbox_id_idx1 ON public.messages_2026_06 USING btree (mailbox_id) WHERE held;


--
-- Name: messages_mailbox_list_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_mailbox_list_idx ON ONLY public.messages USING btree (mailbox_id, list_id) WHERE (list_id IS NOT NULL);


--
-- Name: INDEX messages_mailbox_list_idx; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON INDEX public.messages_mailbox_list_idx IS 'Partial index supporting newsletter bundle grouping queries. Leading mailbox_id enforces auth scoping (R1); partial predicate limits index size to newsletter-only rows.';


--
-- Name: messages_2026_06_mailbox_id_list_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_mailbox_id_list_id_idx ON public.messages_2026_06 USING btree (mailbox_id, list_id) WHERE (list_id IS NOT NULL);


--
-- Name: messages_pinned_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_pinned_idx ON ONLY public.messages USING btree (mailbox_id, pinned_at) WHERE (pinned_at IS NOT NULL);


--
-- Name: messages_2026_06_mailbox_id_pinned_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_mailbox_id_pinned_at_idx ON public.messages_2026_06 USING btree (mailbox_id, pinned_at) WHERE (pinned_at IS NOT NULL);


--
-- Name: messages_thread_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_thread_idx ON ONLY public.messages USING btree (mailbox_id, thread_id);


--
-- Name: messages_2026_06_mailbox_id_thread_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_mailbox_id_thread_id_idx ON public.messages_2026_06 USING btree (mailbox_id, thread_id);


--
-- Name: messages_message_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_message_id_idx ON ONLY public.messages USING btree (message_id);


--
-- Name: messages_2026_06_message_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_message_id_idx ON public.messages_2026_06 USING btree (message_id);


--
-- Name: messages_received_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_received_at_idx ON ONLY public.messages USING btree (received_at DESC);


--
-- Name: messages_2026_06_received_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_received_at_idx ON public.messages_2026_06 USING btree (received_at DESC);


--
-- Name: messages_references_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_references_idx ON ONLY public.messages USING btree (references_hdr) WHERE (references_hdr IS NOT NULL);


--
-- Name: messages_2026_06_references_hdr_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_references_hdr_idx ON public.messages_2026_06 USING btree (references_hdr) WHERE (references_hdr IS NOT NULL);


--
-- Name: messages_sent_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_sent_at_idx ON ONLY public.messages USING btree (sent_at) WHERE (sent_at IS NOT NULL);


--
-- Name: messages_2026_06_sent_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_sent_at_idx ON public.messages_2026_06 USING btree (sent_at) WHERE (sent_at IS NOT NULL);


--
-- Name: messages_spam_score_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_spam_score_idx ON ONLY public.messages USING btree (spam_score) WHERE (spam_score IS NOT NULL);


--
-- Name: messages_2026_06_spam_score_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_spam_score_idx ON public.messages_2026_06 USING btree (spam_score) WHERE (spam_score IS NOT NULL);


--
-- Name: messages_subject_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_subject_tsv_idx ON ONLY public.messages USING gin (subject_tsv);


--
-- Name: messages_2026_06_subject_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_06_subject_tsv_idx ON public.messages_2026_06 USING gin (subject_tsv);


--
-- Name: messages_2026_07_body_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_body_tsv_idx ON public.messages_2026_07 USING gin (body_tsv);


--
-- Name: messages_2026_07_categories_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_categories_idx ON public.messages_2026_07 USING gin (categories);


--
-- Name: messages_2026_07_flag_reminder_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_flag_reminder_at_idx ON public.messages_2026_07 USING btree (flag_reminder_at) WHERE (flag_reminder_at IS NOT NULL);


--
-- Name: messages_2026_07_from_addr_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_from_addr_idx ON public.messages_2026_07 USING btree (from_addr);


--
-- Name: messages_2026_07_from_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_from_tsv_idx ON public.messages_2026_07 USING gin (from_tsv);


--
-- Name: messages_2026_07_in_reply_to_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_in_reply_to_idx ON public.messages_2026_07 USING btree (in_reply_to) WHERE (in_reply_to IS NOT NULL);


--
-- Name: messages_2026_07_mailbox_id_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_mailbox_id_deleted_at_idx ON public.messages_2026_07 USING btree (mailbox_id, deleted_at) WHERE is_deleted;


--
-- Name: messages_2026_07_mailbox_id_folder_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_mailbox_id_folder_id_idx ON public.messages_2026_07 USING btree (mailbox_id, folder_id) WHERE (NOT is_read);


--
-- Name: messages_2026_07_mailbox_id_folder_id_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_mailbox_id_folder_id_idx1 ON public.messages_2026_07 USING btree (mailbox_id, folder_id) WHERE is_deleted;


--
-- Name: messages_2026_07_mailbox_id_folder_id_received_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_mailbox_id_folder_id_received_at_idx ON public.messages_2026_07 USING btree (mailbox_id, folder_id, received_at DESC);


--
-- Name: messages_2026_07_mailbox_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_mailbox_id_idx ON public.messages_2026_07 USING btree (mailbox_id) WHERE is_flagged;


--
-- Name: messages_2026_07_mailbox_id_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_mailbox_id_idx1 ON public.messages_2026_07 USING btree (mailbox_id) WHERE held;


--
-- Name: messages_2026_07_mailbox_id_list_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_mailbox_id_list_id_idx ON public.messages_2026_07 USING btree (mailbox_id, list_id) WHERE (list_id IS NOT NULL);


--
-- Name: messages_2026_07_mailbox_id_pinned_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_mailbox_id_pinned_at_idx ON public.messages_2026_07 USING btree (mailbox_id, pinned_at) WHERE (pinned_at IS NOT NULL);


--
-- Name: messages_2026_07_mailbox_id_thread_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_mailbox_id_thread_id_idx ON public.messages_2026_07 USING btree (mailbox_id, thread_id);


--
-- Name: messages_2026_07_message_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_message_id_idx ON public.messages_2026_07 USING btree (message_id);


--
-- Name: messages_2026_07_received_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_received_at_idx ON public.messages_2026_07 USING btree (received_at DESC);


--
-- Name: messages_2026_07_references_hdr_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_references_hdr_idx ON public.messages_2026_07 USING btree (references_hdr) WHERE (references_hdr IS NOT NULL);


--
-- Name: messages_2026_07_sent_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_sent_at_idx ON public.messages_2026_07 USING btree (sent_at) WHERE (sent_at IS NOT NULL);


--
-- Name: messages_2026_07_spam_score_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_spam_score_idx ON public.messages_2026_07 USING btree (spam_score) WHERE (spam_score IS NOT NULL);


--
-- Name: messages_2026_07_subject_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_2026_07_subject_tsv_idx ON public.messages_2026_07 USING gin (subject_tsv);


--
-- Name: messages_default_body_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_body_tsv_idx ON public.messages_default USING gin (body_tsv);


--
-- Name: messages_default_categories_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_categories_idx ON public.messages_default USING gin (categories);


--
-- Name: messages_default_flag_reminder_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_flag_reminder_at_idx ON public.messages_default USING btree (flag_reminder_at) WHERE (flag_reminder_at IS NOT NULL);


--
-- Name: messages_default_from_addr_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_from_addr_idx ON public.messages_default USING btree (from_addr);


--
-- Name: messages_default_from_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_from_tsv_idx ON public.messages_default USING gin (from_tsv);


--
-- Name: messages_default_in_reply_to_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_in_reply_to_idx ON public.messages_default USING btree (in_reply_to) WHERE (in_reply_to IS NOT NULL);


--
-- Name: messages_default_mailbox_id_deleted_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_mailbox_id_deleted_at_idx ON public.messages_default USING btree (mailbox_id, deleted_at) WHERE is_deleted;


--
-- Name: messages_default_mailbox_id_folder_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_mailbox_id_folder_id_idx ON public.messages_default USING btree (mailbox_id, folder_id) WHERE (NOT is_read);


--
-- Name: messages_default_mailbox_id_folder_id_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_mailbox_id_folder_id_idx1 ON public.messages_default USING btree (mailbox_id, folder_id) WHERE is_deleted;


--
-- Name: messages_default_mailbox_id_folder_id_received_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_mailbox_id_folder_id_received_at_idx ON public.messages_default USING btree (mailbox_id, folder_id, received_at DESC);


--
-- Name: messages_default_mailbox_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_mailbox_id_idx ON public.messages_default USING btree (mailbox_id) WHERE is_flagged;


--
-- Name: messages_default_mailbox_id_idx1; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_mailbox_id_idx1 ON public.messages_default USING btree (mailbox_id) WHERE held;


--
-- Name: messages_default_mailbox_id_list_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_mailbox_id_list_id_idx ON public.messages_default USING btree (mailbox_id, list_id) WHERE (list_id IS NOT NULL);


--
-- Name: messages_default_mailbox_id_pinned_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_mailbox_id_pinned_at_idx ON public.messages_default USING btree (mailbox_id, pinned_at) WHERE (pinned_at IS NOT NULL);


--
-- Name: messages_default_mailbox_id_thread_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_mailbox_id_thread_id_idx ON public.messages_default USING btree (mailbox_id, thread_id);


--
-- Name: messages_default_message_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_message_id_idx ON public.messages_default USING btree (message_id);


--
-- Name: messages_default_received_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_received_at_idx ON public.messages_default USING btree (received_at DESC);


--
-- Name: messages_default_references_hdr_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_references_hdr_idx ON public.messages_default USING btree (references_hdr) WHERE (references_hdr IS NOT NULL);


--
-- Name: messages_default_sent_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_sent_at_idx ON public.messages_default USING btree (sent_at) WHERE (sent_at IS NOT NULL);


--
-- Name: messages_default_spam_score_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_spam_score_idx ON public.messages_default USING btree (spam_score) WHERE (spam_score IS NOT NULL);


--
-- Name: messages_default_subject_tsv_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX messages_default_subject_tsv_idx ON public.messages_default USING gin (subject_tsv);


--
-- Name: migration_jobs_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX migration_jobs_status_idx ON public.migration_jobs USING btree (status);


--
-- Name: migration_one_active_per_user; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX migration_one_active_per_user ON public.migration_jobs USING btree (user_id) WHERE (status = ANY (ARRAY['pending'::text, 'testing'::text, 'fetching'::text, 'importing'::text, 'paused'::text]));


--
-- Name: oauth_hash_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_hash_idx ON public.oauth_tokens USING btree (token_hash);


--
-- Name: oauth_rotated_cleanup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_rotated_cleanup_idx ON public.oauth_tokens USING btree (rotated_at) WHERE (rotated_at IS NOT NULL);


--
-- Name: oauth_user_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_user_active_idx ON public.oauth_tokens USING btree (user_id) WHERE (revoked_at IS NULL);


--
-- Name: oauth_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_user_idx ON public.oauth_tokens USING btree (user_id);


--
-- Name: oidc_tokens_refresh_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oidc_tokens_refresh_idx ON public.oidc_tokens USING btree (refresh_token_hash) WHERE (refresh_token_hash IS NOT NULL);


--
-- Name: orphaned_message_blobs_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX orphaned_message_blobs_created_at_idx ON public.orphaned_message_blobs USING btree (created_at);


--
-- Name: outbound_queue_hot_dedup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX outbound_queue_hot_dedup_idx ON public.outbound_queue_hot USING btree (dedup_key) WHERE (dedup_key IS NOT NULL);


--
-- Name: outbound_queue_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX outbound_queue_mailbox_idx ON public.outbound_queue USING btree (mailbox_id);


--
-- Name: outbound_queue_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX outbound_queue_pending_idx ON public.outbound_queue USING btree (next_attempt_at) WHERE (status = ANY (ARRAY['pending'::text, 'deferred'::text]));


--
-- Name: outbound_queue_status_queued_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX outbound_queue_status_queued_idx ON public.outbound_queue USING btree (status, queued_at);


--
-- Name: passhist_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX passhist_user_idx ON public.password_history USING btree (user_id, created_at DESC);


--
-- Name: passkey_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX passkey_user_idx ON public.passkey_credentials USING btree (user_id) WHERE (revoked_at IS NULL);


--
-- Name: push_mfa_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX push_mfa_user_idx ON public.push_mfa_challenges USING btree (user_id, expires_at) WHERE (verified_at IS NULL);


--
-- Name: push_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX push_user_idx ON public.push_devices USING btree (user_id) WHERE (revoked_at IS NULL);


--
-- Name: quarantined_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX quarantined_mailbox_idx ON public.quarantined_messages USING btree (mailbox_id);


--
-- Name: quarantined_preview_token_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX quarantined_preview_token_idx ON public.quarantined_messages USING btree (preview_token);


--
-- Name: quarantined_sandbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX quarantined_sandbox_idx ON public.quarantined_messages USING btree (reason_type) WHERE ((reason_type = 'sandbox'::text) AND (released_at IS NULL) AND (rejected_at IS NULL));


--
-- Name: quarantined_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX quarantined_status_idx ON public.quarantined_messages USING btree (released_at, rejected_at) WHERE ((released_at IS NULL) AND (rejected_at IS NULL));


--
-- Name: quick_steps_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX quick_steps_mailbox_idx ON public.quick_steps USING btree (mailbox_id, "position");


--
-- Name: rate_limit_block_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rate_limit_block_idx ON public.rate_limit_counters USING btree (blocked_until) WHERE (blocked_until IS NOT NULL);


--
-- Name: reminders_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX reminders_active_idx ON public.reminders USING btree (mailbox_id) WHERE (dismissed_at IS NULL);


--
-- Name: retention_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX retention_expires_idx ON public.message_retention_tags USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: rules_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rules_mailbox_idx ON public.rules USING btree (mailbox_id, enabled, priority) WHERE (mailbox_id IS NOT NULL);


--
-- Name: rules_transport_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rules_transport_idx ON public.rules USING btree (enabled, priority) WHERE (is_transport_rule = true);


--
-- Name: rules_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rules_user_idx ON public.rules USING btree (user_id) WHERE (user_id IS NOT NULL);


--
-- Name: saml_sp_idp_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX saml_sp_idp_idx ON public.saml_sp_registrations USING btree (idp_entity_id);


--
-- Name: scheduled_action_log_action_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scheduled_action_log_action_idx ON public.scheduled_action_log USING btree (action_id, at);


--
-- Name: scheduled_actions_dedup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX scheduled_actions_dedup_idx ON public.scheduled_actions USING btree (dedup_key) WHERE (dedup_key IS NOT NULL);


--
-- Name: scheduled_actions_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scheduled_actions_due_idx ON public.scheduled_actions USING btree (fire_at) WHERE (status = 'pending'::text);


--
-- Name: scheduled_actions_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scheduled_actions_mailbox_idx ON public.scheduled_actions USING btree (mailbox_id) WHERE (mailbox_id IS NOT NULL);


--
-- Name: scheduled_actions_reclaim_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scheduled_actions_reclaim_idx ON public.scheduled_actions USING btree (locked_until) WHERE (status = 'processing'::text);


--
-- Name: scim_tokens_hash_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scim_tokens_hash_idx ON public.scim_tokens USING btree (token_hash);


--
-- Name: sessions_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_expires_idx ON public.sessions USING btree (expires_at);


--
-- Name: sessions_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_user_idx ON public.sessions USING btree (user_id);


--
-- Name: signing_keys_one_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX signing_keys_one_active_idx ON public.signing_keys USING btree (status) WHERE (status = 'active'::text);


--
-- Name: signing_keys_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX signing_keys_status_idx ON public.signing_keys USING btree (status);


--
-- Name: storage_dr_scans_started_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX storage_dr_scans_started_idx ON public.storage_dr_scans USING btree (started_at DESC);


--
-- Name: storage_dr_scans_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX storage_dr_scans_status_idx ON public.storage_dr_scans USING btree (status);


--
-- Name: sync_conflicts_unresolved_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sync_conflicts_unresolved_idx ON public.sync_conflicts USING btree (detected_at) WHERE (resolved_at IS NULL);


--
-- Name: sync_conflicts_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sync_conflicts_user_idx ON public.sync_conflicts USING btree (user_id);


--
-- Name: tags_default_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tags_default_idx ON public.tags USING btree (mailbox_id) WHERE is_default;


--
-- Name: tags_exclusive_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tags_exclusive_idx ON public.tags USING btree (mailbox_id, exclusive_group) WHERE (exclusive_group IS NOT NULL);


--
-- Name: tags_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tags_mailbox_idx ON public.tags USING btree (mailbox_id);


--
-- Name: tags_parent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tags_parent_idx ON public.tags USING btree (parent_id) WHERE (parent_id IS NOT NULL);


--
-- Name: tags_type_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tags_type_idx ON public.tags USING btree (mailbox_id, tag_type);


--
-- Name: tasks_assignee_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tasks_assignee_idx ON public.tasks USING btree (assignee_user_id) WHERE (assignee_user_id IS NOT NULL);


--
-- Name: tasks_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tasks_due_idx ON public.tasks USING btree (due_at) WHERE (due_at IS NOT NULL);


--
-- Name: tasks_linked_event_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tasks_linked_event_idx ON public.tasks USING btree (linked_event_id) WHERE (linked_event_id IS NOT NULL);


--
-- Name: tasks_linked_msg_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tasks_linked_msg_idx ON public.tasks USING btree (linked_message_id) WHERE (linked_message_id IS NOT NULL);


--
-- Name: tasks_mailbox_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tasks_mailbox_idx ON public.tasks USING btree (mailbox_id, status);


--
-- Name: tasks_parent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tasks_parent_idx ON public.tasks USING btree (parent_id) WHERE (parent_id IS NOT NULL);


--
-- Name: threat_feed_cidr_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX threat_feed_cidr_idx ON public.threat_feed_blocks USING gist (cidr inet_ops);


--
-- Name: user_app_entitlements_app_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_app_entitlements_app_idx ON public.user_app_entitlements USING btree (app) WHERE (enabled = false);


--
-- Name: user_devices_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_devices_user_idx ON public.user_devices USING btree (user_id);


--
-- Name: users_ad_guid_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_ad_guid_idx ON public.users USING btree (ad_object_guid) WHERE (ad_object_guid IS NOT NULL);


--
-- Name: users_ad_usn_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_ad_usn_idx ON public.users USING btree (ad_usn_changed) WHERE (ad_usn_changed IS NOT NULL);


--
-- Name: users_avatar_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_avatar_idx ON public.users USING btree (avatar_sha256) WHERE (avatar_sha256 IS NOT NULL);


--
-- Name: users_department_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_department_idx ON public.users USING btree (department_id);


--
-- Name: users_domain_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_domain_idx ON public.users USING btree (domain_id);


--
-- Name: users_email_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_email_idx ON public.users USING btree (email);


--
-- Name: users_email_lower_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_email_lower_idx ON public.users USING btree (lower(email));


--
-- Name: users_enabled_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_enabled_idx ON public.users USING btree (enabled);


--
-- Name: users_manager_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_manager_idx ON public.users USING btree (manager_id) WHERE (manager_id IS NOT NULL);


--
-- Name: users_oidc_subject_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_oidc_subject_idx ON public.users USING btree (oidc_issuer, oidc_subject) WHERE ((oidc_subject IS NOT NULL) AND (oidc_issuer IS NOT NULL));


--
-- Name: users_saml_name_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_saml_name_id_idx ON public.users USING btree (saml_idp_entity_id, saml_name_id) WHERE ((saml_name_id IS NOT NULL) AND (saml_idp_entity_id IS NOT NULL));


--
-- Name: users_scim_external_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_scim_external_id_idx ON public.users USING btree (scim_external_id) WHERE (scim_external_id IS NOT NULL);


--
-- Name: vacation_replies_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX vacation_replies_at_idx ON public.vacation_replies USING btree (replied_at);


--
-- Name: webhook_deliveries_event_sub_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX webhook_deliveries_event_sub_idx ON public.webhook_deliveries USING btree (subscription_id, event_id);


--
-- Name: webhook_subscriptions_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webhook_subscriptions_active_idx ON public.webhook_subscriptions USING btree (id) WHERE is_active;


--
-- Name: ws_subs_session_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ws_subs_session_idx ON public.ws_subscriptions USING btree (session_id);


--
-- Name: ws_subs_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ws_subs_user_idx ON public.ws_subscriptions USING btree (user_id);


--
-- Name: audit_log_2026_05_event_type_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.audit_log_event_type_idx ATTACH PARTITION public.audit_log_2026_05_event_type_occurred_at_idx;


--
-- Name: audit_log_2026_05_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.audit_log_pkey ATTACH PARTITION public.audit_log_2026_05_pkey;


--
-- Name: audit_log_2026_05_source_ip_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.audit_log_ip_idx ATTACH PARTITION public.audit_log_2026_05_source_ip_occurred_at_idx;


--
-- Name: audit_log_2026_05_user_id_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.audit_log_user_idx ATTACH PARTITION public.audit_log_2026_05_user_id_occurred_at_idx;


--
-- Name: auth_attempts_2026_05_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.auth_attempts_pkey ATTACH PARTITION public.auth_attempts_2026_05_pkey;


--
-- Name: auth_attempts_2026_05_source_ip_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.auth_attempts_ip_time_idx ATTACH PARTITION public.auth_attempts_2026_05_source_ip_occurred_at_idx;


--
-- Name: auth_attempts_2026_05_target_username_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.auth_attempts_user_time_idx ATTACH PARTITION public.auth_attempts_2026_05_target_username_occurred_at_idx;


--
-- Name: mailbox_audit_log_2026_06_mailbox_id_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.mailbox_audit_mailbox_idx ATTACH PARTITION public.mailbox_audit_log_2026_06_mailbox_id_occurred_at_idx;


--
-- Name: mailbox_audit_log_2026_06_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.mailbox_audit_log_pkey ATTACH PARTITION public.mailbox_audit_log_2026_06_pkey;


--
-- Name: mailbox_audit_log_2026_07_mailbox_id_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.mailbox_audit_mailbox_idx ATTACH PARTITION public.mailbox_audit_log_2026_07_mailbox_id_occurred_at_idx;


--
-- Name: mailbox_audit_log_2026_07_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.mailbox_audit_log_pkey ATTACH PARTITION public.mailbox_audit_log_2026_07_pkey;


--
-- Name: mailbox_audit_log_default_mailbox_id_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.mailbox_audit_mailbox_idx ATTACH PARTITION public.mailbox_audit_log_default_mailbox_id_occurred_at_idx;


--
-- Name: mailbox_audit_log_default_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.mailbox_audit_log_pkey ATTACH PARTITION public.mailbox_audit_log_default_pkey;


--
-- Name: message_tags_default_message_id_received_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.message_tags_primary_idx ATTACH PARTITION public.message_tags_default_message_id_received_at_idx;


--
-- Name: message_tags_default_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.message_tags_pkey ATTACH PARTITION public.message_tags_default_pkey;


--
-- Name: message_tags_default_scheduled_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.message_tags_scheduled_idx ATTACH PARTITION public.message_tags_default_scheduled_at_idx;


--
-- Name: message_tags_default_snooze_until_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.message_tags_snooze_idx ATTACH PARTITION public.message_tags_default_snooze_until_idx;


--
-- Name: message_tags_default_tag_id_received_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.message_tags_tag_idx ATTACH PARTITION public.message_tags_default_tag_id_received_at_idx;


--
-- Name: message_trace_2026_06_from_addr_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.trace_from_idx ATTACH PARTITION public.message_trace_2026_06_from_addr_occurred_at_idx;


--
-- Name: message_trace_2026_06_message_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.trace_message_id_idx ATTACH PARTITION public.message_trace_2026_06_message_id_idx;


--
-- Name: message_trace_2026_06_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.trace_occurred_idx ATTACH PARTITION public.message_trace_2026_06_occurred_at_idx;


--
-- Name: message_trace_2026_06_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.message_trace_pkey ATTACH PARTITION public.message_trace_2026_06_pkey;


--
-- Name: message_trace_2026_06_rcpt_addr_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.trace_rcpt_idx ATTACH PARTITION public.message_trace_2026_06_rcpt_addr_occurred_at_idx;


--
-- Name: message_trace_2026_07_from_addr_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.trace_from_idx ATTACH PARTITION public.message_trace_2026_07_from_addr_occurred_at_idx;


--
-- Name: message_trace_2026_07_message_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.trace_message_id_idx ATTACH PARTITION public.message_trace_2026_07_message_id_idx;


--
-- Name: message_trace_2026_07_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.trace_occurred_idx ATTACH PARTITION public.message_trace_2026_07_occurred_at_idx;


--
-- Name: message_trace_2026_07_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.message_trace_pkey ATTACH PARTITION public.message_trace_2026_07_pkey;


--
-- Name: message_trace_2026_07_rcpt_addr_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.trace_rcpt_idx ATTACH PARTITION public.message_trace_2026_07_rcpt_addr_occurred_at_idx;


--
-- Name: message_trace_default_from_addr_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.trace_from_idx ATTACH PARTITION public.message_trace_default_from_addr_occurred_at_idx;


--
-- Name: message_trace_default_message_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.trace_message_id_idx ATTACH PARTITION public.message_trace_default_message_id_idx;


--
-- Name: message_trace_default_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.trace_occurred_idx ATTACH PARTITION public.message_trace_default_occurred_at_idx;


--
-- Name: message_trace_default_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.message_trace_pkey ATTACH PARTITION public.message_trace_default_pkey;


--
-- Name: message_trace_default_rcpt_addr_occurred_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.trace_rcpt_idx ATTACH PARTITION public.message_trace_default_rcpt_addr_occurred_at_idx;


--
-- Name: messages_2026_06_body_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_body_tsv_idx ATTACH PARTITION public.messages_2026_06_body_tsv_idx;


--
-- Name: messages_2026_06_categories_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_categories_idx ATTACH PARTITION public.messages_2026_06_categories_idx;


--
-- Name: messages_2026_06_flag_reminder_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_flag_reminder_idx ATTACH PARTITION public.messages_2026_06_flag_reminder_at_idx;


--
-- Name: messages_2026_06_from_addr_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_from_addr_idx ATTACH PARTITION public.messages_2026_06_from_addr_idx;


--
-- Name: messages_2026_06_from_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_from_tsv_idx ATTACH PARTITION public.messages_2026_06_from_tsv_idx;


--
-- Name: messages_2026_06_in_reply_to_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_in_reply_to_idx ATTACH PARTITION public.messages_2026_06_in_reply_to_idx;


--
-- Name: messages_2026_06_mailbox_id_deleted_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_deleted_at_idx ATTACH PARTITION public.messages_2026_06_mailbox_id_deleted_at_idx;


--
-- Name: messages_2026_06_mailbox_id_folder_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_is_read_idx ATTACH PARTITION public.messages_2026_06_mailbox_id_folder_id_idx;


--
-- Name: messages_2026_06_mailbox_id_folder_id_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_is_deleted_idx ATTACH PARTITION public.messages_2026_06_mailbox_id_folder_id_idx1;


--
-- Name: messages_2026_06_mailbox_id_folder_id_received_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_mailbox_folder_idx ATTACH PARTITION public.messages_2026_06_mailbox_id_folder_id_received_at_idx;


--
-- Name: messages_2026_06_mailbox_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_is_flagged_idx ATTACH PARTITION public.messages_2026_06_mailbox_id_idx;


--
-- Name: messages_2026_06_mailbox_id_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_held_idx ATTACH PARTITION public.messages_2026_06_mailbox_id_idx1;


--
-- Name: messages_2026_06_mailbox_id_list_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_mailbox_list_idx ATTACH PARTITION public.messages_2026_06_mailbox_id_list_id_idx;


--
-- Name: messages_2026_06_mailbox_id_pinned_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_pinned_idx ATTACH PARTITION public.messages_2026_06_mailbox_id_pinned_at_idx;


--
-- Name: messages_2026_06_mailbox_id_thread_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_thread_idx ATTACH PARTITION public.messages_2026_06_mailbox_id_thread_id_idx;


--
-- Name: messages_2026_06_message_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_message_id_idx ATTACH PARTITION public.messages_2026_06_message_id_idx;


--
-- Name: messages_2026_06_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_pkey ATTACH PARTITION public.messages_2026_06_pkey;


--
-- Name: messages_2026_06_received_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_received_at_idx ATTACH PARTITION public.messages_2026_06_received_at_idx;


--
-- Name: messages_2026_06_references_hdr_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_references_idx ATTACH PARTITION public.messages_2026_06_references_hdr_idx;


--
-- Name: messages_2026_06_sent_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_sent_at_idx ATTACH PARTITION public.messages_2026_06_sent_at_idx;


--
-- Name: messages_2026_06_spam_score_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_spam_score_idx ATTACH PARTITION public.messages_2026_06_spam_score_idx;


--
-- Name: messages_2026_06_subject_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_subject_tsv_idx ATTACH PARTITION public.messages_2026_06_subject_tsv_idx;


--
-- Name: messages_2026_07_body_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_body_tsv_idx ATTACH PARTITION public.messages_2026_07_body_tsv_idx;


--
-- Name: messages_2026_07_categories_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_categories_idx ATTACH PARTITION public.messages_2026_07_categories_idx;


--
-- Name: messages_2026_07_flag_reminder_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_flag_reminder_idx ATTACH PARTITION public.messages_2026_07_flag_reminder_at_idx;


--
-- Name: messages_2026_07_from_addr_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_from_addr_idx ATTACH PARTITION public.messages_2026_07_from_addr_idx;


--
-- Name: messages_2026_07_from_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_from_tsv_idx ATTACH PARTITION public.messages_2026_07_from_tsv_idx;


--
-- Name: messages_2026_07_in_reply_to_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_in_reply_to_idx ATTACH PARTITION public.messages_2026_07_in_reply_to_idx;


--
-- Name: messages_2026_07_mailbox_id_deleted_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_deleted_at_idx ATTACH PARTITION public.messages_2026_07_mailbox_id_deleted_at_idx;


--
-- Name: messages_2026_07_mailbox_id_folder_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_is_read_idx ATTACH PARTITION public.messages_2026_07_mailbox_id_folder_id_idx;


--
-- Name: messages_2026_07_mailbox_id_folder_id_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_is_deleted_idx ATTACH PARTITION public.messages_2026_07_mailbox_id_folder_id_idx1;


--
-- Name: messages_2026_07_mailbox_id_folder_id_received_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_mailbox_folder_idx ATTACH PARTITION public.messages_2026_07_mailbox_id_folder_id_received_at_idx;


--
-- Name: messages_2026_07_mailbox_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_is_flagged_idx ATTACH PARTITION public.messages_2026_07_mailbox_id_idx;


--
-- Name: messages_2026_07_mailbox_id_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_held_idx ATTACH PARTITION public.messages_2026_07_mailbox_id_idx1;


--
-- Name: messages_2026_07_mailbox_id_list_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_mailbox_list_idx ATTACH PARTITION public.messages_2026_07_mailbox_id_list_id_idx;


--
-- Name: messages_2026_07_mailbox_id_pinned_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_pinned_idx ATTACH PARTITION public.messages_2026_07_mailbox_id_pinned_at_idx;


--
-- Name: messages_2026_07_mailbox_id_thread_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_thread_idx ATTACH PARTITION public.messages_2026_07_mailbox_id_thread_id_idx;


--
-- Name: messages_2026_07_message_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_message_id_idx ATTACH PARTITION public.messages_2026_07_message_id_idx;


--
-- Name: messages_2026_07_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_pkey ATTACH PARTITION public.messages_2026_07_pkey;


--
-- Name: messages_2026_07_received_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_received_at_idx ATTACH PARTITION public.messages_2026_07_received_at_idx;


--
-- Name: messages_2026_07_references_hdr_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_references_idx ATTACH PARTITION public.messages_2026_07_references_hdr_idx;


--
-- Name: messages_2026_07_sent_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_sent_at_idx ATTACH PARTITION public.messages_2026_07_sent_at_idx;


--
-- Name: messages_2026_07_spam_score_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_spam_score_idx ATTACH PARTITION public.messages_2026_07_spam_score_idx;


--
-- Name: messages_2026_07_subject_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_subject_tsv_idx ATTACH PARTITION public.messages_2026_07_subject_tsv_idx;


--
-- Name: messages_default_body_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_body_tsv_idx ATTACH PARTITION public.messages_default_body_tsv_idx;


--
-- Name: messages_default_categories_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_categories_idx ATTACH PARTITION public.messages_default_categories_idx;


--
-- Name: messages_default_flag_reminder_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_flag_reminder_idx ATTACH PARTITION public.messages_default_flag_reminder_at_idx;


--
-- Name: messages_default_from_addr_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_from_addr_idx ATTACH PARTITION public.messages_default_from_addr_idx;


--
-- Name: messages_default_from_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_from_tsv_idx ATTACH PARTITION public.messages_default_from_tsv_idx;


--
-- Name: messages_default_in_reply_to_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_in_reply_to_idx ATTACH PARTITION public.messages_default_in_reply_to_idx;


--
-- Name: messages_default_mailbox_id_deleted_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_deleted_at_idx ATTACH PARTITION public.messages_default_mailbox_id_deleted_at_idx;


--
-- Name: messages_default_mailbox_id_folder_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_is_read_idx ATTACH PARTITION public.messages_default_mailbox_id_folder_id_idx;


--
-- Name: messages_default_mailbox_id_folder_id_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_is_deleted_idx ATTACH PARTITION public.messages_default_mailbox_id_folder_id_idx1;


--
-- Name: messages_default_mailbox_id_folder_id_received_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_mailbox_folder_idx ATTACH PARTITION public.messages_default_mailbox_id_folder_id_received_at_idx;


--
-- Name: messages_default_mailbox_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_is_flagged_idx ATTACH PARTITION public.messages_default_mailbox_id_idx;


--
-- Name: messages_default_mailbox_id_idx1; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_held_idx ATTACH PARTITION public.messages_default_mailbox_id_idx1;


--
-- Name: messages_default_mailbox_id_list_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_mailbox_list_idx ATTACH PARTITION public.messages_default_mailbox_id_list_id_idx;


--
-- Name: messages_default_mailbox_id_pinned_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_pinned_idx ATTACH PARTITION public.messages_default_mailbox_id_pinned_at_idx;


--
-- Name: messages_default_mailbox_id_thread_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_thread_idx ATTACH PARTITION public.messages_default_mailbox_id_thread_id_idx;


--
-- Name: messages_default_message_id_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_message_id_idx ATTACH PARTITION public.messages_default_message_id_idx;


--
-- Name: messages_default_pkey; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_pkey ATTACH PARTITION public.messages_default_pkey;


--
-- Name: messages_default_received_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_received_at_idx ATTACH PARTITION public.messages_default_received_at_idx;


--
-- Name: messages_default_references_hdr_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_references_idx ATTACH PARTITION public.messages_default_references_hdr_idx;


--
-- Name: messages_default_sent_at_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_sent_at_idx ATTACH PARTITION public.messages_default_sent_at_idx;


--
-- Name: messages_default_spam_score_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_spam_score_idx ATTACH PARTITION public.messages_default_spam_score_idx;


--
-- Name: messages_default_subject_tsv_idx; Type: INDEX ATTACH; Schema: public; Owner: -
--

ALTER INDEX public.messages_subject_tsv_idx ATTACH PARTITION public.messages_default_subject_tsv_idx;


--
-- Name: admin_audit_log admin_audit_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER admin_audit_append_only BEFORE DELETE OR UPDATE ON public.admin_audit_log FOR EACH ROW EXECUTE FUNCTION public.trg_audit_append_only();


--
-- Name: admin_audit_log admin_audit_chain; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER admin_audit_chain BEFORE INSERT ON public.admin_audit_log FOR EACH ROW EXECUTE FUNCTION public.trg_admin_audit_checksum();


--
-- Name: app_passwords app_password_limit; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER app_password_limit BEFORE INSERT ON public.app_passwords FOR EACH ROW EXECUTE FUNCTION public.trg_app_password_limit();


--
-- Name: message_attachments attachment_blob_refcount; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER attachment_blob_refcount AFTER DELETE ON public.message_attachments FOR EACH ROW EXECUTE FUNCTION public.trg_attachment_deleted();


--
-- Name: blobs blob_refcount_cleanup; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER blob_refcount_cleanup AFTER UPDATE OF ref_count ON public.blobs FOR EACH ROW EXECUTE FUNCTION public.trg_blob_refcount_zero();


--
-- Name: crash_events crash_events_no_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER crash_events_no_update BEFORE DELETE OR UPDATE ON public.crash_events FOR EACH ROW EXECUTE FUNCTION public.trg_crash_events_immutable();


--
-- Name: mailbox_audit_log mailbox_audit_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mailbox_audit_append_only BEFORE DELETE OR UPDATE ON public.mailbox_audit_log FOR EACH ROW EXECUTE FUNCTION public.trg_audit_append_only();


--
-- Name: mailboxes mailbox_create_folders; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mailbox_create_folders AFTER INSERT ON public.mailboxes FOR EACH ROW EXECUTE FUNCTION public.trg_mailbox_after_insert();


--
-- Name: mailboxes mailbox_create_tags; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mailbox_create_tags AFTER INSERT ON public.mailboxes FOR EACH ROW EXECUTE FUNCTION public.trg_mailbox_tag_after_insert();


--
-- Name: mailboxes mailbox_primary_enforce; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mailbox_primary_enforce AFTER INSERT OR DELETE OR UPDATE ON public.mailboxes FOR EACH ROW EXECUTE FUNCTION public.trg_mailbox_primary_enforce();


--
-- Name: mailboxes mailbox_quota_defaults; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER mailbox_quota_defaults AFTER INSERT ON public.mailboxes FOR EACH ROW EXECUTE FUNCTION public.trg_mailbox_quota_defaults();


--
-- Name: message_tags message_tags_counters_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER message_tags_counters_delete AFTER DELETE ON public.message_tags FOR EACH ROW EXECUTE FUNCTION public.trg_message_tags_counters();


--
-- Name: message_tags message_tags_counters_insert; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER message_tags_counters_insert AFTER INSERT ON public.message_tags FOR EACH ROW EXECUTE FUNCTION public.trg_message_tags_counters();


--
-- Name: message_tags message_tags_exclusive; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER message_tags_exclusive BEFORE INSERT ON public.message_tags FOR EACH ROW EXECUTE FUNCTION public.trg_message_tags_exclusive();


--
-- Name: message_tags message_tags_primary_sync; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER message_tags_primary_sync AFTER INSERT OR UPDATE OF is_primary ON public.message_tags FOR EACH ROW WHEN ((new.is_primary = true)) EXECUTE FUNCTION public.trg_message_tags_primary_sync();


--
-- Name: message_tags message_tags_spam_train; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER message_tags_spam_train AFTER INSERT OR DELETE ON public.message_tags FOR EACH ROW EXECUTE FUNCTION public.spam_train_notify();


--
-- Name: messages messages_hold_check; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER messages_hold_check BEFORE DELETE ON public.messages FOR EACH ROW EXECUTE FUNCTION public.trg_messages_hold_check();


--
-- Name: messages messages_tsv_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER messages_tsv_update BEFORE INSERT OR UPDATE OF body_text, subject, from_addr, from_name ON public.messages FOR EACH ROW EXECUTE FUNCTION public.trg_messages_tsv();


--
-- Name: outbound_queue outbound_queue_dsn; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER outbound_queue_dsn AFTER INSERT OR UPDATE ON public.outbound_queue FOR EACH ROW EXECUTE FUNCTION public.trg_outbound_queue_dsn();


--
-- Name: outbound_queue outbound_queue_status_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER outbound_queue_status_guard BEFORE UPDATE ON public.outbound_queue FOR EACH ROW EXECUTE FUNCTION public.trg_outbound_queue_status_guard();


--
-- Name: read_receipts read_receipt_never_guard; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER read_receipt_never_guard BEFORE INSERT ON public.read_receipts FOR EACH ROW EXECUTE FUNCTION public.trg_read_receipt_never_guard();


--
-- Name: vt_timezone timezone_change_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER timezone_change_trigger AFTER INSERT OR DELETE OR UPDATE ON public.vt_timezone FOR EACH ROW EXECUTE FUNCTION public.notify_timezone_changed();


--
-- Name: audit_log trg_audit_log_no_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_audit_log_no_update BEFORE DELETE OR UPDATE ON public.audit_log FOR EACH ROW EXECUTE FUNCTION public.trg_audit_log_immutable();


--
-- Name: audit_log trg_audit_log_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_audit_log_notify AFTER INSERT ON public.audit_log FOR EACH ROW EXECUTE FUNCTION public.trg_audit_log_notify();


--
-- Name: auth_methods trg_auth_methods_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_auth_methods_notify AFTER INSERT OR DELETE OR UPDATE ON public.auth_methods FOR EACH ROW EXECUTE FUNCTION public.trg_auth_methods_notify();


--
-- Name: feature_toggles trg_feature_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_feature_notify AFTER INSERT OR UPDATE ON public.feature_toggles FOR EACH ROW EXECUTE FUNCTION public.trg_feature_notify();


--
-- Name: oauth_tokens trg_oauth_revoke_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_oauth_revoke_notify AFTER UPDATE ON public.oauth_tokens FOR EACH ROW EXECUTE FUNCTION public.trg_oauth_revoke_notify();


--
-- Name: rules trg_rules_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_rules_notify AFTER INSERT OR DELETE OR UPDATE ON public.rules FOR EACH ROW EXECUTE FUNCTION public.trg_rules_notify();


--
-- Name: system_config trg_system_config_notify; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_system_config_notify AFTER INSERT OR UPDATE ON public.system_config FOR EACH ROW EXECUTE FUNCTION public.trg_system_config_notify();


--
-- Name: addressbooks addressbooks_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.addressbooks
    ADD CONSTRAINT addressbooks_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: admin_audit_log admin_audit_log_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_audit_log
    ADD CONSTRAINT admin_audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: admin_role_assignments admin_role_assignments_domain_override_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_role_assignments
    ADD CONSTRAINT admin_role_assignments_domain_override_fkey FOREIGN KEY (domain_override) REFERENCES public.domains(id);


--
-- Name: admin_role_assignments admin_role_assignments_granted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_role_assignments
    ADD CONSTRAINT admin_role_assignments_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES public.users(id);


--
-- Name: admin_role_assignments admin_role_assignments_role_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_role_assignments
    ADD CONSTRAINT admin_role_assignments_role_group_id_fkey FOREIGN KEY (role_group_id) REFERENCES public.admin_role_groups(id) ON DELETE CASCADE;


--
-- Name: admin_role_assignments admin_role_assignments_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_role_assignments
    ADD CONSTRAINT admin_role_assignments_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: admin_role_groups admin_role_groups_domain_scope_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_role_groups
    ADD CONSTRAINT admin_role_groups_domain_scope_fkey FOREIGN KEY (domain_scope) REFERENCES public.domains(id);


--
-- Name: aliases aliases_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aliases
    ADD CONSTRAINT aliases_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id);


--
-- Name: aliases aliases_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.aliases
    ADD CONSTRAINT aliases_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: app_passwords app_passwords_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_passwords
    ADD CONSTRAINT app_passwords_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: audit_log audit_log_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.audit_log
    ADD CONSTRAINT audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: auth_event_log auth_event_log_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_event_log
    ADD CONSTRAINT auth_event_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: blob_cleanup_queue blob_cleanup_queue_blob_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.blob_cleanup_queue
    ADD CONSTRAINT blob_cleanup_queue_blob_sha256_fkey FOREIGN KEY (blob_sha256) REFERENCES public.blobs(sha256) ON DELETE CASCADE;


--
-- Name: calendar_acls calendar_acls_calendar_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_acls
    ADD CONSTRAINT calendar_acls_calendar_id_fkey FOREIGN KEY (calendar_id) REFERENCES public.calendars(id) ON DELETE CASCADE;


--
-- Name: calendar_acls calendar_acls_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_acls
    ADD CONSTRAINT calendar_acls_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: calendar_events calendar_events_calendar_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendar_events
    ADD CONSTRAINT calendar_events_calendar_id_fkey FOREIGN KEY (calendar_id) REFERENCES public.calendars(id) ON DELETE CASCADE;


--
-- Name: calendars calendars_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.calendars
    ADD CONSTRAINT calendars_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: contact_group_members contact_group_members_contact_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_group_members
    ADD CONSTRAINT contact_group_members_contact_id_fkey FOREIGN KEY (contact_id) REFERENCES public.contacts(id) ON DELETE CASCADE;


--
-- Name: contact_group_members contact_group_members_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_group_members
    ADD CONSTRAINT contact_group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.contact_groups(id) ON DELETE CASCADE;


--
-- Name: contact_groups contact_groups_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_groups
    ADD CONSTRAINT contact_groups_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: contacts contacts_addressbook_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts
    ADD CONSTRAINT contacts_addressbook_id_fkey FOREIGN KEY (addressbook_id) REFERENCES public.addressbooks(id) ON DELETE CASCADE;


--
-- Name: contacts contacts_avatar_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contacts
    ADD CONSTRAINT contacts_avatar_sha256_fkey FOREIGN KEY (avatar_sha256) REFERENCES public.blobs(sha256);


--
-- Name: departments departments_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.departments(id) ON DELETE SET NULL;


--
-- Name: device_events device_events_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_events
    ADD CONSTRAINT device_events_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;


--
-- Name: device_policy device_policy_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_policy
    ADD CONSTRAINT device_policy_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;


--
-- Name: device_registry device_registry_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_registry
    ADD CONSTRAINT device_registry_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: device_telemetry device_telemetry_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_telemetry
    ADD CONSTRAINT device_telemetry_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;


--
-- Name: devices devices_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: distribution_group_members distribution_group_members_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distribution_group_members
    ADD CONSTRAINT distribution_group_members_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.distribution_groups(id) ON DELETE CASCADE;


--
-- Name: distribution_group_members distribution_group_members_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distribution_group_members
    ADD CONSTRAINT distribution_group_members_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: distribution_groups distribution_groups_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distribution_groups
    ADD CONSTRAINT distribution_groups_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id);


--
-- Name: distribution_groups distribution_groups_moderator_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distribution_groups
    ADD CONSTRAINT distribution_groups_moderator_mailbox_id_fkey FOREIGN KEY (moderator_mailbox_id) REFERENCES public.mailboxes(id) ON DELETE SET NULL;


--
-- Name: dlp_policies dlp_policies_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dlp_policies
    ADD CONSTRAINT dlp_policies_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;


--
-- Name: dlp_policy_targets dlp_policy_targets_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dlp_policy_targets
    ADD CONSTRAINT dlp_policy_targets_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: dlp_policy_targets dlp_policy_targets_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dlp_policy_targets
    ADD CONSTRAINT dlp_policy_targets_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.dlp_policies(id) ON DELETE CASCADE;


--
-- Name: dlp_violations dlp_violations_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dlp_violations
    ADD CONSTRAINT dlp_violations_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id);


--
-- Name: dlp_violations dlp_violations_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dlp_violations
    ADD CONSTRAINT dlp_violations_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.dlp_policies(id);


--
-- Name: domain_signing_keys domain_signing_keys_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domain_signing_keys
    ADD CONSTRAINT domain_signing_keys_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;


--
-- Name: domains domains_catch_all_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_catch_all_fk FOREIGN KEY (catch_all_mailbox_id) REFERENCES public.mailboxes(id) ON DELETE SET NULL;


--
-- Name: ediscovery_cases ediscovery_cases_closed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ediscovery_cases
    ADD CONSTRAINT ediscovery_cases_closed_by_fkey FOREIGN KEY (closed_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: ediscovery_cases ediscovery_cases_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ediscovery_cases
    ADD CONSTRAINT ediscovery_cases_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: ediscovery_searches ediscovery_searches_case_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ediscovery_searches
    ADD CONSTRAINT ediscovery_searches_case_id_fkey FOREIGN KEY (case_id) REFERENCES public.ediscovery_cases(id) ON DELETE SET NULL;


--
-- Name: ediscovery_searches ediscovery_searches_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ediscovery_searches
    ADD CONSTRAINT ediscovery_searches_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: email_templates email_templates_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_templates
    ADD CONSTRAINT email_templates_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: event_attendees event_attendees_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_attendees
    ADD CONSTRAINT event_attendees_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.calendar_events(id) ON DELETE CASCADE;


--
-- Name: external_sender_config external_sender_config_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_sender_config
    ADD CONSTRAINT external_sender_config_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;


--
-- Name: field_policy field_policy_set_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.field_policy
    ADD CONSTRAINT field_policy_set_by_fkey FOREIGN KEY (set_by) REFERENCES public.users(id);


--
-- Name: field_policy field_policy_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.field_policy
    ADD CONSTRAINT field_policy_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: folders folders_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.folders
    ADD CONSTRAINT folders_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: folders folders_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.folders
    ADD CONSTRAINT folders_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.folders(id) ON DELETE CASCADE;


--
-- Name: ip_rules ip_rules_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_rules
    ADD CONSTRAINT ip_rules_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: journal_queue journal_queue_journal_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.journal_queue
    ADD CONSTRAINT journal_queue_journal_mailbox_id_fkey FOREIGN KEY (journal_mailbox_id) REFERENCES public.mailboxes(id) ON DELETE RESTRICT;


--
-- Name: journaling_policies journaling_policies_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.journaling_policies
    ADD CONSTRAINT journaling_policies_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;


--
-- Name: journaling_policies journaling_policies_journal_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.journaling_policies
    ADD CONSTRAINT journaling_policies_journal_mailbox_id_fkey FOREIGN KEY (journal_mailbox_id) REFERENCES public.mailboxes(id) ON DELETE RESTRICT;


--
-- Name: login_events login_events_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_events
    ADD CONSTRAINT login_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mailbox_audit_log mailbox_audit_log_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.mailbox_audit_log
    ADD CONSTRAINT mailbox_audit_log_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: mailbox_audit_log mailbox_audit_log_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.mailbox_audit_log
    ADD CONSTRAINT mailbox_audit_log_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: mailbox_delegates mailbox_delegates_granted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailbox_delegates
    ADD CONSTRAINT mailbox_delegates_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: mailbox_delegates mailbox_delegates_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailbox_delegates
    ADD CONSTRAINT mailbox_delegates_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: mailbox_delegates mailbox_delegates_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailbox_delegates
    ADD CONSTRAINT mailbox_delegates_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mailboxes mailboxes_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailboxes
    ADD CONSTRAINT mailboxes_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id);


--
-- Name: mailboxes mailboxes_hold_set_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailboxes
    ADD CONSTRAINT mailboxes_hold_set_by_fkey FOREIGN KEY (hold_set_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: mailboxes mailboxes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailboxes
    ADD CONSTRAINT mailboxes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: managed_devices managed_devices_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_devices
    ADD CONSTRAINT managed_devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: mdm_device_state mdm_device_state_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mdm_device_state
    ADD CONSTRAINT mdm_device_state_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: message_attachments message_attachments_blob_sha256_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_attachments
    ADD CONSTRAINT message_attachments_blob_sha256_fkey FOREIGN KEY (blob_sha256) REFERENCES public.blobs(sha256);


--
-- Name: message_attachments message_attachments_message_id_received_at_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_attachments
    ADD CONSTRAINT message_attachments_message_id_received_at_fkey FOREIGN KEY (message_id, received_at) REFERENCES public.messages(id, received_at) ON DELETE CASCADE;


--
-- Name: message_recalls message_recalls_recalled_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_recalls
    ADD CONSTRAINT message_recalls_recalled_by_fkey FOREIGN KEY (recalled_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: message_retention_tags message_retention_tags_message_id_received_at_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_retention_tags
    ADD CONSTRAINT message_retention_tags_message_id_received_at_fkey FOREIGN KEY (message_id, received_at) REFERENCES public.messages(id, received_at);


--
-- Name: message_retention_tags message_retention_tags_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_retention_tags
    ADD CONSTRAINT message_retention_tags_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.retention_policies(id);


--
-- Name: message_tags message_tags_message_id_received_at_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.message_tags
    ADD CONSTRAINT message_tags_message_id_received_at_fkey FOREIGN KEY (message_id, received_at) REFERENCES public.messages(id, received_at) ON DELETE CASCADE;


--
-- Name: message_tags message_tags_tag_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.message_tags
    ADD CONSTRAINT message_tags_tag_id_fkey FOREIGN KEY (tag_id) REFERENCES public.tags(id) ON DELETE CASCADE;


--
-- Name: messages messages_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.messages
    ADD CONSTRAINT messages_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id);


--
-- Name: migration_jobs migration_jobs_target_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.migration_jobs
    ADD CONSTRAINT migration_jobs_target_mailbox_id_fkey FOREIGN KEY (target_mailbox_id) REFERENCES public.mailboxes(id) ON DELETE SET NULL;


--
-- Name: migration_jobs migration_jobs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.migration_jobs
    ADD CONSTRAINT migration_jobs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: oauth_tokens oauth_tokens_revoked_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_tokens
    ADD CONSTRAINT oauth_tokens_revoked_by_fkey FOREIGN KEY (revoked_by) REFERENCES public.users(id);


--
-- Name: oauth_tokens oauth_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_tokens
    ADD CONSTRAINT oauth_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: oidc_auth_requests oidc_auth_requests_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_auth_requests
    ADD CONSTRAINT oidc_auth_requests_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oidc_clients(id);


--
-- Name: oidc_tokens oidc_tokens_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_tokens
    ADD CONSTRAINT oidc_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oidc_clients(id);


--
-- Name: oidc_tokens oidc_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_tokens
    ADD CONSTRAINT oidc_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: outbound_queue outbound_queue_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.outbound_queue
    ADD CONSTRAINT outbound_queue_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE SET NULL;


--
-- Name: passkey_credentials passkey_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.passkey_credentials
    ADD CONSTRAINT passkey_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: password_history password_history_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_history
    ADD CONSTRAINT password_history_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: push_devices push_devices_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_devices
    ADD CONSTRAINT push_devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: push_mfa_challenges push_mfa_challenges_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.push_mfa_challenges
    ADD CONSTRAINT push_mfa_challenges_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: quarantined_messages quarantined_messages_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quarantined_messages
    ADD CONSTRAINT quarantined_messages_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: quarantined_messages quarantined_messages_rejected_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quarantined_messages
    ADD CONSTRAINT quarantined_messages_rejected_by_fkey FOREIGN KEY (rejected_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: quarantined_messages quarantined_messages_released_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quarantined_messages
    ADD CONSTRAINT quarantined_messages_released_by_fkey FOREIGN KEY (released_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: quick_steps quick_steps_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quick_steps
    ADD CONSTRAINT quick_steps_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: reminders reminders_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.reminders
    ADD CONSTRAINT reminders_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: retention_policies retention_policies_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.retention_policies
    ADD CONSTRAINT retention_policies_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;


--
-- Name: rules rules_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: rules rules_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rules
    ADD CONSTRAINT rules_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: scheduled_actions scheduled_actions_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduled_actions
    ADD CONSTRAINT scheduled_actions_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: signatures signatures_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.signatures
    ADD CONSTRAINT signatures_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: sync_conflicts sync_conflicts_resolved_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sync_conflicts
    ADD CONSTRAINT sync_conflicts_resolved_by_fkey FOREIGN KEY (resolved_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: sync_conflicts sync_conflicts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sync_conflicts
    ADD CONSTRAINT sync_conflicts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: system_config system_config_updated_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_config
    ADD CONSTRAINT system_config_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: tags tags_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: tags tags_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.tags(id) ON DELETE CASCADE;


--
-- Name: tasks tasks_assignee_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT tasks_assignee_user_id_fkey FOREIGN KEY (assignee_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: tasks tasks_linked_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT tasks_linked_event_id_fkey FOREIGN KEY (linked_event_id) REFERENCES public.calendar_events(id) ON DELETE SET NULL;


--
-- Name: tasks tasks_linked_message_id_linked_message_received_at_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT tasks_linked_message_id_linked_message_received_at_fkey FOREIGN KEY (linked_message_id, linked_message_received_at) REFERENCES public.messages(id, received_at) ON DELETE SET NULL;


--
-- Name: tasks tasks_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT tasks_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: tasks tasks_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tasks
    ADD CONSTRAINT tasks_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.tasks(id) ON DELETE CASCADE;


--
-- Name: user_app_entitlements user_app_entitlements_updated_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_app_entitlements
    ADD CONSTRAINT user_app_entitlements_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: user_app_entitlements user_app_entitlements_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_app_entitlements
    ADD CONSTRAINT user_app_entitlements_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_devices user_devices_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_devices
    ADD CONSTRAINT user_devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_imap_settings user_imap_settings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_imap_settings
    ADD CONSTRAINT user_imap_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_notification_prefs user_notification_prefs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_notification_prefs
    ADD CONSTRAINT user_notification_prefs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_sender_list user_sender_list_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sender_list
    ADD CONSTRAINT user_sender_list_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_signatures user_signatures_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_signatures
    ADD CONSTRAINT user_signatures_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_smime_certs user_smime_certs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_smime_certs
    ADD CONSTRAINT user_smime_certs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_spam_model user_spam_model_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_spam_model
    ADD CONSTRAINT user_spam_model_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: users users_avatar_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_avatar_fk FOREIGN KEY (avatar_sha256) REFERENCES public.blobs(sha256) ON DELETE SET NULL;


--
-- Name: users users_department_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_department_id_fkey FOREIGN KEY (department_id) REFERENCES public.departments(id) ON DELETE SET NULL;


--
-- Name: users users_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id);


--
-- Name: users users_manager_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_manager_id_fkey FOREIGN KEY (manager_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: vacation_replies vacation_replies_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vacation_replies
    ADD CONSTRAINT vacation_replies_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: vacation_settings vacation_settings_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vacation_settings
    ADD CONSTRAINT vacation_settings_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;


--
-- Name: vt_timezone vt_timezone_calendar_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vt_timezone
    ADD CONSTRAINT vt_timezone_calendar_id_fkey FOREIGN KEY (calendar_id) REFERENCES public.calendars(id) ON DELETE CASCADE;


--
-- Name: webhook_deliveries webhook_deliveries_subscription_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_subscription_id_fkey FOREIGN KEY (subscription_id) REFERENCES public.webhook_subscriptions(id) ON DELETE CASCADE;


--
-- Name: webhook_subscriptions webhook_subscriptions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_subscriptions
    ADD CONSTRAINT webhook_subscriptions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;



--
-- ════════════════════════════════════════════════════════════════════════
-- SEED DATA (system reference rows present in every fresh build).
-- pg_dump --schema-only drops these; the baseline therefore carries them
-- explicitly. Rows are sorted deterministically within each table block.
-- ════════════════════════════════════════════════════════════════════════
--

--
-- Data: admin_permissions (21 rows); Type: SEED; domain: mailserver
--

INSERT INTO public.admin_permissions VALUES ('audit.read', 'Audit', 'View audit logs, login history', false);
INSERT INTO public.admin_permissions VALUES ('backup.read', 'Backup', 'View backup status, restore history', false);
INSERT INTO public.admin_permissions VALUES ('backup.write', 'Backup', 'Trigger backup, initiate restore', true);
INSERT INTO public.admin_permissions VALUES ('compliance.read', 'Compliance', 'View eDiscovery, retention policies, DLP', false);
INSERT INTO public.admin_permissions VALUES ('compliance.write', 'Compliance', 'Create eDiscovery cases, edit policies', true);
INSERT INTO public.admin_permissions VALUES ('domains.read', 'Domains', 'View domain configuration', false);
INSERT INTO public.admin_permissions VALUES ('domains.write', 'Domains', 'Add/remove domains, change DNS config', true);
INSERT INTO public.admin_permissions VALUES ('mam.read', 'MAM', 'View MAM policies, device list, events', false);
INSERT INTO public.admin_permissions VALUES ('mam.write', 'MAM', 'Change policies, lock/wipe devices', true);
INSERT INTO public.admin_permissions VALUES ('queue.read', 'Queue', 'View outbound queue status', false);
INSERT INTO public.admin_permissions VALUES ('queue.write', 'Queue', 'Retry, bounce, purge queue items', false);
INSERT INTO public.admin_permissions VALUES ('reports.read', 'Reports', 'View storage, traffic, user activity reports', false);
INSERT INTO public.admin_permissions VALUES ('roles.manage', 'Roles', 'Create/edit/delete role groups', true);
INSERT INTO public.admin_permissions VALUES ('security.write', 'Security', 'Threat settings, TLS config, spam threshold', true);
INSERT INTO public.admin_permissions VALUES ('system.config', 'System', 'Change gateway config, feature toggles', true);
INSERT INTO public.admin_permissions VALUES ('system.upgrade', 'System', 'Trigger software upgrade', true);
INSERT INTO public.admin_permissions VALUES ('users.delete', 'Users', 'Permanently delete users', true);
INSERT INTO public.admin_permissions VALUES ('users.impersonate', 'Users', 'Impersonate another user mailbox', true);
INSERT INTO public.admin_permissions VALUES ('users.password_reset', 'Users', 'Reset non-admin passwords', false);
INSERT INTO public.admin_permissions VALUES ('users.read', 'Users', 'View users, profiles, aliases', false);
INSERT INTO public.admin_permissions VALUES ('users.write', 'Users', 'Create, update, suspend users', false);

--
-- Data: admin_role_groups (6 rows); Type: SEED; domain: mailserver
--

INSERT INTO public.admin_role_groups VALUES (1, 'Super Admin', 'Full unrestricted access to all admin features.', '{users.read,users.write,users.delete,users.password_reset,users.impersonate,domains.read,domains.write,audit.read,mam.read,mam.write,queue.read,queue.write,reports.read,security.write,roles.manage,compliance.read,compliance.write,backup.read,backup.write,system.config,system.upgrade}', NULL, true, '2026-06-18 16:02:03.142877+08', '2026-06-18 16:02:03.142877+08');
INSERT INTO public.admin_role_groups VALUES (2, 'User Admin', 'Manage users and view domains. Cannot change server settings.', '{users.read,users.write,users.password_reset,domains.read,audit.read}', NULL, true, '2026-06-18 16:02:03.142877+08', '2026-06-18 16:02:03.142877+08');
INSERT INTO public.admin_role_groups VALUES (3, 'Help Desk', 'Reset passwords, view users, manage mail queue.', '{users.read,users.password_reset,queue.read,queue.write}', NULL, true, '2026-06-18 16:02:03.142877+08', '2026-06-18 16:02:03.142877+08');
INSERT INTO public.admin_role_groups VALUES (4, 'Audit Reader', 'Read-only access to audit logs and reports.', '{audit.read,reports.read}', NULL, true, '2026-06-18 16:02:03.142877+08', '2026-06-18 16:02:03.142877+08');
INSERT INTO public.admin_role_groups VALUES (5, 'Security Admin', 'Manage MAM policies, security settings. Cannot manage users.', '{mam.read,mam.write,security.write,audit.read,users.read}', NULL, true, '2026-06-18 16:02:03.142877+08', '2026-06-18 16:02:03.142877+08');
INSERT INTO public.admin_role_groups VALUES (6, 'Domain Admin', 'Manage users and view reports for a specific domain. Domain scope required.', '{users.read,users.write,users.password_reset,domains.read,audit.read,reports.read}', NULL, true, '2026-06-18 16:02:03.142877+08', '2026-06-18 16:02:03.142877+08');

SELECT pg_catalog.setval('public.admin_role_groups_id_seq', 6, true);

--
-- Data: auth_methods (5 rows); Type: SEED; domain: mailserver
--

INSERT INTO public.auth_methods VALUES (1, 'jwt_bearer', 'JWT Bearer Token', true, 10, '{}', '2026-06-18 16:02:01.351557+08', '2026-06-18 16:02:01.351557+08');
INSERT INTO public.auth_methods VALUES (2, 'kerberos', 'Kerberos / SPNEGO', false, 20, '{}', '2026-06-18 16:02:01.351557+08', '2026-06-18 16:02:01.351557+08');
INSERT INTO public.auth_methods VALUES (3, 'saml', 'SAML 2.0', false, 30, '{}', '2026-06-18 16:02:01.351557+08', '2026-06-18 16:02:01.351557+08');
INSERT INTO public.auth_methods VALUES (4, 'oidc', 'OpenID Connect', false, 40, '{}', '2026-06-18 16:02:01.351557+08', '2026-06-18 16:02:01.351557+08');
INSERT INTO public.auth_methods VALUES (5, 'webauthn', 'WebAuthn / FIDO2', false, 50, '{}', '2026-06-18 16:02:01.351557+08', '2026-06-18 16:02:01.351557+08');

SELECT pg_catalog.setval('public.auth_methods_id_seq', 5, true);

--
-- Data: conditional_access_policies (5 rows); Type: SEED; domain: mailserver
--

INSERT INTO public.conditional_access_policies VALUES (1, 10, 'Block critical countries', 'Block authentication from critical-risk countries', false, 'global', '', '{"geo_risk_tier": "critical"}', '{"action": "block", "reason": "Authentication from critical-risk country is blocked"}', '2026-06-18 16:02:02.755862+08', '2026-06-18 16:02:02.755862+08');
INSERT INTO public.conditional_access_policies VALUES (2, 20, 'Step-up high-risk + unknown device', 'Require MFA when signing in from high-risk country with unknown device', false, 'global', '', '{"device_trust": "unknown", "geo_risk_tier": "high"}', '{"action": "step_up", "reason": "MFA required for high-risk country sign-in with unknown device", "methods": ["totp", "webauthn"]}', '2026-06-18 16:02:02.755862+08', '2026-06-18 16:02:02.755862+08');
INSERT INTO public.conditional_access_policies VALUES (3, 30, 'Step-up risky device', 'Require MFA when using a risky device', false, 'global', '', '{"device_trust": "risky"}', '{"action": "step_up", "reason": "MFA required for unrecognized device", "methods": ["totp", "webauthn", "push"]}', '2026-06-18 16:02:02.755862+08', '2026-06-18 16:02:02.755862+08');
INSERT INTO public.conditional_access_policies VALUES (4, 40, 'Block medium IP risk + critical country', 'Block when medium IP reputation from critical country', false, 'global', '', '{"geo_risk_tier": "critical", "ip_reputation": "medium"}', '{"action": "block", "reason": "Suspicious IP from critical-risk country"}', '2026-06-18 16:02:02.755862+08', '2026-06-18 16:02:02.755862+08');
INSERT INTO public.conditional_access_policies VALUES (5, 50, 'Notify high IP risk', 'Send admin alert when high IP risk score detected', false, 'global', '', '{"ip_reputation": "high"}', '{"action": "notify", "reason": "High IP risk score detected", "channels": ["admin_alert", "audit"]}', '2026-06-18 16:02:02.755862+08', '2026-06-18 16:02:02.755862+08');

SELECT pg_catalog.setval('public.conditional_access_policies_id_seq', 5, true);

--
-- Data: dlp_policies (8 rows); Type: SEED; domain: mailserver
--

INSERT INTO public.dlp_policies VALUES (1, NULL, 'Credit Card Number', true, 0, 'block', '{"\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b"}', '{}', 0.7, '{}', 0, true, '2026-06-18 16:02:03.511188+08', '2026-06-18 16:02:03.511188+08', true);
INSERT INTO public.dlp_policies VALUES (2, NULL, 'SSN (US Social Security)', true, 0, 'quarantine', '{"\\b\\d{3}-\\d{2}-\\d{4}\\b"}', '{}', 0.7, '{}', 0, true, '2026-06-18 16:02:03.511188+08', '2026-06-18 16:02:03.511188+08', true);
INSERT INTO public.dlp_policies VALUES (3, NULL, 'IBAN (Bank Account)', true, 0, 'notify_admin', '{"\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b"}', '{}', 0.7, '{}', 0, true, '2026-06-18 16:02:03.511188+08', '2026-06-18 16:02:03.511188+08', true);
INSERT INTO public.dlp_policies VALUES (4, NULL, 'Passport Number', false, 0, 'notify_admin', '{"\\b[A-Z0-9]{6,9}\\b"}', '{}', 0.7, '{}', 0, true, '2026-06-18 16:02:03.511188+08', '2026-06-18 16:02:03.511188+08', true);
INSERT INTO public.dlp_policies VALUES (5, NULL, 'API Key / Secret', true, 0, 'block', '{"\\b(?:sk-|api-|key-|secret-)[A-Za-z0-9_\\-]{20,}\\b"}', '{}', 0.7, '{}', 0, true, '2026-06-18 16:02:03.511188+08', '2026-06-18 16:02:03.511188+08', true);
INSERT INTO public.dlp_policies VALUES (6, NULL, 'Chinese Resident ID (18-digit)', true, 0, 'quarantine', '{"\\b[1-9]\\d{5}(?:19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{3}[0-9Xx]\\b"}', '{}', 0.7, '{}', 0, true, '2026-06-18 16:02:03.511188+08', '2026-06-18 16:02:03.511188+08', true);
INSERT INTO public.dlp_policies VALUES (7, NULL, 'Chinese Phone Number', true, 0, 'warn', '{"\\b1[3-9]\\d{9}\\b"}', '{}', 0.7, '{}', 0, true, '2026-06-18 16:02:03.511188+08', '2026-06-18 16:02:03.511188+08', true);
INSERT INTO public.dlp_policies VALUES (8, NULL, 'Chinese Business License', true, 0, 'warn', '{"\\b[0-9A-HJ-NPQRTUWXY]{2}\\d{5}[0-9A-HJ-NPQRTUWXY]{10}\\b"}', '{}', 0.7, '{}', 0, true, '2026-06-18 16:02:03.511188+08', '2026-06-18 16:02:03.511188+08', true);

SELECT pg_catalog.setval('public.dlp_policies_id_seq', 9, true);

--
-- Data: feature_toggles (44 rows); Type: SEED; domain: mailserver
--

INSERT INTO public.feature_toggles VALUES ('device_telemetry', false, 'Enable anonymous device telemetry collection (no PII, no email content, no IPs)', '2026-06-18 16:02:03.314735+08');
INSERT INTO public.feature_toggles VALUES ('feature.ad_sync', false, 'Active Directory sync engine', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.antiphish_contact_graph', true, 'Contact graph impersonation detector (novel sender with known display name)', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.antiphish_display_name', true, 'Display-name spoofing detector (fuzzy match against internal users)', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.antiphish_lookalike', true, 'Lookalike domain detector (homoglyph + Levenshtein against protected domains)', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.antiphish_strict_mode', false, 'Treat Warn as Reject for all anti-phishing detectors', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.assist', false, 'AI assist: compose draft/polish/translate and admin ops copilot (pluggable provider)', '2026-06-18 16:02:03.441202+08');
INSERT INTO public.feature_toggles VALUES ('feature.auth_log_app_password', true, 'Log app password authentication events', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.auth_log_basic', false, 'Log HTTP Basic auth events (high volume — off by default)', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.auth_log_bcrypt', true, 'Log bcrypt authentication events', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.auth_log_jwt', true, 'Log JWT issuance events', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.auth_log_kerberos', true, 'Log Kerberos/SPNEGO authentication events', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.caldav', true, 'CalDAV bridge', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.captcha', true, 'Math CAPTCHA challenge on repeated failures', '2026-06-18 16:02:01.727051+08');
INSERT INTO public.feature_toggles VALUES ('feature.carddav', true, 'CardDAV bridge', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.cert_rollout', false, 'Enable 2×TLSA rolling rollout for cert changes (default: stable key reuse via TLS_AUTOCERT_KEY_FILE)', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.conditional_access', false, NULL, '2026-06-18 16:02:02.755035+08');
INSERT INTO public.feature_toggles VALUES ('feature.dane', true, 'Enable DANE (RFC 7672) outbound SMTP TLSA validation after STARTTLS', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.dnssec', true, 'Enable DNSSEC validation for DNS lookups and TLSA record generation', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.external_sender_first_time', true, 'Show green first-time-sender notice for unknown senders', '2026-06-18 16:02:02.620237+08');
INSERT INTO public.feature_toggles VALUES ('feature.external_sender_name_spoof', true, 'Escalate banner to red pill when display name matches internal user', '2026-06-18 16:02:02.620237+08');
INSERT INTO public.feature_toggles VALUES ('feature.external_sender_warn', true, 'Show amber warning banner on messages from external senders', '2026-06-18 16:02:02.620237+08');
INSERT INTO public.feature_toggles VALUES ('feature.forgot_password', true, 'Allow users to reset forgotten passwords via MFA', '2026-06-18 16:02:01.830989+08');
INSERT INTO public.feature_toggles VALUES ('feature.forgot_password_push', true, 'Allow push MFA as forgot-password verification method', '2026-06-18 16:02:01.830989+08');
INSERT INTO public.feature_toggles VALUES ('feature.geo_block', true, 'MaxMind GeoIP2 country-level geo-blocking', '2026-06-18 16:02:01.727051+08');
INSERT INTO public.feature_toggles VALUES ('feature.imap', true, 'IMAP4rev2 server on ports 143 and 993', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.journaling', true, 'BCC-style journaling: archive a copy of every message to a designated journal mailbox', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.kerberos', false, 'Kerberos / SPNEGO authentication', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.ldap_gal', true, 'LDAP GAL server on port 389', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.link_protect_rewrite', true, 'Master toggle: rewrite URLs in inbound email bodies through /link-protect proxy', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.link_protect_safebrowsing', true, 'Google Safe Browsing API v5 scanner for link protection', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.link_protect_spamhaus', true, 'Spamhaus DBL scanner for link protection', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.link_protect_strict_mode', false, 'Treat unknown verdicts as malicious (block instead of warn)', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.mdm', true, NULL, '2026-06-18 16:02:02.788981+08');
INSERT INTO public.feature_toggles VALUES ('feature.ml_spam', true, 'Per-user FTRL-Proximal spam classifier', '2026-06-18 16:02:03.005314+08');
INSERT INTO public.feature_toggles VALUES ('feature.newsletter_bundles', true, 'Computed newsletter bundle grouping by List-Id header (B5). Absent row treated as TRUE by effective_capabilities().', '2026-06-18 16:02:03.603658+08');
INSERT INTO public.feature_toggles VALUES ('feature.oidc', false, 'OpenID Connect relying party', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.require_mfa', true, 'Require MFA for all users', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.saml', false, 'SAML 2.0 service provider', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.smtp_inbound', true, 'SMTP inbound MTA on port 25', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.smtp_submission', true, 'SMTP submission MSA on port 587', '2026-06-18 16:02:02.332339+08');
INSERT INTO public.feature_toggles VALUES ('feature.spray_detect', true, 'Password spray attack detection', '2026-06-18 16:02:01.727051+08');
INSERT INTO public.feature_toggles VALUES ('feature.tarpit', true, 'Connection delay for suspicious clients', '2026-06-18 16:02:01.727051+08');
INSERT INTO public.feature_toggles VALUES ('feature.threat_feed', true, 'Spamhaus DROP threat feed blocking', '2026-06-18 16:02:01.727051+08');

--
-- Data: geo_country_tiers (10 rows); Type: SEED; domain: mailserver
--

INSERT INTO public.geo_country_tiers VALUES ('BY', 'high', 'Sanctions + cyber threat (Belarus)', '2026-06-18 16:02:02.754434+08');
INSERT INTO public.geo_country_tiers VALUES ('CN', 'high', 'Elevated cyber threat (China)', '2026-06-18 16:02:02.754434+08');
INSERT INTO public.geo_country_tiers VALUES ('CU', 'critical', 'OFAC comprehensive sanctions (Cuba)', '2026-06-18 16:02:02.754434+08');
INSERT INTO public.geo_country_tiers VALUES ('IR', 'critical', 'OFAC comprehensive sanctions (Iran)', '2026-06-18 16:02:02.754434+08');
INSERT INTO public.geo_country_tiers VALUES ('KP', 'critical', 'OFAC comprehensive sanctions (DPRK)', '2026-06-18 16:02:02.754434+08');
INSERT INTO public.geo_country_tiers VALUES ('MM', 'high', 'Sanctions (Myanmar)', '2026-06-18 16:02:02.754434+08');
INSERT INTO public.geo_country_tiers VALUES ('RU', 'high', 'Sectoral sanctions + elevated cyber threat (Russia)', '2026-06-18 16:02:02.754434+08');
INSERT INTO public.geo_country_tiers VALUES ('SD', 'high', 'Sanctions (Sudan)', '2026-06-18 16:02:02.754434+08');
INSERT INTO public.geo_country_tiers VALUES ('SY', 'critical', 'OFAC comprehensive sanctions (Syria)', '2026-06-18 16:02:02.754434+08');
INSERT INTO public.geo_country_tiers VALUES ('VE', 'high', 'Sectoral sanctions (Venezuela)', '2026-06-18 16:02:02.754434+08');

--
-- Data: mdm_policies (1 rows); Type: SEED; domain: mailserver
--

INSERT INTO public.mdm_policies VALUES (1, 'Default', 'Built-in default policy — permissive baseline', 0, 'global', NULL, true, 6, 'numeric', 90, 5, 10, 5, false, false, true, '', '', 'quarantine', 3600, 60, '2026-06-18 16:02:02.790103+08', '2026-06-18 16:02:02.790103+08');

SELECT pg_catalog.setval('public.mdm_policies_id_seq', 1, true);

--
-- Data: retention_policies (5 rows); Type: SEED; domain: mailserver
--

INSERT INTO public.retention_policies VALUES (1, 'Default Global Policy', 'Applies to all domains unless overridden', 30, 'delete', true, NULL, '2026-06-18 16:02:01.955219+08');
INSERT INTO public.retention_policies VALUES (2, 'Default 2-Year', 'Standard retention policy — keep messages for 2 years then delete.', 730, 'delete', false, NULL, '2026-06-18 16:02:02.211624+08');
INSERT INTO public.retention_policies VALUES (3, 'Finance 7-Year', 'Finance compliance retention — 7 years per SEC/IRS recordkeeping requirements.', 2555, 'delete', false, NULL, '2026-06-18 16:02:02.211624+08');
INSERT INTO public.retention_policies VALUES (4, 'HR 1-Year', 'HR personnel records retention — 1 year per standard employment guidelines.', 365, 'delete', false, NULL, '2026-06-18 16:02:02.211624+08');
INSERT INTO public.retention_policies VALUES (5, 'Auto-Purge 90-Day', 'Short retention — auto-delete messages after 90 days. For transient or notification-only mailboxes.', 90, 'delete', false, NULL, '2026-06-18 16:02:02.211624+08');

SELECT pg_catalog.setval('public.retention_policies_id_seq', 8, true);

--
-- Data: system_config (72 rows); Type: SEED; domain: mailserver
--

INSERT INTO public.system_config VALUES ('ad_sync_auto_create_depts', '"false"', false, 'Auto-create departments from AD', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('ad_sync_bind_dn', '""', false, 'AD service account DN', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('ad_sync_domain', '""', false, 'Active Directory domain name', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('ad_sync_enabled', '"false"', false, 'Enable automatic AD user sync', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('ad_sync_interval_min', '"15"', false, 'AD sync interval in minutes', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('ad_sync_ldap_host', '""', false, 'AD LDAP host override (auto-discovered from DNS if empty)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('ad_sync_password_enc', '""', false, 'AD service account password (AES-256-GCM encrypted)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('ad_sync_proxy_as_aliases', '"false"', false, 'Sync proxyAddresses as email aliases', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('alert_email_addresses', '""', false, 'Comma-separated admin emails for health alerts', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('alert_min_consecutive', '"3"', false, 'Consecutive health check failures before alerting', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('antiphish.name_similarity_threshold', '0.85', false, 'pg_trgm similarity threshold for display-name fuzzy matching (0.0–1.0)', '2026-06-18 16:02:02.655122+08', NULL);
INSERT INTO public.system_config VALUES ('antiphish.protected_domains', '[]', false, 'High-value domains for lookalike detection (JSON array of strings, e.g. ["microsoft.com","google.com","paypal.com"])', '2026-06-18 16:02:02.655122+08', NULL);
INSERT INTO public.system_config VALUES ('auth_grace_hours', '"4"', false, 'Hours to keep JWT valid if AD is unreachable', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('auto_update.auto_apply_safe', 'false', false, NULL, '2026-06-18 16:02:02.861298+08', NULL);
INSERT INTO public.system_config VALUES ('auto_update.channel', '"stable"', false, NULL, '2026-06-18 16:02:02.861298+08', NULL);
INSERT INTO public.system_config VALUES ('auto_update.check_interval', '"daily"', false, NULL, '2026-06-18 16:02:02.861298+08', NULL);
INSERT INTO public.system_config VALUES ('auto_update.enabled', 'false', false, NULL, '2026-06-18 16:02:02.861298+08', NULL);
INSERT INTO public.system_config VALUES ('auto_update.notify_admin', 'true', false, NULL, '2026-06-18 16:02:02.861298+08', NULL);
INSERT INTO public.system_config VALUES ('auto_update.require_confirm_breaking', 'true', false, NULL, '2026-06-18 16:02:02.861298+08', NULL);
INSERT INTO public.system_config VALUES ('auto_update.source_path', '"/opt/mailserver/releases"', false, NULL, '2026-06-18 16:02:02.861298+08', NULL);
INSERT INTO public.system_config VALUES ('default_quota_bytes', '"53687091200"', false, 'Default storage quota per new mailbox (50 GB)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('default_sending_quota_day', '"500"', false, 'Default daily sending limit per new mailbox', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('deleted_items_purge_days', '30', false, 'Number of days before soft-deleted emails are permanently purged. 0 = disable auto-purge.', '2026-06-18 16:02:02.186937+08', NULL);
INSERT INTO public.system_config VALUES ('enable_sms_reset', '"false"', false, 'Allow SMS-based password reset', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('enable_totp_reset', '"true"', false, 'Allow TOTP-based password reset', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('external_sender.enabled', 'true', false, NULL, '2026-06-18 16:02:02.930393+08', NULL);
INSERT INTO public.system_config VALUES ('external_sender.warn_color', '"#FFD60A"', false, NULL, '2026-06-18 16:02:02.930393+08', NULL);
INSERT INTO public.system_config VALUES ('external_sender.warn_text', '"This message is from an external sender. Use caution when clicking links or opening attachments."', false, NULL, '2026-06-18 16:02:02.930393+08', NULL);
INSERT INTO public.system_config VALUES ('hc_auth_fail_error', '"200"', false, 'Auth failure rate error threshold (failed attempts per 5-minute window)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('hc_auth_fail_warn', '"50"', false, 'Auth failure rate warn threshold (failed attempts per 5-minute window)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('hc_consec_fail_window_min', '"20"', false, 'Consecutive failure escalation window (minutes)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('hc_crash_window_min', '"10"', false, 'Crash event detection window (minutes)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('hc_db_size_error_gb', '"100"', false, 'Database size error threshold (GB)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('hc_db_size_warn_gb', '"80"', false, 'Database size warn threshold (GB)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('hc_dkim_expiry_error_days', '"7"', false, 'DKIM key expiry error threshold (days)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('hc_dkim_expiry_warn_days', '"30"', false, 'DKIM key expiry warn threshold (days)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('hc_outbound_queue_age_error_min', '"60"', false, 'Oldest queue item age error threshold (minutes)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('hc_outbound_queue_age_warn_min', '"15"', false, 'Oldest queue item age warn threshold (minutes)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('hc_outbound_queue_error', '"500"', false, 'Outbound queue depth error threshold (messages)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('hc_outbound_queue_warn', '"100"', false, 'Outbound queue depth warn threshold (messages)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('hc_replication_lag_error_sec', '"60"', false, 'Replication lag error threshold (seconds)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('hc_replication_lag_warn_sec', '"30"', false, 'Replication lag warn threshold (seconds)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('identity_source', '"local"', false, 'Identity provider: local | ad | ldap', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('log_retention_auth_event_days', '90', false, 'Number of days to retain auth_event_log rows. NULL or 0 = keep forever.', '2026-06-18 16:02:01.95354+08', NULL);
INSERT INTO public.system_config VALUES ('log_retention_mailbox_audit_days', '90', false, 'Number of days to retain mailbox_audit_log rows. NULL or 0 = keep forever.', '2026-06-18 16:02:01.95354+08', NULL);
INSERT INTO public.system_config VALUES ('log_retention_message_trace_days', '30', false, 'Number of days to retain message_trace rows. NULL or 0 = keep forever.', '2026-06-18 16:02:01.95354+08', NULL);
INSERT INTO public.system_config VALUES ('log_retention_webhook_delivery_days', '30', false, 'Number of days to retain webhook_deliveries rows. NULL or 0 = keep forever.', '2026-06-18 16:02:01.95354+08', NULL);
INSERT INTO public.system_config VALUES ('maintenance_window.day_of_week', '"sunday"', false, NULL, '2026-06-18 16:02:02.862373+08', NULL);
INSERT INTO public.system_config VALUES ('maintenance_window.end_time', '"05:00"', false, NULL, '2026-06-18 16:02:02.862373+08', NULL);
INSERT INTO public.system_config VALUES ('maintenance_window.idle_duration', '"10m"', false, NULL, '2026-06-18 16:02:02.862373+08', NULL);
INSERT INTO public.system_config VALUES ('maintenance_window.max_connections', '5', false, NULL, '2026-06-18 16:02:02.862373+08', NULL);
INSERT INTO public.system_config VALUES ('maintenance_window.max_wait', '"2h"', false, NULL, '2026-06-18 16:02:02.862373+08', NULL);
INSERT INTO public.system_config VALUES ('maintenance_window.mode', '"manual"', false, NULL, '2026-06-18 16:02:02.862373+08', NULL);
INSERT INTO public.system_config VALUES ('maintenance_window.start_time', '"03:00"', false, NULL, '2026-06-18 16:02:02.862373+08', NULL);
INSERT INTO public.system_config VALUES ('maintenance_window.timezone', '"UTC"', false, NULL, '2026-06-18 16:02:02.862373+08', NULL);
INSERT INTO public.system_config VALUES ('max_message_bytes', '"157286400"', false, 'Maximum inbound message size in bytes (150 MB)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('mfa_enforcement_mode', '"required"', false, 'MFA mode: optional | required', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('password_min_length', '"8"', false, 'Minimum password length', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('password_require_digit', '"true"', false, 'Require at least one digit', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('password_require_lowercase', '"true"', false, 'Require at least one lowercase letter', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('password_require_special', '"true"', false, 'Require at least one special character', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('password_require_uppercase', '"true"', false, 'Require at least one uppercase letter', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('setup_complete', '"false"', false, 'Set to true after first-run wizard completes', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('spam_purge_days', '30', false, 'Number of days before spam-tagged messages are permanently purged. 0 = disable.', '2026-06-18 16:02:02.514105+08', NULL);
INSERT INTO public.system_config VALUES ('spam_threshold', '"5.0"', false, 'Spam score above which messages go to Spam tag', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('telemetry_retention_days', '90', false, NULL, '2026-06-18 16:02:03.317625+08', NULL);
INSERT INTO public.system_config VALUES ('tls_auto_renew', '"true"', false, 'Auto-renew Let''s Encrypt certificates', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('tls_autocert_challenge', '"tls-alpn-01"', false, 'Challenge: tls-alpn-01 (port 443) | http-01 (port 80)', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('tls_autocert_domains', '""', false, 'Comma-separated Let''s Encrypt domains', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('tls_autocert_email', '""', false, 'Let''s Encrypt notification email', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('tls_mode', '"none"', false, 'TLS mode: none | static | autocert', '2026-06-18 16:02:01.588211+08', NULL);
INSERT INTO public.system_config VALUES ('trusted_proxy_ips', '["127.0.0.1", "::1"]', false, 'Comma-separated trusted proxy IPs/CIDRs for X-Forwarded-For', '2026-06-18 16:02:01.588211+08', NULL);

--
-- Data: device_policy (6 rows); Type: SEED; domain: authserver
--

INSERT INTO public.device_policy VALUES (1, NULL, 'copy_paste', 'allow', '2026-06-18 16:02:01.868571+08', '2026-06-18 16:02:01.868571+08', NULL);
INSERT INTO public.device_policy VALUES (2, NULL, 'screen_capture', 'allow', '2026-06-18 16:02:01.868571+08', '2026-06-18 16:02:01.868571+08', NULL);
INSERT INTO public.device_policy VALUES (3, NULL, 'encryption', 'required', '2026-06-18 16:02:01.868571+08', '2026-06-18 16:02:01.868571+08', NULL);
INSERT INTO public.device_policy VALUES (4, NULL, 'watermark', 'false', '2026-06-18 16:02:01.868571+08', '2026-06-18 16:02:01.868571+08', NULL);
INSERT INTO public.device_policy VALUES (5, NULL, 'notification_profile', 'push', '2026-06-18 16:02:01.868571+08', '2026-06-18 16:02:01.868571+08', NULL);
INSERT INTO public.device_policy VALUES (6, NULL, 'max_offline_days', '30', '2026-06-18 16:02:01.868571+08', '2026-06-18 16:02:01.868571+08', NULL);

SELECT pg_catalog.setval('public.device_policy_id_seq', 6, true);

--
-- ════════════════════════════════════════════════════════════════════════
-- BASELINE VERSION MARKER. This collapsed baseline is migration version 1.
-- MAX(version) is read by main.go / admin_system.go (expectedVersion=1).
-- Forward changes are new sequential migrations (V002, V003, …) on top.
-- ════════════════════════════════════════════════════════════════════════
--

INSERT INTO public.schema_migrations (version, applied_at) VALUES (1, now())
    ON CONFLICT (version) DO NOTHING;

--
-- PostgreSQL database dump complete
--

\unrestrict 4ytpLFRZJF1Y5RJjRbO84hlsoaBmGzxZSm9pK5Eh2W8nbstGCHNCMs55ZxNIUEk

