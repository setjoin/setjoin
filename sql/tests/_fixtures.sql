-- ──────────────────────────────────────────────────────────────────────────
-- _fixtures.sql — pgTAP fixture helpers (TEST DATABASE ONLY, not a reducer)
--
-- ADR-003 (docs/adr/ARCH-003-account-scope-currency.md): the account-slot
-- argument every reducer receives is ALWAYS a mailbox_id (`parseAccountID`
-- resolves a JMAP accountId to the caller's PRIMARY mailbox id). `users.id` and
-- `mailboxes.id` are independent BIGSERIAL sequences and `mailboxes.user_id` is
-- nullable (shared/resource mailboxes), so a `user_id = p_mailbox_id` predicate
-- matches ZERO rows in production — the feature fails silently. pgTAP fixtures
-- that used COINCIDENT ids (mailbox.id == user_id) made that buggy predicate
-- pass by accident and masked the bug class.
--
-- These helpers make divergent ids the default *by construction*: user ids come
-- from a 70000+ sequence, mailbox ids from a DISJOINT 90000+ sequence, so
-- user_id != mailbox_id ALWAYS. A reducer that confuses the two now matches the
-- wrong row (or zero rows) and fails the suite — the regression guard for the
-- entire bug class.
--
-- Loaded into mailserver_test by scripts/load-test-schema.sh (after reducers).
-- Not a reducer; never shipped in a migration.
-- ──────────────────────────────────────────────────────────────────────────

-- Disjoint id sources. user ids ∈ [70000, …); mailbox ids ∈ [90000, …).
-- Sequence advances survive test ROLLBACK (harmless — they only ever climb), so
-- repeated calls across a session never collide.
CREATE SEQUENCE IF NOT EXISTS mk_account_user_seq START 70000;
CREATE SEQUENCE IF NOT EXISTS mk_account_mb_seq   START 90000;

-- mk_account(p_label) → mailbox_id
--   Creates a user (id from the 70000+ source) and that user's PRIMARY mailbox
--   (id from the DISJOINT 90000+ source) in a fresh test domain, and returns the
--   MAILBOX id — the value a reducer's account slot expects. user_id != mailbox_id
--   is guaranteed by the disjoint sources.
CREATE OR REPLACE FUNCTION mk_account(p_label TEXT)
RETURNS BIGINT
LANGUAGE plpgsql AS $$
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

-- mk_shared_mailbox(p_label) → mailbox_id
--   Creates a SHARED mailbox: user_id IS NULL (the case the account_scope() seam
--   must return NULL for, and the case a `user_id = p_mailbox_id` predicate breaks
--   on). Returns the mailbox id. No owning user row; pair with mailbox_delegates
--   in the test if a delegate is needed.
CREATE OR REPLACE FUNCTION mk_shared_mailbox(p_label TEXT)
RETURNS BIGINT
LANGUAGE plpgsql AS $$
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

-- ──────────────────────────────────────────────────────────────────────────
-- notify-capture side-channel (TEST DATABASE ONLY — never in a migration)
--
-- app_notify(channel, payload) (reducers/app_notify.sql) is the single choke
-- point for every pg_notify in the reducer layer. pgTAP wraps each test in
-- BEGIN…ROLLBACK, so a LISTEN issued inside a test can NEVER observe a real
-- notification (the emitting txn rolls back, never commits). To assert a push
-- fired, app_notify TEES the payload into _test_notify_log — but ONLY when the
-- session GUC app.capture_notify = 'on'. Production never sets the GUC AND this
-- table is absent in prod (it lives only here), so the capture is doubly
-- prod-safe. The real pg_notify is emitted unconditionally regardless.
--
-- A test does:  SET LOCAL app.capture_notify = 'on';  (auto-resets at txn end)
-- then runs the reducer, then asserts on notify_count / last_notify_event /
-- notified_on. SET LOCAL means no cross-pgTAP-file leakage.
-- ──────────────────────────────────────────────────────────────────────────

-- A dedicated sequence (not a column SERIAL) so app_notify can call nextval()
-- by a stable name independent of how the table was declared.
CREATE SEQUENCE IF NOT EXISTS _test_notify_log_seq;

CREATE TABLE IF NOT EXISTS _test_notify_log (
  channel TEXT   NOT NULL,
  payload TEXT   NOT NULL,
  seq     BIGINT NOT NULL DEFAULT nextval('_test_notify_log_seq')
);

-- notified_on(channel) → SETOF payload — every payload captured on a channel
-- this txn, in fire order.
CREATE OR REPLACE FUNCTION notified_on(p_channel TEXT)
RETURNS SETOF TEXT
LANGUAGE sql STABLE AS $$
  SELECT payload FROM _test_notify_log WHERE channel = p_channel ORDER BY seq;
$$;

-- last_notify_event(channel) → TEXT — payload->>'event' of the most recent
-- capture on the channel (NULL if none / no 'event' key).
CREATE OR REPLACE FUNCTION last_notify_event(p_channel TEXT)
RETURNS TEXT
LANGUAGE sql STABLE AS $$
  SELECT (payload::jsonb)->>'event'
  FROM _test_notify_log WHERE channel = p_channel
  ORDER BY seq DESC LIMIT 1;
$$;

-- notify_count(channel) → INT — how many captures on the channel this txn
-- (catches double-push / no-push).
CREATE OR REPLACE FUNCTION notify_count(p_channel TEXT)
RETURNS INT
LANGUAGE sql STABLE AS $$
  SELECT count(*)::INT FROM _test_notify_log WHERE channel = p_channel;
$$;

-- last_notify_payload(channel) → TEXT — the RAW payload text of the most recent
-- capture on the channel (NULL if none). Distinct from last_notify_event (which
-- extracts payload->>'event'): a test can cast this to JSONB and assert the
-- ABSENCE of keys (e.g. no 'body'/'preview' on an encrypted delivery push).
CREATE OR REPLACE FUNCTION last_notify_payload(p_channel TEXT)
RETURNS TEXT
LANGUAGE sql STABLE AS $$
  SELECT payload FROM _test_notify_log WHERE channel = p_channel
  ORDER BY seq DESC LIMIT 1;
$$;

-- ──────────────────────────────────────────────────────────────────────────
-- state-bump ⇒ push guard (TEST DATABASE ONLY — never in a migration)
--
-- INVARIANT (today convention-only): a MUTATING reducer that advances a
-- mailbox's JMAP state token (any mailboxes.jmap_*_state column) MUST, in the
-- SAME txn, also emit a pg_notify on that mailbox's canonical reactive channel
-- ('tag:'||mailbox_id) — otherwise a client that holds the old state token
-- never learns to re-fetch and silently stales. The whole reducer layer routes
-- pushes through app_notify (single choke point) and bumps through
-- notify_state_change / bump_*_state, so the bump and the push live together.
-- These helpers turn that convention into a TEST-TIME assertion.
--
-- Shape of use in a pgTAP test (BEGIN…ROLLBACK):
--     SET LOCAL app.capture_notify = 'on';            -- arm the tee
--     -- snapshot the mailbox's state tokens BEFORE the mutation:
--     CREATE TEMP TABLE _g AS SELECT notify_guard_snapshot(<mailbox_id>) AS s;
--     SELECT some_mutating_reducer(...);              -- bumps + pushes
--     SELECT ok( reducer_pushed_if_bumped(<mailbox_id>, (SELECT s FROM _g)),
--                'state bump pushed on tag:{mailbox}' );
--
-- The boolean predicate is the testable core; the test wraps it in pgTAP's ok()
-- (so this file, loaded by plain psql WITHOUT the pgTAP extension, never needs
-- ok() at definition time). assert_reducer_pushed() is a SETOF TEXT convenience
-- that emits the ok() line itself for tests that prefer a one-liner.
--
-- PROD-SAFE for the same two reasons app_notify's capture is: these functions +
-- _test_notify_log exist ONLY in tests/_fixtures.sql (never in a migration), and
-- they only ever READ — they change no reducer and no production behavior.
--
-- LIMITATION (by design): the guard is per-(mailbox channel, txn), not
-- per-mutation. It asks "after this snapshot, did the state climb AND was there
-- ≥1 push on tag:{mailbox} in this txn?" — so if a test chains several mutations
-- against the SAME mailbox in one txn, an earlier push satisfies a later bump.
-- Use it the way the demos do: arm capture, snapshot immediately before the ONE
-- mutation under test, on a clean channel window (a fresh mk_account() for a
-- negative case). That is exactly enough to catch a reducer that bumps without
-- ever pushing — the silent-stale bug this guards.
-- ──────────────────────────────────────────────────────────────────────────

-- notify_guard_snapshot(mailbox_id) → JSONB — { "<jmap_*_state column>": value }
-- for EVERY jmap_*_state column on mailboxes, captured now. Built dynamically off
-- information_schema so a newly-added state domain is covered with no edit here.
-- Returns '{}' if the mailbox row does not exist (the assert then sees no bump).
CREATE OR REPLACE FUNCTION notify_guard_snapshot(p_mailbox_id BIGINT)
RETURNS JSONB
LANGUAGE plpgsql STABLE AS $$
DECLARE
  v_cols TEXT;
  v_json JSONB;
BEGIN
  SELECT string_agg(
           format('%L, %I', column_name, column_name), ', '
           ORDER BY column_name)
    INTO v_cols
  FROM information_schema.columns
  WHERE table_name = 'mailboxes' AND column_name LIKE 'jmap\_%\_state';

  IF v_cols IS NULL THEN
    RETURN '{}'::JSONB;   -- no state columns at all (shouldn't happen)
  END IF;

  EXECUTE format(
    'SELECT jsonb_build_object(%s) FROM mailboxes WHERE id = $1', v_cols)
  INTO v_json USING p_mailbox_id;

  RETURN COALESCE(v_json, '{}'::JSONB);   -- '{}' when the mailbox row is absent
END;
$$;

-- reducer_pushed_if_bumped(mailbox_id, state_before) → BOOLEAN — the guard.
-- TRUE  when EITHER no jmap_*_state column advanced versus the snapshot (nothing
--       to push — vacuously satisfied) OR at least one advanced AND ≥1 notify was
--       captured on 'tag:'||mailbox_id this txn.
-- FALSE when a state column advanced but NO push was captured on that channel —
--       i.e. the reducer bumped state without notifying (the silent-stale bug).
-- Requires app.capture_notify = 'on' for the txn (else the tee logs nothing and a
-- genuine push reads as absent — caller's responsibility to arm it; see header).
CREATE OR REPLACE FUNCTION reducer_pushed_if_bumped(
  p_mailbox_id   BIGINT,
  p_state_before JSONB
)
RETURNS BOOLEAN
LANGUAGE plpgsql STABLE AS $$
DECLARE
  v_after   JSONB := notify_guard_snapshot(p_mailbox_id);
  v_bumped  BOOLEAN := FALSE;
  v_key     TEXT;
BEGIN
  -- Did ANY state column climb? (after > before, per column; missing/equal = no.)
  FOR v_key IN SELECT jsonb_object_keys(v_after) LOOP
    IF (v_after->>v_key)::BIGINT
         > COALESCE((p_state_before->>v_key)::BIGINT, (v_after->>v_key)::BIGINT)
    THEN
      v_bumped := TRUE;
      EXIT;
    END IF;
  END LOOP;

  IF NOT v_bumped THEN
    RETURN TRUE;   -- no bump this txn → invariant vacuously holds
  END IF;

  -- A state token advanced → a push on the mailbox's tag: channel is REQUIRED.
  RETURN notify_count('tag:' || p_mailbox_id) > 0;
END;
$$;

-- assert_reducer_pushed(mailbox_id, state_before [, description]) → SETOF TEXT —
-- one-line pgTAP convenience: emits the ok() TAP line for the guard predicate.
-- Late-binds ok() in the plpgsql body, so this loads under plain psql even though
-- ok() (pgTAP) is absent at load time; it is in scope when a .pg test calls it.
CREATE OR REPLACE FUNCTION assert_reducer_pushed(
  p_mailbox_id   BIGINT,
  p_state_before JSONB,
  p_description  TEXT DEFAULT NULL
)
RETURNS SETOF TEXT
LANGUAGE plpgsql AS $$
BEGIN
  RETURN QUERY SELECT ok(
    reducer_pushed_if_bumped(p_mailbox_id, p_state_before),
    COALESCE(p_description,
             'state bump on mailbox ' || p_mailbox_id ||
             ' pushed on tag:' || p_mailbox_id));
END;
$$;

-- mk_offline_device(p_mailbox_id, p_state) → user_devices.id
--   Seeds a registered NATIVE user_devices row for offline governance tests.
--   p_mailbox_id resolves the owning user; p_state sets offline_approval.
--   Platform is 'desktop' (a native platform; 'web' rows never register for
--   offline sync and would be filtered out of the approval queue).
--   Idempotent via the (user_id, fingerprint_hash) partial unique index.
CREATE OR REPLACE FUNCTION mk_offline_device(p_mailbox_id BIGINT, p_state TEXT)
RETURNS BIGINT AS $$
DECLARE v_user_id BIGINT; v_id BIGINT; v_dev BIGINT;
BEGIN
  SELECT user_id INTO v_user_id FROM mailboxes WHERE id = p_mailbox_id;
  -- Link the canonical devices row (like offline_device_register): device_id is
  -- the id the client self-identifies by and the offline.wipe push targets.
  INSERT INTO devices (user_id, fingerprint, hmac_secret, platform)
  VALUES (v_user_id, 'fp' || p_mailbox_id, encode(gen_random_bytes(32),'hex'), 'desktop')
  ON CONFLICT DO NOTHING;
  SELECT id INTO v_dev FROM devices
    WHERE user_id = v_user_id AND fingerprint = 'fp' || p_mailbox_id;
  INSERT INTO user_devices (user_id, device_id, device_name, platform, fingerprint_hash,
                            offline_approval, offline_opt_in, last_seen_at)
  VALUES (v_user_id, v_dev, 'test-native', 'desktop',
          sha256(('fp' || p_mailbox_id)::bytea),
          p_state, true, now())
  ON CONFLICT (user_id, fingerprint_hash) WHERE fingerprint_hash IS NOT NULL
  DO UPDATE SET offline_approval = EXCLUDED.offline_approval, device_id = EXCLUDED.device_id
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$ LANGUAGE plpgsql;

-- mk_auth_user(email) → users.id. A bare auth-test user satisfying the current
-- users NOT-NULL set (username, domain_id, email, display_name). The authserver
-- pgTAP files predate the username/domain_id columns and used the obsolete
-- (email, password_hash, display_name) shape; this is their fixture. username is
-- UNIQUE per (username, domain_id) so derive it from a sequence.
CREATE SEQUENCE IF NOT EXISTS mk_auth_user_seq;
CREATE OR REPLACE FUNCTION mk_auth_user(
  p_email         TEXT,
  p_password_hash TEXT DEFAULT 'x',
  p_display_name  TEXT DEFAULT 'Test User'
) RETURNS BIGINT AS $$
DECLARE
  v_domain_id BIGINT;
  v_uid       BIGINT;
  v_n         BIGINT := nextval('mk_auth_user_seq');
BEGIN
  INSERT INTO domains (name, is_local) VALUES ('authtest.local', TRUE)
    ON CONFLICT (name) DO NOTHING;
  SELECT id INTO v_domain_id FROM domains WHERE name = 'authtest.local';
  INSERT INTO users (username, domain_id, email, display_name, password_hash)
    VALUES ('authuser-' || v_n, v_domain_id, p_email, p_display_name, p_password_hash)
    RETURNING id INTO v_uid;
  RETURN v_uid;
END;
$$ LANGUAGE plpgsql;

-- Guest G1 tracer fixture: structurally absent from production because this
-- file is loaded only by scripts/load-test-schema.sh after reducer loading.
-- Task 9 must call it only against mailserver_test; no caller-settable GUC is
-- an authorization boundary and no pooled SET LOCAL is required.
CREATE OR REPLACE FUNCTION guest_invite_accept_test_helper(
  p_guest_user_id BIGINT,
  p_raw_token     TEXT
) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF current_database() <> 'mailserver_test' THEN
    RAISE EXCEPTION 'guest_invite_accept_test_helper: test database required'
      USING ERRCODE='BZ002';
  END IF;
  UPDATE guest_invites
     SET token_hash = encode(sha256(p_raw_token::bytea), 'hex')
   WHERE guest_user_id = p_guest_user_id AND used_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'guest_invite_accept_test_helper: no pending invite for user %',
      p_guest_user_id USING ERRCODE='BZ002';
  END IF;
  RETURN p_raw_token;
END;
$$;

-- Ensure the PREVIOUS- and CURRENT-month partitions exist for the occurred_at
-- range-partitioned
-- audit tables. The collapsed baseline ships only static partitions (generated
-- when 'now' was an earlier month) and pre-creates +1 for some tables but NOT
-- audit_log / auth_attempts — so a fresh load in a later month has no partition
-- for now(), and every test inserting an audit/auth row with now() fails with
-- "no partition of relation ... found for row". Idempotent; covers all four so it
-- stays correct as wall-clock advances past whichever table's last static partition.
-- The previous month is also required because rolling-window tests legitimately
-- insert now()-relative rows during the first hours/days of a new month.
DO $$
DECLARE
  t    TEXT;
  v_offset INTEGER;
  v_month TIMESTAMPTZ;
  v_m  TEXT;
  v_lo TEXT;
  v_hi TEXT;
BEGIN
  FOR v_offset IN -1..0 LOOP
    v_month := date_trunc('month', now()) + make_interval(months => v_offset);
    v_m := to_char(v_month, 'YYYY_MM');
    v_lo := to_char(v_month, 'YYYY-MM-DD');
    v_hi := to_char(v_month + INTERVAL '1 month', 'YYYY-MM-DD');
    FOREACH t IN ARRAY ARRAY['audit_log', 'auth_attempts', 'login_events', 'mailbox_audit_log'] LOOP
      EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                     t || '_' || v_m, t, v_lo, v_hi);
    END LOOP;
  END LOOP;
END $$;
