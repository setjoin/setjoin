-- app_notify.sql: the single choke point for every pg_notify in the reducer
-- layer. Reducers MUST call PERFORM app_notify(channel, payload) instead of
-- pg_notify(channel, payload) directly. This centralizes the reactive push the
-- way notify_state_change centralized bump+push, and makes "did this reducer
-- push?" answerable in one place: a test-only side-channel tees the payload to a
-- log row so a pgTAP test (whose BEGIN…ROLLBACK can never observe a real LISTEN)
-- can assert the push fired, on the right channel, with the right payload —
-- WITHOUT changing any production behavior.
--
-- Why a wrapper, not "intercept pg_notify": pg_notify is a built-in C function
-- and cannot be shadowed or hooked. A SQL wrapper is the only way to tee.
--
-- PROD SAFETY — two independent guards make production structurally untouched:
--   1. The capture is gated on a SESSION GUC, default OFF. current_setting(
--      'app.capture_notify', TRUE) returns NULL when unset (the TRUE second arg
--      suppresses the "unrecognized parameter" error), so production — which
--      never sets it — takes the pg_notify-only branch.
--   2. _test_notify_log exists ONLY in tests/_fixtures.sql (loaded into
--      mailserver_test only) and is NEVER created by a migration, so it is ABSENT
--      in production. Even if the GUC were somehow set in prod, the INSERT target
--      does not exist there.
-- The real push is emitted UNCONDITIONALLY on BOTH capture branches — capture
-- is purely additive, so behavior is identical with or without the GUC. Tests
-- assert on _test_notify_log, never on a fired LISTEN.
--
-- NOTIFY DECOUPLE (V088, toggle feature.notify_decouple, seeded OFF): each
-- NOTIFY at commit takes a DB-wide AccessExclusiveLock on the notify queue.
-- With the toggle ON the "real push" becomes a durable notify_intents row
-- (written in the reducer txn); the notifyjobs Go worker drains batches on its
-- own short txns and emits the pg_notify there. Toggle OFF = byte-identical to
-- the direct pg_notify path (proof: tests/notify_decouple.pg). The capture tee
-- fires on both branches, so pgTAP push assertions are toggle-agnostic.
--
-- The plpgsql body late-binds the _test_notify_log table reference at call time,
-- so this reducer loads cleanly even though the fixture table is created AFTER
-- reducers by load-test-schema.sh (and never exists at all in prod).
--
-- p_channel — the pg_notify channel (e.g. 'tag:'||mailbox_id, 'calendar:'||…).
-- p_payload — the JSON payload text.
CREATE OR REPLACE FUNCTION app_notify(
  p_channel TEXT,
  p_payload TEXT
) RETURNS VOID AS $$
BEGIN
  IF coalesce(current_setting('app.capture_notify', TRUE), '') = 'on' THEN
    INSERT INTO _test_notify_log(channel, payload, seq)
      VALUES (p_channel, p_payload, nextval('_test_notify_log_seq'));
  END IF;

  -- ponytail: one PK lookup per push; cache in a GUC if it ever shows in p99.
  IF COALESCE((SELECT enabled FROM feature_toggles
                WHERE key = 'feature.notify_decouple'), FALSE) THEN
    INSERT INTO notify_intents (channel, payload) VALUES (p_channel, p_payload);
  ELSE
    PERFORM pg_notify(p_channel, p_payload);
  END IF;
END;
$$ LANGUAGE plpgsql;
