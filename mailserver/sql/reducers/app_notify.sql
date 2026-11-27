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
-- NOTIFY DECOUPLE (Wave 2.1, #548): feature.notify_decouple is retired here.
-- Every app_notify call unconditionally writes a durable notify_intents row
-- inside the reducer transaction (drained in batches by NotifyIntentDrain on
-- its own short transactions — zero DB-wide NOTIFY queue AccessExclusiveLock
-- on user write commits). The capture tee still fires under app.capture_notify
-- so pgTAP push assertions stay unchanged.
--
-- The plpgsql body late-binds the _test_notify_log table reference at call time,
-- so this reducer loads cleanly even though the fixture table is created AFTER
-- reducers by load-test-schema.sh (and never exists at all in prod).
--
-- Narrow worker-owned SECURITY DEFINER enqueue seam for public.notify_intents
-- (Wave 2.1, #548): notify_intents is FORCE-RLS deny-all to setjoin_app so an
-- app session can never read cross-tenant session_revoke/identity_link intents,
-- while app_notify / emit_wakeup_bell still enqueue validated rows through here.
-- Rejects invalid channels or payloads > 7900 bytes so no malformed row can
-- poison pg_notify and wedge NotifyIntentDrain.
CREATE OR REPLACE FUNCTION app_notify_enqueue_intent(
  p_channel TEXT,
  p_payload TEXT
) RETURNS VOID
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_payload TEXT := COALESCE(p_payload, '');
BEGIN
  IF p_channel IS NULL OR octet_length(p_channel) = 0 OR octet_length(p_channel) > 63
     OR p_channel !~ '^[a-zA-Z0-9_.:-]+$' THEN
    RAISE EXCEPTION 'app_notify_enqueue_intent: invalid channel %', p_channel
      USING ERRCODE = 'BZ040',
            HINT = '{"type":"invalid_notify_channel"}';
  END IF;
  IF octet_length(v_payload) > 7900 THEN
    RAISE EXCEPTION 'app_notify_enqueue_intent: payload exceeds 7900 bytes'
      USING ERRCODE = 'BZ040',
            HINT = '{"type":"notify_payload_too_large"}';
  END IF;

  INSERT INTO public.notify_intents (channel, payload)
  VALUES (p_channel, v_payload);
END;
$$;

DO $$
DECLARE
  v_granted_create BOOLEAN := FALSE;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    IF NOT has_schema_privilege('setjoin_worker', 'public', 'CREATE') THEN
      GRANT CREATE ON SCHEMA public TO setjoin_worker;
      v_granted_create := TRUE;
    END IF;
    ALTER FUNCTION public.app_notify_enqueue_intent(text, text) OWNER TO setjoin_worker;
    IF v_granted_create THEN
      REVOKE CREATE ON SCHEMA public FROM setjoin_worker;
    END IF;
  END IF;
  REVOKE ALL ON FUNCTION public.app_notify_enqueue_intent(text, text) FROM PUBLIC;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
    GRANT EXECUTE ON FUNCTION public.app_notify_enqueue_intent(text, text) TO setjoin_app;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
    GRANT EXECUTE ON FUNCTION public.app_notify_enqueue_intent(text, text) TO setjoin_worker;
  END IF;
END $$;

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

  PERFORM public.app_notify_enqueue_intent(p_channel, p_payload);
END;
$$ LANGUAGE plpgsql;
