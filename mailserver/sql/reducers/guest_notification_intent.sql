-- guest_notification_intent.sql — Guest Accounts G1 digest outbox enqueue.
-- The worker drain is unconditional; only new enqueue is feature-gated.

CREATE OR REPLACE FUNCTION guest_notification_intent_enqueue(
    p_user_id bigint,
    p_kind    text,
    p_ref     text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    IF NOT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key = 'feature.guest_accounts'), false)
       OR NOT is_guest_account(p_user_id) THEN
        RETURN;
    END IF;
    INSERT INTO guest_notification_intents (user_id, kind, ref)
    VALUES (p_user_id, p_kind, p_ref);
END;
$$;
SELECT apply_worker_ownership('guest_notification_intent_enqueue(bigint,text,text)'::regprocedure);
