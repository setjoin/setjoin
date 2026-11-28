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
    -- Serialize per-guest intent insert + WorkQueue coalescing against the
    -- consumer's post-drain check/complete transaction so a coalesced wakeup
    -- can never be lost between drain and complete (#549).
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('guest-digest:' || p_user_id::text, 0)
    );
    INSERT INTO guest_notification_intents (user_id, kind, ref)
    VALUES (p_user_id, p_kind, p_ref);
    -- Wave 2.2 (#549): coalesce per-guest digest wakeup onto durable WorkQueue
    -- while keeping guest_notification_intents populated during drain-then-retire.
    PERFORM public.work_enqueue(
        'guest.digest_notify',
        jsonb_build_object('user_id', p_user_id),
        'guest.digest:' || p_user_id::text,
        now(),
        0::smallint,
        5
    );
END;
$$;
SELECT apply_worker_ownership('guest_notification_intent_enqueue(bigint,text,text)'::regprocedure);
