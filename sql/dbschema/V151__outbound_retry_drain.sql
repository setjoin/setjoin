-- V151__outbound_retry_drain.sql — repair the legacy outbound retry cron.
--
-- outbound_queue.next_attempt_at is NOT NULL. The baseline function attempted
-- to re-pend due rows by assigning NULL, so every cron invocation that found a
-- due deferred row failed with SQLSTATE 23502. The SMTP worker already selects
-- due pending and deferred rows directly; preserve that authority and make the
-- cron transition immediately eligible without changing attempt_count/backoff.

CREATE OR REPLACE FUNCTION public.drain_outbound_queue(
    p_retry_only boolean DEFAULT false
) RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE public.outbound_queue
       SET status = 'pending',
           next_attempt_at = now()
     WHERE status = 'deferred'
       AND next_attempt_at <= now()
       AND attempt_count < 20;
END;
$$;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (151, now())
    ON CONFLICT (version) DO NOTHING;
