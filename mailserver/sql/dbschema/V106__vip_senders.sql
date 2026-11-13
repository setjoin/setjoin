-- V106__vip_senders.sql — VIP senders (QoL #10a: VIP/mute in-app, no push dependency).
--
-- H3 (binding, per plan review): does NOT create a new notification-prefs table —
-- user_notification_prefs already exists (V001) and mute-thread already exists as
-- the Muted tag consumed by deliver(). This migration adds ONLY the one missing
-- primitive: a per-user VIP-sender list. sender_email is stored lowercased so
-- lookups/uniqueness are case-insensitive without a functional index surprise at
-- query time; the reducer lower()s on write, the PK lower()s again as a backstop
-- against a future caller that inserts directly.
CREATE TABLE public.vip_senders (
    user_id      BIGINT      NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    sender_email TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, sender_email),
    CONSTRAINT vip_senders_email_lower_chk CHECK (sender_email = lower(sender_email))
);

CREATE INDEX vip_senders_user_idx ON public.vip_senders (user_id);

-- R4 backstop: per-user RLS, copying the V091/V092 self-policy shape exactly.
ALTER TABLE public.vip_senders ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vip_senders FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS vip_senders_self ON public.vip_senders;
CREATE POLICY vip_senders_self ON public.vip_senders
    FOR ALL
    TO public
    USING (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    )
    WITH CHECK (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    );

INSERT INTO public.schema_migrations (version, applied_at) VALUES (106, now())
    ON CONFLICT (version) DO NOTHING;
