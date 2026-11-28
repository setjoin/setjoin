-- V091__user_image_allow.sql — per-sender remote-image trust (WAVE-5 #5).
--
-- user_image_allow remembers the senders a user chose "Always load images from
-- this sender" for. EXACT-ADDRESS grain, not domain grain — domain grain would
-- trust every local-part at big shared providers (gmail.com, qq.com), so one
-- newsletter opt-in would unblock every sender at that provider. (Decision
-- recorded in TODOS.md's WAVE-5 mail-read note.)
--
-- The allowlist ungates the remote-image FETCH in the webmail only — the HTML
-- body ALWAYS still passes DOMPurify sanitize (asserted by sanitize.test.ts).
-- Table + policy shape copies V078 focus_sender_overrides exactly.

CREATE TABLE IF NOT EXISTS public.user_image_allow (
    user_id    BIGINT      NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    sender     TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, sender)
);

-- R4 backstop: per-user RLS (mirrors V078 focus_sender_overrides). App-layer
-- scoping in the handler (user_id from auth in every statement) is the primary
-- guard; this is the fail-closed defense-in-depth once the runtime DSN switches
-- to setjoin_app. Latent until then (superuser/owner bypasses FORCE), so it is
-- a no-op for the dev/test connection + pgTAP suite's default role.
ALTER TABLE public.user_image_allow ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_image_allow FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS user_image_allow_self ON public.user_image_allow;
CREATE POLICY user_image_allow_self ON public.user_image_allow
    FOR ALL
    TO public
    USING (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    )
    WITH CHECK (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    );

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (91, now())
  ON CONFLICT (version) DO NOTHING;
