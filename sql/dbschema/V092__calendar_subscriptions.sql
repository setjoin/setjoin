-- V092__calendar_subscriptions.sql — webcal/ICS subscribe (WAVE-5 #10).
--
-- calendar_subscriptions ties a user to ONE dedicated read-only mirrored
-- calendar (calendar_id is UNIQUE — 1:1) fetched periodically from an external
-- ICS/webcal URL by the calendarsync worker (internal/calendarsync). The URL
-- is validated (shared/ssrf.ValidateURL) at subscribe time and re-validated on
-- every redirect hop at fetch time — a user-supplied URL is untrusted input,
-- unlike the admin-trusted migration IMAP/webhook posture.
--
-- etag/last_modified cache the feed's conditional-GET headers (If-None-Match /
-- If-Modified-Since) so an unchanged feed costs one 304, not a re-parse.
-- last_status/last_error surface the row's health in the CalendarApp UI
-- ("Updated Xh ago" / failure dot); 'partial' covers an N-of-M parse (some
-- components in the feed failed to parse but the rest still synced).
--
-- The calendar itself is a plain `calendars` row (no new column — the
-- existing `INSERT INTO calendars` path in internal/caldav/caldav.go is the
-- precedent for a raw, non-reducer calendar create); "read-only" is enforced
-- by the webmail UI hiding create/edit affordances on a subscribed calendar,
-- not by a DB constraint — same posture as most webcal implementations.
CREATE TABLE IF NOT EXISTS public.calendar_subscriptions (
    id                       BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id                  BIGINT      NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    calendar_id              BIGINT      NOT NULL REFERENCES public.calendars(id) ON DELETE CASCADE,
    url                      TEXT        NOT NULL,
    etag                     TEXT,
    last_modified            TEXT,
    refresh_interval_minutes INTEGER     NOT NULL DEFAULT 15,
    last_fetch_at            TIMESTAMPTZ,
    last_status              TEXT        NOT NULL DEFAULT 'pending',
    last_error               TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT calendar_subscriptions_calendar_id_key UNIQUE (calendar_id),
    CONSTRAINT calendar_subscriptions_last_status_check
      CHECK (last_status IN ('pending', 'ok', 'partial', 'error'))
);

-- The calendarsync worker's due-poll scan (WHERE last_fetch_at IS NULL OR
-- last_fetch_at < now() - refresh_interval).
CREATE INDEX IF NOT EXISTS calendar_subscriptions_due_idx
  ON public.calendar_subscriptions (last_fetch_at);

-- R4 backstop: per-user RLS (mirrors V091 user_image_allow exactly). App-layer
-- scoping in the handler (user_id from auth in every statement) is the primary
-- guard; this is the fail-closed defense-in-depth once the runtime DSN switches
-- to setjoin_app. Latent until then (superuser/owner bypasses FORCE), so it is
-- a no-op for the dev/test connection + pgTAP suite's default role.
ALTER TABLE public.calendar_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.calendar_subscriptions FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS calendar_subscriptions_self ON public.calendar_subscriptions;
CREATE POLICY calendar_subscriptions_self ON public.calendar_subscriptions
    FOR ALL
    TO public
    USING (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    )
    WITH CHECK (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    );

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (92, now())
  ON CONFLICT (version) DO NOTHING;
