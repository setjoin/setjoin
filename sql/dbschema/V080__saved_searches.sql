-- ════════════════════════════════════════════════════════════════════════
-- V080__saved_searches.sql — forward migration: saved-search folders.
--
-- A saved search is a named per-mailbox persisted query a user can re-run
-- (mirrors the quick_steps per-mailbox user-object rail). The RAW query string
-- is stored VERBATIM — the webmail re-parses it at click time; we never store a
-- resolved filter. CRUD lives in reducers/saved_searches.sql.
--
-- RLS: quick_steps (the shape precedent) is app-layer-isolated only, but here we
-- ALSO lay a native-RLS backstop matching the messages/message_tags policy shape
-- (V003/V004) — ENABLE+FORCE + a per-mailbox policy keyed on the
-- transaction-scoped app.current_mailbox_id GUC the gateway's CallScoped sets per
-- request. It is INERT for the superuser/owner identity (owner/superuser bypass),
-- so it is a no-op until the prod DSN switches to setjoin_app — the same latent
-- posture as V004 (docs/standards/DATABASE_SECURITY.md → Deploy gate). The
-- InitPlan `(SELECT NULLIF(current_setting(…, true), '')::bigint)` form is
-- fail-closed: an unset/empty GUC → NULL → no row qualifies.
-- ════════════════════════════════════════════════════════════════════════

CREATE TABLE public.saved_searches (
    id         BIGSERIAL PRIMARY KEY,
    mailbox_id BIGINT NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    query      TEXT NOT NULL,
    position   INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX saved_searches_mailbox_idx ON public.saved_searches (mailbox_id, "position");

-- ── Native-RLS backstop (per-mailbox), messages/message_tags policy shape ──
ALTER TABLE public.saved_searches ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.saved_searches FORCE  ROW LEVEL SECURITY;

CREATE POLICY saved_searches_tenant_isolation ON public.saved_searches
  FOR ALL
  TO public
  USING      (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint))
  WITH CHECK (mailbox_id = (SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (80, now())
    ON CONFLICT (version) DO NOTHING;
