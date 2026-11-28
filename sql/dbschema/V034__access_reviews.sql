-- V031__access_reviews.sql
-- Access reviews (recertification): campaign + per-assignment snapshot items.
-- Admin-data tables (admin-gated routes, no per-user RLS) — same model as
-- admin_role_assignments. See docs/superpowers/specs/2026-06-23-access-reviews-design.md.

CREATE TABLE public.access_review_campaigns (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name         text NOT NULL,
    status       text NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
    -- scope tag: actor's domain scope at start (NULL ⇒ GLOBAL admin, snapshots org-wide).
    domain_scope bigint REFERENCES public.domains(id),
    created_by   bigint NOT NULL REFERENCES public.users(id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    closed_by    bigint REFERENCES public.users(id),
    closed_at    timestamptz
);

CREATE TABLE public.access_review_items (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id     bigint NOT NULL REFERENCES public.access_review_campaigns(id) ON DELETE CASCADE,
    -- live link (NULL once the assignment is deleted, here or elsewhere):
    assignment_id   bigint REFERENCES public.admin_role_assignments(id) ON DELETE SET NULL,
    -- point-in-time snapshot — NO FK on user_id/role_group_id BY DESIGN: an immutable
    -- historical record that must survive the referent's deletion. Do not add FKs here.
    user_id         bigint NOT NULL,
    role_group_id   bigint NOT NULL,
    domain_override bigint,
    granted_by      bigint,            -- snapshot; NULL ⇒ is_sso
    granted_at      timestamptz,
    is_sso          boolean NOT NULL,  -- granted_by IS NULL at snapshot time
    decision        text NOT NULL DEFAULT 'undecided' CHECK (decision IN ('undecided','keep','revoke')),
    decided_by      bigint REFERENCES public.users(id),
    decided_at      timestamptz,
    -- set by close ONLY when the revoke was actually applied (DELETE matched). A
    -- decision='revoke' item with applied_at IS NULL after close ⇒ revoke not applied
    -- (became SSO-managed, moved out of scope, or already deleted elsewhere).
    applied_at      timestamptz,
    note            text
);
CREATE INDEX access_review_items_campaign_idx ON public.access_review_items(campaign_id);

-- ── Schema migration record ──────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (34, now())
  ON CONFLICT (version) DO NOTHING;
