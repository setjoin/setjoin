-- V044: snapshot eligible + activation state in access-review items (D3).
-- Reviewers recertify standing eligibility — a dormant-eligible Super Admin must
-- appear in a campaign with their eligible/activated_until state visible.
ALTER TABLE public.access_review_items
  ADD COLUMN eligible        boolean NOT NULL DEFAULT false,
  ADD COLUMN activated_until timestamptz;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (44, now())
  ON CONFLICT (version) DO NOTHING;
