-- V145__guest_profiles.sql — Guest G2 profile and constrained-shell substrate.
-- History walls compare creation with membership join time. now() is the
-- transaction start, so stamp this immutable fact at the actual INSERT.
ALTER TABLE public.chat_messages
    ALTER COLUMN created_at SET DEFAULT clock_timestamp();

CREATE TABLE public.guest_profiles (
    id                  BIGSERIAL PRIMARY KEY,
    host_domain_id      BIGINT NOT NULL REFERENCES public.domains(id),
    name                TEXT NOT NULL,
    can_post            BOOLEAN NOT NULL DEFAULT true,
    history_from_join   BOOLEAN NOT NULL DEFAULT true,
    allow_download      BOOLEAN NOT NULL DEFAULT false,
    allow_meet_create   BOOLEAN NOT NULL DEFAULT false,
    allow_meet_host     BOOLEAN NOT NULL DEFAULT false,
    can_initiate_dm     BOOLEAN NOT NULL DEFAULT false,
    allow_native_shell  BOOLEAN NOT NULL DEFAULT true,
    default_expiry_days INT CHECK (default_expiry_days IS NULL OR default_expiry_days > 0),
    apps                TEXT[] NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (apps <@ ARRAY['chat','drive','meet']::text[])
);
CREATE UNIQUE INDEX guest_profiles_domain_name_unique
    ON public.guest_profiles(host_domain_id, lower(name));

ALTER TABLE public.guest_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.guest_profiles FORCE ROW LEVEL SECURITY;

ALTER TABLE public.guest_accounts
  ADD CONSTRAINT guest_accounts_profile_fk
  FOREIGN KEY (profile_id) REFERENCES public.guest_profiles(id) ON DELETE RESTRICT;

ALTER TABLE public.chat_channel_members
  ADD COLUMN can_post boolean,
  ADD COLUMN history_floor_seq bigint;

ALTER TABLE public.user_app_entitlements
  DROP CONSTRAINT user_app_entitlements_app_check;
ALTER TABLE public.user_app_entitlements
  ADD CONSTRAINT user_app_entitlements_app_check
  CHECK (app = ANY (ARRAY['mail','calendar','contacts','tasks','chat','drive','meet']::text[]));

INSERT INTO public.schema_migrations(version, applied_at)
VALUES (145, now()) ON CONFLICT (version) DO NOTHING;
