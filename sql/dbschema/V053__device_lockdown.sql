-- ════════════════════════════════════════════════════════════════════════
-- V053__device_lockdown.sql — CA-2 device lockdown (终端安全).
-- Extends the CANONICAL devices row (CA-F §F3) with an enrollment lifecycle,
-- adds a lifecycle audit trail, a per-user IMAP kill switch, and the
-- default-OFF feature.device_lockdown toggle. No new policy table: lockdown
-- rules are rows in conditional_access_policies (JSONB).
-- ════════════════════════════════════════════════════════════════════════

-- ── devices: enrollment lifecycle on the canonical credential row ──
ALTER TABLE public.devices
  ADD COLUMN IF NOT EXISTS enroll_state text NOT NULL DEFAULT 'unenrolled'
    CHECK (enroll_state IN ('unenrolled','enrolled','approved','revoked')),
  ADD COLUMN IF NOT EXISTS enrolled_by   bigint REFERENCES public.users(id),
  ADD COLUMN IF NOT EXISTS approved_by   bigint REFERENCES public.users(id),
  ADD COLUMN IF NOT EXISTS approved_at   timestamptz,
  ADD COLUMN IF NOT EXISTS credential_kind text NOT NULL DEFAULT 'hmac'
    CHECK (credential_kind IN ('hmac'));
  -- 'webauthn_platform'/'asym_pubkey' added by the deferred upgrade (spec §15).

CREATE INDEX IF NOT EXISTS devices_enroll_state_idx
  ON public.devices(user_id, enroll_state) WHERE revoked_at IS NULL;

-- ── device_enroll_events: lifecycle audit trail (mirrors device_events) ──
CREATE TABLE IF NOT EXISTS public.device_enroll_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  device_id bigint NOT NULL REFERENCES public.devices(id) ON DELETE CASCADE,
  actor_user_id bigint,            -- admin (NULL for system/auto)
  from_state text,
  to_state   text,
  reason     text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS device_enroll_events_device_idx
  ON public.device_enroll_events(device_id, created_at DESC);

ALTER TABLE public.device_enroll_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_enroll_events FORCE ROW LEVEL SECURITY;
-- A user may read only events for their own devices; admin reads use the
-- worker/admin (BYPASSRLS) pool.
DROP POLICY IF EXISTS dee_self ON public.device_enroll_events;
CREATE POLICY dee_self ON public.device_enroll_events
  USING (device_id IN (
    SELECT id FROM public.devices
    WHERE user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)));

-- ── user_imap_settings: per-user legacy-IMAP kill switch ──
ALTER TABLE public.user_imap_settings
  ADD COLUMN IF NOT EXISTS imap_enabled boolean NOT NULL DEFAULT true;
-- 'pop_enabled' DEFERRED (spec §15): setjoin has no POP listener today.

-- ── feature.device_lockdown toggle (default OFF) ──
-- ponytail: fail-closed — toggle defaults FALSE, device gating requires explicit admin enable.
INSERT INTO public.feature_toggles (key, enabled)
VALUES ('feature.device_lockdown', FALSE)
ON CONFLICT (key) DO NOTHING;

-- ── ca_templates: device-lockdown starter template ──────────────────────────
-- "Device lockdown (native shells only)": conditions match legacy auth clients
-- (IMAP/SMTP/ActiveSync → umbrella "legacy"); action require_compliant_device
-- blocks any device that is not enrolled + approved. Born report_only via
-- ca_template_instantiate (never enforcing at seed time).
-- ponytail: single template row — require_compliant_device is the blocking
-- action; the client_type:legacy condition scopes it to IMAP/SMTP paths only.
INSERT INTO public.ca_templates
    (slug, name, description, scope_type, scope_target, conditions, actions, suggested_priority)
VALUES (
    'device-lockdown',
    'Device lockdown (native shells only)',
    'Block IMAP/SMTP access from devices that are not enrolled and approved. Requires a native shell with a valid device proof. Born report-only; promote to enforcing after validating impact.',
    'global',
    '',
    '{"client_type":"legacy"}'::jsonb,
    '{"require_compliant_device":true,"reason":"Only enrolled, approved native-shell devices may use IMAP/SMTP under device lockdown"}'::jsonb,
    40
) ON CONFLICT (slug) DO NOTHING;

-- ── schema_migrations row ─────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (53, now())
    ON CONFLICT (version) DO NOTHING;
