-- V152__external_identity_labels.sql — broaden the existing default-on
-- external-sender warning toggle to cover sender and recipient identity labels.
--
-- Preserve the operator's current enabled value. Fresh installs already seed
-- feature.external_sender_warn ON in V001; this migration only updates the
-- admin-facing description so existing installations see the expanded scope.

UPDATE public.feature_toggles
   SET description = 'Show External labels and warnings for senders and recipients outside the organization'
 WHERE key = 'feature.external_sender_warn';

COMMENT ON COLUMN public.users.external_sender_warning IS
    'Per-user toggle for External labels and warnings on outside senders and recipients. TRUE by default.';

INSERT INTO public.schema_migrations (version, applied_at) VALUES (152, now())
    ON CONFLICT (version) DO NOTHING;
