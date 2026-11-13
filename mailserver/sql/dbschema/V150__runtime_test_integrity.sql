-- V150__runtime_test_integrity.sql — close two defects surfaced by the live
-- browser/runtime verification lane.

-- The materialized view deliberately retains one row per historical display
-- name so a later name change does not erase impersonation evidence. Its old
-- unique index omitted sender_name, so two names from one address made every
-- scheduled REFRESH fail with SQLSTATE 23505. Include the full row identity;
-- this also remains suitable for a future CONCURRENTLY refresh.
DROP INDEX IF EXISTS public.antiphish_contact_graph_idx;
CREATE UNIQUE INDEX antiphish_contact_graph_idx
    ON public.antiphish_contact_graph (mailbox_id, sender_email, sender_name);

-- The gateway auth chain reads this row directly at startup. The Go registry
-- safely defaulted it OFF when absent, but the missing DB row made the feature
-- invisible to operators and logged a warning on every reload.
INSERT INTO public.feature_toggles (key, enabled, description)
VALUES ('feature.disable_basic_auth', FALSE,
        'Disable HTTP Basic authentication while retaining Bearer and configured authentication methods.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (150, now())
    ON CONFLICT (version) DO NOTHING;
