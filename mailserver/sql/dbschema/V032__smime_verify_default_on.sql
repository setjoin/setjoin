-- ════════════════════════════════════════════════════════════════════════
-- V032__smime_verify_default_on.sql — ship inbound S/MIME verification ON by default.
--
-- feature.smime_verify gates the inbound S/MIME signature-verification path
-- (smtp/inbound.go: toggles.IsEnabledDefault("feature.smime_verify", false)). V013
-- seeded the row enabled=FALSE (the signing feature shipped off-by-default). For the
-- cutover default we now want it ON, so flip the seeded row to enabled=TRUE: a
-- freshly-deployed org verifies inbound S/MIME (and shows the verified-sender badge)
-- out of the box. The path is FAIL-OPEN — a verification error never blocks delivery
-- — so on-by-default is safe.
--
-- UPDATE (not INSERT…ON CONFLICT DO NOTHING) because V013 < V032 guarantees the row
-- already exists; the INSERT below is a defensive fallback for the (impossible-once-
-- V013-applied) absent case. The flip is unconditional — this sets the SHIPPING
-- default, and there is no established production whose deliberate OFF we'd override.
--
-- (Seed/default changes belong in a forward migration, NOT a hand-edit of V001/V013.)
-- ════════════════════════════════════════════════════════════════════════

UPDATE public.feature_toggles
   SET enabled = true, updated_at = now()
 WHERE key = 'feature.smime_verify';

INSERT INTO public.feature_toggles (key, enabled, description)
VALUES ('feature.smime_verify', true,
        'Inbound S/MIME signature verification (verified-sender badge). Cutover default ON; fail-open — a verification error never blocks delivery.')
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (32, now())
    ON CONFLICT (version) DO NOTHING;
