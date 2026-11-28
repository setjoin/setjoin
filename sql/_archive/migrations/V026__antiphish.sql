-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V026: Advanced Anti-Phishing — materialized view, feature toggles, system config (Stage 2.4)
-- Depends on: Go cron worker (replaces pg_cron), pg_trgm extension (already deployed)

-- ── 1. Contact graph materialized view (refreshed every 5 min by pg_cron) ──────────
-- Maps mailbox → sender familiarity for impersonation detection.
CREATE MATERIALIZED VIEW antiphish_contact_graph AS
SELECT
    m.mailbox_id,
    m.from_addr AS sender_email,
    m.from_name AS sender_name,
    MAX(m.received_at) AS last_seen_at,
    COUNT(*) AS message_count
FROM messages m
WHERE m.from_name IS NOT NULL
  AND m.from_name != ''
  AND m.from_addr IS NOT NULL
  AND m.from_addr != ''
GROUP BY m.mailbox_id, m.from_addr, m.from_name;

CREATE UNIQUE INDEX antiphish_contact_graph_idx
    ON antiphish_contact_graph (mailbox_id, sender_email);

-- Schedule periodic refresh (runs concurrently to avoid blocking reads).
-- [pg_cron→Go cron worker] SELECT cron.schedule('refresh-antiphish-contact-graph', '*/5 * * * *',
--     $$ REFRESH MATERIALIZED VIEW CONCURRENTLY antiphish_contact_graph; $$
-- );

-- ── 2. Feature toggles ───────────────────────────────────────────────────────────
INSERT INTO feature_toggles (key, enabled, description) VALUES
    ('feature.antiphish_display_name',   TRUE,  'Display-name spoofing detector (fuzzy match against internal users)'),
    ('feature.antiphish_lookalike',      TRUE,  'Lookalike domain detector (homoglyph + Levenshtein against protected domains)'),
    ('feature.antiphish_contact_graph',  TRUE,  'Contact graph impersonation detector (novel sender with known display name)'),
    ('feature.antiphish_strict_mode',    FALSE, 'Treat Warn as Reject for all anti-phishing detectors')
ON CONFLICT (key) DO NOTHING;

-- ── 3. System config defaults ────────────────────────────────────────────────────
INSERT INTO system_config (key, value, description) VALUES
    ('antiphish.name_similarity_threshold', to_jsonb(0.85::float8),
     'pg_trgm similarity threshold for display-name fuzzy matching (0.0–1.0)'),
    ('antiphish.protected_domains', to_jsonb('[]'::jsonb),
     'High-value domains for lookalike detection (JSON array of strings, e.g. ["microsoft.com","google.com","paypal.com"])')
ON CONFLICT (key) DO NOTHING;
