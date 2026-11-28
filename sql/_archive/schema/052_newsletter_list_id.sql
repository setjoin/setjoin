-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- schema/052_newsletter_list_id.sql
-- B5.1 — newsletter bundle infrastructure (migration V078)
--
-- Adds messages.list_id (normalized RFC 2919 List-Id), the normalize_list_id()
-- IMMUTABLE helper, the partial index over (mailbox_id, list_id), and the
-- feature.newsletter_bundles feature toggle (default ON).
--
-- Design:
--   - list_id is NULL for regular messages; non-NULL for newsletters.
--   - The normalization strips any "Optional Label <domain>" wrapper, keeping
--     only the bare domain token, lowercased.  RFC 2919 §2 permits the form
--     "List Name <list-id-namespace>" where the unique part is in angle brackets.
--   - The partial index (WHERE list_id IS NOT NULL) keeps the index small:
--     only newsletter rows are indexed.  The leading mailbox_id column satisfies
--     R1 auth-scoping so newsletter queries never cross mailbox boundaries.

-- 1. Column (idempotent)
ALTER TABLE messages ADD COLUMN IF NOT EXISTS list_id TEXT;

COMMENT ON COLUMN messages.list_id IS
  'Normalized RFC 2919 List-Id header value (bare domain token, lowercase). '
  'Non-NULL ⇒ message belongs to a newsletter bundle groupable by this id. '
  'Populated at delivery time by deliver() and import_message() via normalize_list_id(). '
  'NULL for all regular (non-newsletter) messages.';

-- 2. Normalize helper — IMMUTABLE (result depends only on input; no table reads)
CREATE OR REPLACE FUNCTION normalize_list_id(p_raw TEXT) RETURNS TEXT
IMMUTABLE
LANGUAGE sql AS $$
  SELECT CASE
    WHEN p_raw IS NULL THEN NULL
    -- Extract the token inside angle-brackets if present (RFC 2919 §2 form)
    WHEN p_raw ~ '<[^>]+>' THEN lower(trim(substring(p_raw FROM '<([^>]+)>')))
    -- Plain bare value (no angle-brackets) — lowercase and trim
    ELSE lower(trim(p_raw))
  END;
$$;

COMMENT ON FUNCTION normalize_list_id(TEXT) IS
  'Normalize an RFC 2919 List-Id header value to a bare lowercase domain token. '
  'Extracts the <...> token when present; otherwise lowercases and trims. '
  'Returns NULL when the input is NULL.  IMMUTABLE — safe to index.';

-- 3. Partial index — only newsletter rows; auth-scoped by leading mailbox_id (R1, S12)
CREATE INDEX IF NOT EXISTS messages_mailbox_list_idx
  ON messages (mailbox_id, list_id)
  WHERE list_id IS NOT NULL;

COMMENT ON INDEX messages_mailbox_list_idx IS
  'Partial index supporting newsletter bundle grouping queries. '
  'Leading mailbox_id enforces auth scoping (R1); partial predicate limits '
  'index size to newsletter-only rows.';

-- 4. Feature toggle — default ON
INSERT INTO feature_toggles (key, enabled, description)
VALUES ('feature.newsletter_bundles', TRUE,
        'Computed newsletter bundle grouping by List-Id header (B5). '
        'Absent row treated as TRUE by effective_capabilities().')
ON CONFLICT (key) DO NOTHING;
