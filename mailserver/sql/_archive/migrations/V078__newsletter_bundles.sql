-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V078__newsletter_bundles.sql
-- B5 — Newsletter bundles (computed, not stored; S12)
--
-- 1. Adds messages.list_id TEXT column: normalized RFC 2919 List-Id header value.
--    Non-NULL ⇒ message is part of a newsletter bundle groupable by list_id.
--    Populated by deliver() and import_message() at delivery time.
--
-- 2. normalize_list_id(p_raw TEXT) — IMMUTABLE helper: extracts the bare
--    domain token from the RFC 2919 List-Id header value
--    (strips "Optional Label <domain>" or plain "<domain>" form).
--
-- 3. Partial index messages_mailbox_list_idx (mailbox_id, list_id) WHERE
--    list_id IS NOT NULL — only indexes newsletter messages; equality on the
--    leading auth-scoped mailbox_id column (S12, R1).
--
-- 4. Seeds feature.newsletter_bundles toggle (default ON).

\i ../schema/052_newsletter_list_id.sql

-- Drop old function overloads that are superseded by B5.1's p_list_id additions.
-- Without these DROPs the new and old signatures coexist and PostgreSQL cannot
-- resolve ambiguous calls (42725) from callers that pass fewer positional args.

-- Old 27-arg deliver() (no p_list_id); replaced by 28-arg version below.
DROP FUNCTION IF EXISTS deliver(
  text, text, text, text, text,
  jsonb, jsonb, jsonb,
  text, text, text, text, text,
  bigint, boolean, timestamptz,
  text, text, text,
  real, jsonb,
  text, text,
  boolean, text, boolean,
  integer
);

-- Old 19-arg import_message() (no p_list_id); replaced by 20-arg version below.
DROP FUNCTION IF EXISTS import_message(
  bigint, bigint,
  text, text, text, text,
  jsonb, jsonb, jsonb,
  text, text, text, text,
  bigint, boolean, boolean,
  text, timestamptz,
  bigint
);

-- B5.2: newsletter_bundles_list — computed bundle grouping query + per-user opt-out.
\i ../reducers/newsletter_bundles.sql
