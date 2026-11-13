-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 036: pg_search BM25 full-text search index (Phase 36).
-- Replaces 3 GIN indexes with a single BM25 index for relevance-ranked search.
-- Requires: CREATE EXTENSION pg_search (ParadeDB extension, AGPLv3).
-- On systems without ParadeDB installed, this block is skipped gracefully.
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pg_search;

  -- Drop existing GIN indexes (replaced by BM25 below)
  DROP INDEX IF EXISTS messages_body_tsv_idx;
  DROP INDEX IF EXISTS messages_subject_tsv_idx;
  DROP INDEX IF EXISTS messages_from_tsv_idx;

  -- Create BM25 index on the message tsvector columns.
  -- Uses ICU tokenizer for CJK support.
  -- key_field=id enables paradedb.score(id) for relevance ranking.
  EXECUTE $idx$
    CREATE INDEX IF NOT EXISTS idx_messages_bm25 ON messages
    USING bm25 (id, body_tsv, subject_tsv, from_tsv, received_at)
    WITH (key_field='id', tokenizer='icu')
  $idx$;
EXCEPTION
  WHEN undefined_file THEN
    RAISE NOTICE 'pg_search (ParadeDB) extension not installed — BM25 index skipped. Install ParadeDB for full-text search.';
  WHEN feature_not_supported THEN
    RAISE NOTICE 'pg_search (ParadeDB) extension not supported — BM25 index skipped.';
END;
$$;
