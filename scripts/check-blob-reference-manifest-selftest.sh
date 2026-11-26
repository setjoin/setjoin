#!/usr/bin/env bash
# Self-test for scripts/check-blob-reference-manifest.sh (Issue #550).
# Auto-discovered by scripts/run-guards.sh (runs before check-blob-reference-manifest.sh).
# Asserts non-zero exit + exact invariant code + planted symbol for all 5 mutants,
# then verifies pristine HEAD passes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$SCRIPT_DIR/check-blob-reference-manifest.sh"

echo "==> check-blob-reference-manifest selftest"

# 1. Run Python unit & mutant suite (covers pristine HEAD + all 5 invariants + comment stripping).
python3 "$SCRIPT_DIR/test-blob-reference-manifest.py"

# 2. Shell-level grep -qF verification on synthetic fixtures for every invariant + planted symbol.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/dbschema"
cat >"$WORK/dbschema/V001__base.sql" <<'SQL'
CREATE TABLE public.blobs (
  sha256 text PRIMARY KEY,
  minio_ref text NOT NULL
);
CREATE TABLE public.message_attachments (
  id bigint PRIMARY KEY,
  blob_sha256 text NOT NULL REFERENCES public.blobs(sha256)
);
CREATE TABLE public.messages (
  id bigint PRIMARY KEY,
  raw_ref text NOT NULL
);
CREATE TABLE public.blob_gc_state (
  blob_sha256 text PRIMARY KEY REFERENCES public.blobs(sha256) ON DELETE CASCADE
);
SQL

cat >"$WORK/manifest.json" <<'JSON'
{
  "schema_version": 1,
  "live_roots": [
    {"table": "message_attachments", "column": "blob_sha256"},
    {"table": "messages", "column": "raw_ref"}
  ],
  "blobs_internal": [
    {"table": "blobs", "column": "sha256", "reason": "pk"},
    {"table": "blobs", "column": "minio_ref", "reason": "ref"},
    {"table": "blob_gc_state", "column": "blob_sha256", "reason": "gc"}
  ],
  "separate_storage_plane": [],
  "non_blob_digest": []
}
JSON

cat >"$WORK/blob_gc.sql" <<'SQL'
CREATE OR REPLACE FUNCTION public.blob_has_live_reference(p_sha256 text)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM public.message_attachments ma
     WHERE ma.blob_sha256 = p_sha256
  ) OR EXISTS (
    SELECT 1 FROM public.messages m
     WHERE m.raw_ref = p_sha256
       AND length(m.raw_ref) = 64
       AND m.raw_ref ~ '^[0-9a-f]{64}$'
  );
END;
$$;
SQL

assert_mutant() {
  local label="$1"
  local expected_code="$2"
  local expected_symbol="$3"
  local manifest_file="$4"
  local schema_dir="$5"
  local gc_sql="$6"
  local rc=0
  local out
  out="$(
    BLOB_MANIFEST="$manifest_file" \
      BLOB_SCHEMA_DIR="$schema_dir" \
      BLOB_GC_SQL_FILE="$gc_sql" \
      bash "$GUARD" 2>&1
  )" || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "FAIL [$label]: mutant unexpectedly passed" >&2
    exit 1
  fi
  if ! printf '%s\n' "$out" | grep -qF "$expected_code"; then
    echo "FAIL [$label]: expected code '$expected_code' missing in output:" >&2
    printf '%s\n' "$out" >&2
    exit 1
  fi
  if ! printf '%s\n' "$out" | grep -qF "$expected_symbol"; then
    echo "FAIL [$label]: expected symbol '$expected_symbol' missing in output:" >&2
    printf '%s\n' "$out" >&2
    exit 1
  fi
}

# Mutant 1: UNMANIFESTED_BLOB_COLUMN
mkdir -p "$WORK/m1_schema"
cp "$WORK/dbschema/V001__base.sql" "$WORK/m1_schema/"
cat >"$WORK/m1_schema/V002__unmanifested.sql" <<'SQL'
CREATE TABLE public.smoke_unmanifested (id bigint PRIMARY KEY, rogue_blob_sha256 text);
SQL
assert_mutant \
  "UNMANIFESTED_BLOB_COLUMN" \
  "UNMANIFESTED_BLOB_COLUMN" \
  "smoke_unmanifested.rogue_blob_sha256" \
  "$WORK/manifest.json" \
  "$WORK/m1_schema" \
  "$WORK/blob_gc.sql"

# Mutant 2: STALE_MANIFEST_ENTRY
cat >"$WORK/m2_manifest.json" <<'JSON'
{
  "schema_version": 1,
  "live_roots": [
    {"table": "message_attachments", "column": "blob_sha256"},
    {"table": "messages", "column": "raw_ref"}
  ],
  "blobs_internal": [
    {"table": "blobs", "column": "sha256", "reason": "pk"},
    {"table": "blobs", "column": "minio_ref", "reason": "ref"},
    {"table": "blob_gc_state", "column": "blob_sha256", "reason": "gc"}
  ],
  "separate_storage_plane": [],
  "non_blob_digest": [
    {"table": "smoke_deleted_table", "column": "stale_sha256", "reason": "stale"}
  ]
}
JSON
assert_mutant \
  "STALE_MANIFEST_ENTRY" \
  "STALE_MANIFEST_ENTRY" \
  "smoke_deleted_table.stale_sha256" \
  "$WORK/m2_manifest.json" \
  "$WORK/dbschema" \
  "$WORK/blob_gc.sql"

# Mutant 3: FK_NOT_LIVE_ROOT
mkdir -p "$WORK/m3_schema"
cp "$WORK/dbschema/V001__base.sql" "$WORK/m3_schema/"
cat >"$WORK/m3_schema/V002__fk_nonroot.sql" <<'SQL'
CREATE TABLE public.smoke_fk_nonroot (
  id bigint PRIMARY KEY,
  misclassified_blob_sha256 text REFERENCES public.blobs(sha256)
);
SQL
cat >"$WORK/m3_manifest.json" <<'JSON'
{
  "schema_version": 1,
  "live_roots": [
    {"table": "message_attachments", "column": "blob_sha256"},
    {"table": "messages", "column": "raw_ref"}
  ],
  "blobs_internal": [
    {"table": "blobs", "column": "sha256", "reason": "pk"},
    {"table": "blobs", "column": "minio_ref", "reason": "ref"},
    {"table": "blob_gc_state", "column": "blob_sha256", "reason": "gc"}
  ],
  "separate_storage_plane": [],
  "non_blob_digest": [
    {"table": "smoke_fk_nonroot", "column": "misclassified_blob_sha256", "reason": "bad"}
  ]
}
JSON
assert_mutant \
  "FK_NOT_LIVE_ROOT" \
  "FK_NOT_LIVE_ROOT" \
  "smoke_fk_nonroot.misclassified_blob_sha256" \
  "$WORK/m3_manifest.json" \
  "$WORK/m3_schema" \
  "$WORK/blob_gc.sql"

# Mutant 4: DUPLICATE_MANIFEST_ENTRY
cat >"$WORK/m4_manifest.json" <<'JSON'
{
  "schema_version": 1,
  "live_roots": [
    {"table": "message_attachments", "column": "blob_sha256"},
    {"table": "messages", "column": "raw_ref"}
  ],
  "blobs_internal": [
    {"table": "blobs", "column": "sha256", "reason": "pk"},
    {"table": "blobs", "column": "minio_ref", "reason": "ref"},
    {"table": "blob_gc_state", "column": "blob_sha256", "reason": "gc"}
  ],
  "separate_storage_plane": [],
  "non_blob_digest": [
    {"table": "messages", "column": "raw_ref", "reason": "dup"}
  ]
}
JSON
assert_mutant \
  "DUPLICATE_MANIFEST_ENTRY" \
  "DUPLICATE_MANIFEST_ENTRY" \
  "messages.raw_ref" \
  "$WORK/m4_manifest.json" \
  "$WORK/dbschema" \
  "$WORK/blob_gc.sql"

# Mutant 5: SQL_CATALOG_DRIFT (commented-out root in blob_has_live_reference)
cat >"$WORK/m5_blob_gc.sql" <<'SQL'
CREATE OR REPLACE FUNCTION public.blob_has_live_reference(p_sha256 text)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM public.message_attachments ma
     WHERE ma.blob_sha256 = p_sha256
  )
  /* OR EXISTS (
    SELECT 1 FROM public.messages m
     WHERE m.raw_ref = p_sha256
  ) */;
END;
$$;
SQL
assert_mutant \
  "SQL_CATALOG_DRIFT" \
  "SQL_CATALOG_DRIFT" \
  "messages.raw_ref" \
  "$WORK/manifest.json" \
  "$WORK/dbschema" \
  "$WORK/m5_blob_gc.sql"

# 3. Verify clean HEAD passes.
bash "$GUARD"

echo "check-blob-reference-manifest-selftest: PASS (all 5 mutants + clean HEAD verified)."
