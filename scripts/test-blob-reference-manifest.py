#!/usr/bin/env python3
"""Unit and mutant test suite for scripts/check-blob-reference-manifest.py (#550)."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GUARD_PATH = REPO_ROOT / "scripts" / "check-blob-reference-manifest.py"

spec = importlib.util.spec_from_file_location("blob_manifest_guard", GUARD_PATH)
assert spec is not None and spec.loader is not None
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def _base_fixture(work: Path) -> tuple[Path, Path, Path]:
    schema_dir = work / "dbschema"
    schema_dir.mkdir(parents=True, exist_ok=True)
    (schema_dir / "V001__base.sql").write_text(
        """
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
CREATE TABLE public.mail_recovery_quarantine_artifacts (
    id uuid PRIMARY KEY,
    status text NOT NULL,
    blob_inventory jsonb NOT NULL
);
CREATE TABLE public.blob_gc_state (
    blob_sha256 text PRIMARY KEY REFERENCES public.blobs(sha256) ON DELETE CASCADE
);
""",
        encoding="utf-8",
    )
    manifest = {
        "schema_version": 1,
        "live_roots": [
            {"table": "message_attachments", "column": "blob_sha256"},
            {"table": "messages", "column": "raw_ref"},
            {
                "table": "mail_recovery_quarantine_artifacts",
                "column": "blob_inventory",
            },
        ],
        "blobs_internal": [
            {"table": "blobs", "column": "sha256", "reason": "pk"},
            {"table": "blobs", "column": "minio_ref", "reason": "ref"},
            {"table": "blob_gc_state", "column": "blob_sha256", "reason": "gc"},
        ],
        "separate_storage_plane": [],
        "non_blob_digest": [],
    }
    manifest_path = work / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    gc_sql = work / "blob_gc.sql"
    gc_body = """
CREATE OR REPLACE FUNCTION public.blob_has_live_reference(p_sha256 text)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'denied' USING ERRCODE = 'BZ003';
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM public.message_attachments ma
         WHERE ma.blob_sha256 = p_sha256
    ) OR EXISTS (
        SELECT 1 FROM public.messages m
         WHERE m.raw_ref = p_sha256
           AND length(m.raw_ref) = 64
           AND m.raw_ref ~ '^[0-9a-f]{64}$'
    ) OR EXISTS (
        SELECT 1 FROM public.mail_recovery_quarantine_artifacts mrqa
        CROSS JOIN LATERAL jsonb_array_elements(mrqa.blob_inventory) elem
         WHERE mrqa.status NOT IN ('rejected', 'tampered')
           AND (elem->>'sha256' = p_sha256 OR elem->>'objectRef' = p_sha256)
    );
END;
$$;
"""
    gc_sql.write_text(gc_body, encoding="utf-8")
    v1_path = schema_dir / "V001__baseline.sql"
    if not v1_path.exists():
        v1_path = sorted(schema_dir.glob("V*.sql"))[0]
    v1_path.write_text(v1_path.read_text(encoding="utf-8") + "\n" + gc_body, encoding="utf-8")
    return manifest_path, schema_dir, gc_sql


def _assert_fails_with(
    errors: list[str], code: str, symbol: str, label: str
) -> None:
    joined = "\n".join(errors)
    assert errors, f"{label}: expected failure {code}, but guard passed"
    assert code in joined, f"{label}: missing code {code} in:\n{joined}"
    assert symbol in joined, f"{label}: missing symbol {symbol} in:\n{joined}"


def main() -> int:
    # 1. Pristine repo HEAD must pass cleanly.
    errors, stats = guard.validate(
        REPO_ROOT / "config" / "blob-reference-manifest.json",
        REPO_ROOT / "mailserver" / "sql" / "dbschema",
        REPO_ROOT / "mailserver" / "sql" / "reducers" / "blob_gc.sql",
    )
    assert not errors, f"pristine repo failed: {errors}"
    assert stats["live_roots"] >= 14, f"expected >= 14 live_roots, got {stats}"

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        m_path, s_dir, g_path = _base_fixture(work)
        errs, _ = guard.validate(m_path, s_dir, g_path)
        assert not errs, f"synthetic baseline failed: {errs}"

        base_manifest = json.loads(m_path.read_text(encoding="utf-8"))

        # Mutant 1: UNMANIFESTED_BLOB_COLUMN
        v2 = s_dir / "V002__unmanifested.sql"
        v2.write_text(
            "CREATE TABLE public.planted_widgets "
            "(id bigint PRIMARY KEY, planted_blob_sha256 text);\n",
            encoding="utf-8",
        )
        errs, _ = guard.validate(m_path, s_dir, g_path)
        _assert_fails_with(
            errs,
            "UNMANIFESTED_BLOB_COLUMN",
            "planted_widgets.planted_blob_sha256",
            "mutant-unmanifested",
        )
        v2.unlink()

        # Mutant 2: STALE_MANIFEST_ENTRY
        stale = copy.deepcopy(base_manifest)
        stale["non_blob_digest"].append(
            {
                "table": "planted_ghost_table",
                "column": "ghost_sha256",
                "reason": "stale",
            }
        )
        stale_path = work / "stale.json"
        stale_path.write_text(json.dumps(stale), encoding="utf-8")
        errs, _ = guard.validate(stale_path, s_dir, g_path)
        _assert_fails_with(
            errs,
            "STALE_MANIFEST_ENTRY",
            "planted_ghost_table.ghost_sha256",
            "mutant-stale",
        )

        # Mutant 3: FK_NOT_LIVE_ROOT
        v3 = s_dir / "V003__fk_misclassified.sql"
        v3.write_text(
            "CREATE TABLE public.planted_fk_table ("
            "id bigint PRIMARY KEY, "
            "planted_fk_blob_sha256 text REFERENCES public.blobs(sha256));\n",
            encoding="utf-8",
        )
        bad_fk = copy.deepcopy(base_manifest)
        bad_fk["non_blob_digest"].append(
            {
                "table": "planted_fk_table",
                "column": "planted_fk_blob_sha256",
                "reason": "wrongly classified",
            }
        )
        bad_fk_path = work / "bad_fk.json"
        bad_fk_path.write_text(json.dumps(bad_fk), encoding="utf-8")
        errs, _ = guard.validate(bad_fk_path, s_dir, g_path)
        _assert_fails_with(
            errs,
            "FK_NOT_LIVE_ROOT",
            "planted_fk_table.planted_fk_blob_sha256",
            "mutant-fk",
        )
        v3.unlink()

        # Mutant 4: DUPLICATE_MANIFEST_ENTRY
        dup = copy.deepcopy(base_manifest)
        dup["non_blob_digest"].append(
            {
                "table": "messages",
                "column": "raw_ref",
                "reason": "duplicate",
            }
        )
        dup_path = work / "dup.json"
        dup_path.write_text(json.dumps(dup), encoding="utf-8")
        errs, _ = guard.validate(dup_path, s_dir, g_path)
        _assert_fails_with(
            errs,
            "DUPLICATE_MANIFEST_ENTRY",
            "messages.raw_ref",
            "mutant-duplicate",
        )

        # Mutant 5a: SQL_CATALOG_DRIFT via commented-out root (-- and /* */)
        gc_commented = work / "gc_commented.sql"
        gc_commented.write_text(
            """
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
    ) */
    -- OR EXISTS (SELECT 1 FROM public.messages m WHERE m.raw_ref = p_sha256)
    OR EXISTS (
        SELECT 1 FROM public.mail_recovery_quarantine_artifacts mrqa
        CROSS JOIN LATERAL jsonb_array_elements(mrqa.blob_inventory) elem
         WHERE mrqa.status NOT IN ('rejected', 'tampered')
           AND (elem->>'sha256' = p_sha256 OR elem->>'objectRef' = p_sha256)
    );
END;
$$;
""",
            encoding="utf-8",
        )
        errs, _ = guard.validate(m_path, s_dir, gc_commented)
        _assert_fails_with(
            errs,
            "SQL_CATALOG_DRIFT",
            "messages.raw_ref",
            "mutant-sql-drift-missing-commented",
        )

        # Mutant 5b: SQL_CATALOG_DRIFT reverse direction (extra root in SQL)
        gc_extra = work / "gc_extra.sql"
        gc_extra.write_text(
            g_path.read_text(encoding="utf-8").replace(
                "    );\nEND;",
                "    ) OR EXISTS (\n"
                "        SELECT 1 FROM public.planted_extra_tbl pe\n"
                "         WHERE pe.extra_blob_sha256 = p_sha256\n"
                "    );\nEND;",
            ),
            encoding="utf-8",
        )
        errs, _ = guard.validate(m_path, s_dir, gc_extra)
        _assert_fails_with(
            errs,
            "SQL_CATALOG_DRIFT",
            "planted_extra_tbl.extra_blob_sha256",
            "mutant-sql-drift-extra",
        )

        # Mutant 5c: JSONB traversal WITHOUT elem->>'sha256'/'objectRef' comparison
        gc_bad_jsonb = work / "gc_bad_jsonb.sql"
        gc_bad_jsonb.write_text(
            g_path.read_text(encoding="utf-8").replace(
                "AND (elem->>'sha256' = p_sha256 OR elem->>'objectRef' = p_sha256)",
                "AND elem IS NOT NULL",
            ),
            encoding="utf-8",
        )
        errs, _ = guard.validate(m_path, s_dir, gc_bad_jsonb)
        _assert_fails_with(
            errs,
            "SQL_CATALOG_DRIFT",
            "mail_recovery_quarantine_artifacts.blob_inventory",
            "mutant-sql-drift-jsonb-no-digest-check",
        )

        # Mutant 5d: Embedded migration blob_has_live_reference() drift (upgrade parity)
        v999_drift = s_dir / "V999__drifted_gc.sql"
        v999_drift.write_text(
            gc_commented.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        errs, _ = guard.validate(m_path, s_dir, g_path)
        _assert_fails_with(
            errs,
            "SQL_CATALOG_DRIFT",
            "V999__drifted_gc.sql",
            "mutant-migration-sql-drift",
        )
        v999_drift.unlink()

        # Mutant 6: ALTER TABLE ... RENAME COLUMN updates columns and FKs
        v4_rename = s_dir / "V004__rename_col.sql"
        v4_rename.write_text(
            "ALTER TABLE public.message_attachments "
            "RENAME COLUMN blob_sha256 TO renamed_blob_sha256;\n",
            encoding="utf-8",
        )
        errs, _ = guard.validate(m_path, s_dir, g_path)
        _assert_fails_with(
            errs,
            "STALE_MANIFEST_ENTRY",
            "message_attachments.blob_sha256",
            "mutant-rename-stale",
        )
        _assert_fails_with(
            errs,
            "UNMANIFESTED_BLOB_COLUMN",
            "message_attachments.renamed_blob_sha256",
            "mutant-rename-unmanifested",
        )
        _assert_fails_with(
            errs,
            "FK_NOT_LIVE_ROOT",
            "message_attachments.renamed_blob_sha256",
            "mutant-rename-fk",
        )
        v4_rename.unlink()

    print("test-blob-reference-manifest: PASS (pristine repo + all 5 mutants verified)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
