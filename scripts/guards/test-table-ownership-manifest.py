#!/usr/bin/env python3
"""Self-test suite for scripts/guards/check-table-ownership-manifest.py (Issue #539).

Tests executed:
  0a. Pristine repository passes cleanly.
  0b. Synthetic base fixture passes (partitions excluded, SQL comments including
      inside DO $$ ignored, Rust #[cfg(test)] ignored, ordered FOREACH replay).
  1.  UNCLASSIFIED: newly added base table not in manifest.
  2.  STALE: ghost table in manifest absent from migrations.
  3.  UNCONTRACTED_CROSS_DOMAIN_READ: calendar reading jmap's messages.
  4a. UNCONTRACTED_CROSS_DOMAIN_WRITE: chat updating drive's drive_nodes.
  4b. read_only contract still blocks cross-domain WRITE.
  5a. MISSING_FORCE_RLS: enforced table lacking RLS entirely.
  5b. MISSING_FORCE_RLS: enforced table with ENABLE-only (no FORCE).
  5c. MISSING_FORCE_RLS: enforced table with FORCE followed by NO FORCE.
  6a. R1_MISSING_PREDICATE: unscoped SELECT without WHERE clause.
  6b. R1_MISSING_PREDICATE: projection-only SELECT user_id ... WHERE id = $1.
  6c. r1_r3_allowlist permits explicitly listed (file, table).
  6d. R1_MISSING_PREDICATE: chat_channels with FK chain `id -> ...` rejects bare
      `WHERE id = $1` (no `"id"` scope-token bypass).
  7a. R3_MISSING_PREDICATE: UPDATE missing ownership in WHERE (only SET/RETURNING).
  7b. R3_MISSING_PREDICATE: DELETE missing ownership in WHERE.
  8a. RLS_PENDING_RATCHET: new table using pending_wave1_cutover outside baseline.
  8b. RLS_PENDING_RATCHET: pending count exceeding legacy_rls_pending_ceiling.
  9a. STALE_PENDING_RLS: legacy pending table already having ENABLE+FORCE.
  9b. LEGACY_WRITE_RATCHET: legacy_write_migration_pending count exceeding ceiling.
  9c. Fail-closed exit 3 on unsupported dynamic RLS %s format.
  9d. Fail-closed exit 3 on zero extracted logical tables.
  10. Rust char-literal `let _ = '"';` does not invert string parsing; `cr#"` raw
      C-string SQL is scanned.
  11. Domain `src/*.sql` (`include_str!`) files are scanned for cross-domain SQL.
  12. `#[cfg(test)]` stripper handles `'{'` char literals inside test blocks and
      ignores `"#[cfg(test)]"` inside production string literals.
  13. Comma-joins (`FROM a, messages`), `DELETE ... USING`, and double-quoted
      `"messages"` identifiers are extracted.
  14. SQL migration RLS extractor: comma-separated `ENABLE ..., NO FORCE ...`,
      interleaved `FORCE` + `RENAME TO`, and string-literal immunity inside
      `INSERT ... VALUES ('ALTER TABLE ... FORCE ROW LEVEL SECURITY')`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD_SH = REPO_ROOT / "scripts/guards/check-table-ownership-manifest.sh"


def run_guard(
    manifest: Optional[Path] = None,
    schema_dir: Optional[Path] = None,
    domains_dir: Optional[Path] = None,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    if manifest is not None:
        env["TABLE_MANIFEST"] = str(manifest)
    if schema_dir is not None:
        env["TABLE_SCHEMA_DIR"] = str(schema_dir)
    if domains_dir is not None:
        env["TABLE_RUST_DOMAINS_DIR"] = str(domains_dir)
    return subprocess.run(
        ["bash", str(GUARD_SH)],
        env=env,
        capture_output=True,
        text=True,
    )


def build_base_fixture(tmp: Path) -> Tuple[Path, Path, Path]:
    """Create a minimal passing synthetic fixture (schema + manifest + Rust domains)."""
    schema_dir = tmp / "dbschema"
    domains_dir = tmp / "domains"
    schema_dir.mkdir(parents=True, exist_ok=True)
    for crate in (
        "calendar",
        "chat",
        "drive",
        "guests",
        "identity",
        "jmap",
        "user-settings",
    ):
        (domains_dir / crate / "src").mkdir(parents=True, exist_ok=True)

    (schema_dir / "V001__base.sql").write_text(
        """\
-- Commented ghost table must never be extracted:
-- CREATE TABLE public.commented_ghost (id bigint);
/* Nested /* CREATE TABLE public.nested_ghost (id bigint); */ still comment */
CREATE TABLE public.messages (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    subject text
) PARTITION BY RANGE (id);
CREATE TABLE public.messages_p1 (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    subject text
);
ALTER TABLE ONLY public.messages
    ATTACH PARTITION public.messages_p1 FOR VALUES FROM (1) TO (100);
CREATE TABLE public.messages_p2 PARTITION OF public.messages
    FOR VALUES FROM (100) TO (200);
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.messages FORCE  ROW LEVEL SECURITY;

CREATE TABLE public.drive_nodes (
    id bigint PRIMARY KEY,
    space_id bigint NOT NULL,
    name text
);
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['drive_nodes'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I NO FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', t);
    /* ALTER TABLE public.drive_nodes NO FORCE ROW LEVEL SECURITY; */
  END LOOP;
END $$;

CREATE TABLE public.chat_channels (
    id bigint PRIMARY KEY,
    name text
);
ALTER TABLE public.chat_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_channels FORCE ROW LEVEL SECURITY;

CREATE TABLE public.user_signatures (
    id bigint PRIMARY KEY,
    user_id bigint NOT NULL,
    body text
);
ALTER TABLE public.user_signatures ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_signatures FORCE ROW LEVEL SECURITY;

CREATE TABLE public.legacy_profiles (
    id bigint PRIMARY KEY,
    user_id bigint NOT NULL
);

CREATE TABLE public.system_config (
    key text PRIMARY KEY,
    value text
);
""",
        encoding="utf-8",
    )

    (domains_dir / "jmap/src/lib.rs").write_text(
        """\
pub fn read_msg() -> &'static str {
    "SELECT id, subject FROM messages WHERE id = $1 AND mailbox_id = $2"
}
#[cfg(test)]
mod tests {
    const BAD_TEST_SQL: &str = "UPDATE drive_nodes SET name = 'x' WHERE id = $1";
}
""",
        encoding="utf-8",
    )
    (domains_dir / "user-settings/src/lib.rs").write_text(
        """\
pub fn read_sig() -> &'static str {
    "SELECT id, body FROM user_signatures WHERE id = $1 AND user_id = $2"
}
pub fn update_sig() -> &'static str {
    "UPDATE user_signatures SET body = $3 WHERE id = $1 AND user_id = $2"
}
""",
        encoding="utf-8",
    )

    manifest = {
        "schema_version": 1,
        "legacy_rls_pending_ceiling": 1,
        "legacy_rls_pending_tables": ["legacy_profiles"],
        "legacy_write_migration_ceiling": 0,
        "r1_r3_allowlist": [],
        "tables": {
            "messages": {
                "owner": "jmap",
                "security_class": "mailbox_scoped",
                "rls_posture": "enforced",
                "rls_scope_column": "mailbox_id",
                "read_contracts": [],
            },
            "drive_nodes": {
                "owner": "drive",
                "security_class": "user_scoped",
                "rls_posture": "enforced",
                "rls_scope_column": "space_id -> drive_spaces.owner_user_id",
                "read_contracts": [],
            },
            "chat_channels": {
                "owner": "chat",
                "security_class": "user_scoped",
                "rls_posture": "enforced",
                "rls_scope_column": "id -> chat_channel_members.user_id",
                "read_contracts": [],
            },
            "user_signatures": {
                "owner": "user-settings",
                "security_class": "user_scoped",
                "rls_posture": "enforced",
                "rls_scope_column": "user_id",
                "read_contracts": [],
            },
            "legacy_profiles": {
                "owner": "identity",
                "security_class": "user_scoped",
                "rls_posture": "pending_wave1_cutover",
                "rls_tracking_issue": "#546",
                "rls_scope_column": "user_id",
                "read_contracts": [],
            },
            "system_config": {
                "owner": "platform",
                "security_class": "org_global",
                "rls_posture": "not_applicable",
                "read_contracts": [],
            },
        },
    }
    manifest_path = tmp / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest_path, schema_dir, domains_dir


def assert_fails_with(
    name: str,
    proc: subprocess.CompletedProcess,
    expected_token: str,
    expected_rc: Optional[int] = None,
) -> None:
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode == 0:
        raise AssertionError(
            f"[{name}] expected failure containing {expected_token!r}, "
            f"but guard PASSED:\n{combined}"
        )
    if expected_rc is not None and proc.returncode != expected_rc:
        raise AssertionError(
            f"[{name}] expected exit code {expected_rc}, "
            f"got {proc.returncode}:\n{combined}"
        )
    if expected_token not in combined:
        raise AssertionError(
            f"[{name}] expected output to contain {expected_token!r}, got:\n{combined}"
        )
    print(f"  PASS: {name} -> caught {expected_token!r} (rc={proc.returncode})")


def assert_passes(name: str, proc: subprocess.CompletedProcess) -> None:
    if proc.returncode != 0:
        raise AssertionError(
            f"[{name}] expected PASS, got rc={proc.returncode}:\n"
            f"{proc.stdout}\n{proc.stderr}"
        )
    print(f"  PASS: {name}")


def main() -> int:
    # 0a. Pristine repository check
    assert_passes("0a. pristine repo passes", run_guard())

    with tempfile.TemporaryDirectory(prefix="table-manifest-selftest-") as td:
        root = Path(td)

        # 0b. Positive control on clean synthetic fixture
        m, s, d = build_base_fixture(root / "clean")
        assert_passes(
            "0b. synthetic base fixture passes "
            "(partitions, comments, #[cfg(test)], ordered FOREACH)",
            run_guard(m, s, d),
        )

        # 1. UNCLASSIFIED:
        m, s, d = build_base_fixture(root / "m1_unclassified")
        (s / "V002__add_unclassified.sql").write_text(
            "CREATE TABLE public.shadow_notes "
            "(id bigint PRIMARY KEY, user_id bigint NOT NULL);\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "1. UNCLASSIFIED new table",
            run_guard(m, s, d),
            "UNCLASSIFIED: shadow_notes",
        )

        # 2. STALE:
        m, s, d = build_base_fixture(root / "m2_stale")
        data = json.loads(m.read_text(encoding="utf-8"))
        data["tables"]["ghost_legacy_table"] = {
            "owner": "platform",
            "security_class": "system_only",
            "rls_posture": "not_applicable",
            "read_contracts": [],
        }
        m.write_text(json.dumps(data, indent=2), encoding="utf-8")
        assert_fails_with(
            "2. STALE ghost table",
            run_guard(m, s, d),
            "STALE: ghost_legacy_table",
        )

        # 3. UNCONTRACTED_CROSS_DOMAIN_READ: (calendar reading jmap's messages)
        m, s, d = build_base_fixture(root / "m3_xread")
        (d / "calendar/src/leak.rs").write_text(
            "pub fn leak() -> &'static str {\n"
            '    "SELECT id FROM messages WHERE mailbox_id = $1"\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "3. UNCONTRACTED_CROSS_DOMAIN_READ (calendar -> messages)",
            run_guard(m, s, d),
            "UNCONTRACTED_CROSS_DOMAIN_READ: calendar -> messages",
        )

        # 4a & 4b. UNCONTRACTED_CROSS_DOMAIN_WRITE: (chat updating drive's drive_nodes)
        m, s, d = build_base_fixture(root / "m4_xwrite")
        (d / "chat/src/mutate.rs").write_text(
            "pub fn bad() -> &'static str {\n"
            '    "UPDATE drive_nodes SET name = $2 WHERE id = $1 AND space_id = $3"\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "4a. UNCONTRACTED_CROSS_DOMAIN_WRITE (chat -> drive_nodes)",
            run_guard(m, s, d),
            "UNCONTRACTED_CROSS_DOMAIN_WRITE: chat -> drive_nodes",
        )
        data = json.loads(m.read_text(encoding="utf-8"))
        data["tables"]["drive_nodes"]["read_contracts"].append(
            {
                "consumer": "chat",
                "mode": "read_only",
                "reason": "selftest read-only contract",
            }
        )
        m.write_text(json.dumps(data, indent=2), encoding="utf-8")
        assert_fails_with(
            "4b. read_only contract still blocks cross-domain WRITE",
            run_guard(m, s, d),
            "UNCONTRACTED_CROSS_DOMAIN_WRITE: chat -> drive_nodes",
        )

        # 5a. MISSING_FORCE_RLS (missing entirely)
        m, s, d = build_base_fixture(root / "m5a_rls_missing")
        (s / "V002__add_unforced.sql").write_text(
            "CREATE TABLE public.no_rls_table "
            "(id bigint PRIMARY KEY, user_id bigint NOT NULL);\n",
            encoding="utf-8",
        )
        data = json.loads(m.read_text(encoding="utf-8"))
        data["tables"]["no_rls_table"] = {
            "owner": "identity",
            "security_class": "user_scoped",
            "rls_posture": "enforced",
            "rls_scope_column": "user_id",
            "read_contracts": [],
        }
        m.write_text(json.dumps(data, indent=2), encoding="utf-8")
        assert_fails_with(
            "5a. MISSING_FORCE_RLS (missing entirely)",
            run_guard(m, s, d),
            "MISSING_FORCE_RLS: no_rls_table",
        )

        # 5b. MISSING_FORCE_RLS (ENABLE-only without FORCE)
        m, s, d = build_base_fixture(root / "m5b_enable_only")
        (s / "V002__enable_only.sql").write_text(
            "CREATE TABLE public.enable_only_tbl "
            "(id bigint PRIMARY KEY, user_id bigint NOT NULL);\n"
            "ALTER TABLE public.enable_only_tbl ENABLE ROW LEVEL SECURITY;\n",
            encoding="utf-8",
        )
        data = json.loads(m.read_text(encoding="utf-8"))
        data["tables"]["enable_only_tbl"] = {
            "owner": "identity",
            "security_class": "user_scoped",
            "rls_posture": "enforced",
            "rls_scope_column": "user_id",
            "read_contracts": [],
        }
        m.write_text(json.dumps(data, indent=2), encoding="utf-8")
        assert_fails_with(
            "5b. MISSING_FORCE_RLS (ENABLE-only without FORCE)",
            run_guard(m, s, d),
            "MISSING_FORCE_RLS: enable_only_tbl",
        )

        # 5c. MISSING_FORCE_RLS (FORCE followed by NO FORCE)
        m, s, d = build_base_fixture(root / "m5c_no_force")
        (s / "V002__unforce.sql").write_text(
            "ALTER TABLE public.messages NO FORCE ROW LEVEL SECURITY;\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "5c. MISSING_FORCE_RLS (FORCE then NO FORCE)",
            run_guard(m, s, d),
            "MISSING_FORCE_RLS: messages",
        )

        # 6a. R1_MISSING_PREDICATE (unscoped SELECT without WHERE)
        m, s, d = build_base_fixture(root / "m6a_r1_no_where")
        (d / "user-settings/src/all_sigs.rs").write_text(
            "pub fn all() -> &'static str {\n"
            '    "SELECT id, body FROM user_signatures"\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "6a. R1_MISSING_PREDICATE (unscoped SELECT without WHERE)",
            run_guard(m, s, d),
            "R1_MISSING_PREDICATE",
        )

        # 6b & 6c. R1_MISSING_PREDICATE (projection-only SELECT user_id WHERE id = $1)
        m, s, d = build_base_fixture(root / "m6b_r1_projection")
        (d / "user-settings/src/idor.rs").write_text(
            "pub fn idor() -> &'static str {\n"
            '    "SELECT user_id, body FROM user_signatures WHERE id = $1"\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "6b. R1_MISSING_PREDICATE (projection-only SELECT user_id WHERE id = $1)",
            run_guard(m, s, d),
            "R1_MISSING_PREDICATE",
        )
        data = json.loads(m.read_text(encoding="utf-8"))
        data["r1_r3_allowlist"].append(
            {
                "file": "server-rust/crates/domains/user-settings/src/idor.rs",
                "table": "user_signatures",
                "reason": "selftest allowlist control",
            }
        )
        m.write_text(json.dumps(data, indent=2), encoding="utf-8")
        assert_passes(
            "6c. r1_r3_allowlist allows explicitly listed (file, table)",
            run_guard(m, s, d),
        )

        # 6d. chat_channels FK chain `id -> ...` rejects bare `WHERE id = $1`
        m, s, d = build_base_fixture(root / "m6d_chat_id_bypass")
        (d / "chat/src/idor.rs").write_text(
            "pub fn bad_ch() -> &'static str {\n"
            '    "SELECT name FROM chat_channels WHERE id = $1"\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "6d. R1_MISSING_PREDICATE (chat_channels bare WHERE id = $1 rejected)",
            run_guard(m, s, d),
            "R1_MISSING_PREDICATE",
        )

        # 7a. R3_MISSING_PREDICATE (UPDATE with user_id in SET & RETURNING, not WHERE)
        m, s, d = build_base_fixture(root / "m7a_r3_update")
        (d / "user-settings/src/bad_upd.rs").write_text(
            "pub fn bad_upd() -> &'static str {\n"
            '    "UPDATE user_signatures SET user_id = $2, body = $3 '
            'WHERE id = $1 RETURNING user_id"\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "7a. R3_MISSING_PREDICATE (UPDATE missing ownership in WHERE)",
            run_guard(m, s, d),
            "R3_MISSING_PREDICATE",
        )

        # 7b. R3_MISSING_PREDICATE (DELETE missing ownership in WHERE)
        m, s, d = build_base_fixture(root / "m7b_r3_delete")
        (d / "jmap/src/bad_del.rs").write_text(
            "pub fn bad_del() -> &'static str {\n"
            '    "DELETE FROM messages WHERE id = $1"\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "7b. R3_MISSING_PREDICATE (DELETE missing ownership in WHERE)",
            run_guard(m, s, d),
            "R3_MISSING_PREDICATE",
        )

        # 8a. RLS_PENDING_RATCHET (new table using pending_wave1_cutover)
        m, s, d = build_base_fixture(root / "m8a_ratchet")
        (s / "V002__new_pending.sql").write_text(
            "CREATE TABLE public.brand_new_user_table "
            "(id bigint PRIMARY KEY, user_id bigint NOT NULL);\n",
            encoding="utf-8",
        )
        data = json.loads(m.read_text(encoding="utf-8"))
        data["tables"]["brand_new_user_table"] = {
            "owner": "identity",
            "security_class": "user_scoped",
            "rls_posture": "pending_wave1_cutover",
            "rls_tracking_issue": "#546",
            "rls_scope_column": "user_id",
            "read_contracts": [],
        }
        m.write_text(json.dumps(data, indent=2), encoding="utf-8")
        assert_fails_with(
            "8a. RLS_PENDING_RATCHET (new table using pending_wave1_cutover)",
            run_guard(m, s, d),
            "RLS_PENDING_RATCHET",
        )

        # 8b. RLS_PENDING_RATCHET (count exceeding legacy_rls_pending_ceiling)
        m, s, d = build_base_fixture(root / "m8b_ceiling")
        data = json.loads(m.read_text(encoding="utf-8"))
        data["legacy_rls_pending_ceiling"] = 0
        m.write_text(json.dumps(data, indent=2), encoding="utf-8")
        assert_fails_with(
            "8b. RLS_PENDING_RATCHET (count exceeds legacy_rls_pending_ceiling)",
            run_guard(m, s, d),
            "RLS_PENDING_RATCHET",
        )

        # 9a. STALE_PENDING_RLS (legacy pending table now has ENABLE+FORCE)
        m, s, d = build_base_fixture(root / "m9a_stale_pending")
        (s / "V002__fix_legacy.sql").write_text(
            "ALTER TABLE public.legacy_profiles ENABLE ROW LEVEL SECURITY;\n"
            "ALTER TABLE public.legacy_profiles FORCE ROW LEVEL SECURITY;\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "9a. STALE_PENDING_RLS (pending table already has ENABLE+FORCE)",
            run_guard(m, s, d),
            "STALE_PENDING_RLS: legacy_profiles",
        )

        # 9b. LEGACY_WRITE_RATCHET (exceeding legacy_write_migration_ceiling)
        m, s, d = build_base_fixture(root / "m9b_write_ratchet")
        data = json.loads(m.read_text(encoding="utf-8"))
        data["tables"]["drive_nodes"]["read_contracts"].append(
            {
                "consumer": "chat",
                "mode": "legacy_write_migration_pending",
                "reason": "selftest exceeding ceiling=0",
            }
        )
        m.write_text(json.dumps(data, indent=2), encoding="utf-8")
        assert_fails_with(
            "9b. LEGACY_WRITE_RATCHET (legacy write exceeds ceiling)",
            run_guard(m, s, d),
            "LEGACY_WRITE_RATCHET",
        )

        # 9c. Fail-closed exit 3 on unsupported RLS syntax (%s placeholder)
        m, s, d = build_base_fixture(root / "m9c_bad_rls_syntax")
        (s / "V002__bad_dyn.sql").write_text(
            "DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['messages'] LOOP "
            "EXECUTE format('ALTER TABLE public.%s FORCE ROW LEVEL SECURITY', t); "
            "END LOOP; END $$;\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "9c. fail-closed on unsupported dynamic RLS %s format",
            run_guard(m, s, d),
            "UNSUPPORTED",
            expected_rc=3,
        )

        # 9d. Fail-closed exit 3 on empty schema
        empty_s = root / "m9d_empty_schema"
        empty_s.mkdir(parents=True)
        (empty_s / "V001__empty.sql").write_text("-- nothing here\n", encoding="utf-8")
        assert_fails_with(
            "9d. fail-closed on zero extracted tables",
            run_guard(m, empty_s, d),
            "Zero logical tables",
            expected_rc=3,
        )

        # 10. Rust char literal `'"'` preceding SQL violation + `cr#"` C-string
        m, s, d = build_base_fixture(root / "m10_char_quote")
        (d / "calendar/src/quote_char.rs").write_text(
            "pub fn f() -> &'static str {\n"
            "    let _ = '\"';\n"
            "    let _ = b'\"';\n"
            '    "SELECT id FROM messages WHERE mailbox_id = $1"\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "10a. char literal '\"' does not invert subsequent SQL string",
            run_guard(m, s, d),
            "UNCONTRACTED_CROSS_DOMAIN_READ: calendar -> messages",
        )
        m, s, d = build_base_fixture(root / "m10b_cstr")
        (d / "calendar/src/cstr.rs").write_text(
            "pub fn f() {\n"
            '    let _ = cr#"SELECT id FROM messages WHERE mailbox_id = $1"#;\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            '10b. raw C-string cr#"..."# SQL is scanned',
            run_guard(m, s, d),
            "UNCONTRACTED_CROSS_DOMAIN_READ: calendar -> messages",
        )

        # 11. Domain `src/*.sql` (`include_str!`) scanning
        m, s, d = build_base_fixture(root / "m11_sql_file")
        (d / "guests/src/probe.sql").write_text(
            "SELECT id FROM messages WHERE mailbox_id = $1;\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "11. src/*.sql file scanned for uncontracted cross-domain read",
            run_guard(m, s, d),
            "UNCONTRACTED_CROSS_DOMAIN_READ: guests -> messages",
        )

        # 12a & 12b. Hardened #[cfg(test)] stripper ('{' char literal & string literal)
        m, s, d = build_base_fixture(root / "m12a_cfg_char")
        (d / "calendar/src/cfg_char.rs").write_text(
            "#[cfg(test)]\n"
            "fn h() { let _ = '{'; }\n"
            "pub fn prod() -> &'static str {\n"
            '    "SELECT id FROM messages WHERE mailbox_id = $1"\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "12a. #[cfg(test)] with '{' char literal does not swallow prod SQL",
            run_guard(m, s, d),
            "UNCONTRACTED_CROSS_DOMAIN_READ: calendar -> messages",
        )
        m, s, d = build_base_fixture(root / "m12b_cfg_in_str")
        (d / "calendar/src/cfg_str.rs").write_text(
            'pub const MARKER: &str = "#[cfg(test)]";\n'
            "pub fn prod() -> &'static str {\n"
            '    "SELECT id FROM messages WHERE mailbox_id = $1"\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            '12b. "#[cfg(test)]" inside string literal does not swallow prod SQL',
            run_guard(m, s, d),
            "UNCONTRACTED_CROSS_DOMAIN_READ: calendar -> messages",
        )

        # 13a, 13b, 13c. Comma-join, DELETE ... USING, double-quoted table identifier
        m, s, d = build_base_fixture(root / "m13a_comma_join")
        (d / "calendar/src/comma.rs").write_text(
            "pub fn q() -> &'static str {\n"
            '    "SELECT m.id FROM system_config c, messages m '
            'WHERE m.mailbox_id = $1"\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "13a. comma-join FROM a, messages caught",
            run_guard(m, s, d),
            "UNCONTRACTED_CROSS_DOMAIN_READ: calendar -> messages",
        )
        m, s, d = build_base_fixture(root / "m13b_del_using")
        (d / "chat/src/del_using.rs").write_text(
            "pub fn q() -> &'static str {\n"
            '    "DELETE FROM chat_channels c USING messages m '
            'WHERE c.id = m.id AND m.mailbox_id = $1"\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "13b. DELETE ... USING messages caught",
            run_guard(m, s, d),
            "UNCONTRACTED_CROSS_DOMAIN_READ: chat -> messages",
        )
        m, s, d = build_base_fixture(root / "m13c_quoted_ident")
        (d / "calendar/src/quoted.rs").write_text(
            "pub fn q() -> &'static str {\n"
            '    "SELECT id FROM \\"messages\\" WHERE mailbox_id = $1"\n'
            "}\n",
            encoding="utf-8",
        )
        assert_fails_with(
            '13c. double-quoted "messages" identifier caught',
            run_guard(m, s, d),
            "UNCONTRACTED_CROSS_DOMAIN_READ: calendar -> messages",
        )

        # 14a. Comma-separated multi-action ALTER TABLE ... ENABLE ..., NO FORCE ...
        m, s, d = build_base_fixture(root / "m14a_comma_rls")
        (s / "V002__comma_rls.sql").write_text(
            "ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY, "
            "NO FORCE ROW LEVEL SECURITY;\n",
            encoding="utf-8",
        )
        assert_fails_with(
            "14a. comma-separated ENABLE ..., NO FORCE ... removes FORCE RLS",
            run_guard(m, s, d),
            "MISSING_FORCE_RLS: messages",
        )

        # 14b. Interleaved FORCE then RENAME TO preserves FORCE on renamed table
        m, s, d = build_base_fixture(root / "m14b_interleave_rename")
        (s / "V002__rename_after_force.sql").write_text(
            "CREATE TABLE public.tmp_scoped (id bigint PRIMARY KEY, user_id bigint);\n"
            "ALTER TABLE public.tmp_scoped ENABLE ROW LEVEL SECURITY;\n"
            "ALTER TABLE public.tmp_scoped FORCE ROW LEVEL SECURITY;\n"
            "ALTER TABLE public.tmp_scoped RENAME TO renamed_scoped;\n",
            encoding="utf-8",
        )
        data = json.loads(m.read_text(encoding="utf-8"))
        data["tables"]["renamed_scoped"] = {
            "owner": "identity",
            "security_class": "user_scoped",
            "rls_posture": "enforced",
            "rls_scope_column": "user_id",
            "read_contracts": [],
        }
        m.write_text(json.dumps(data, indent=2), encoding="utf-8")
        assert_passes(
            "14b. interleaved FORCE then RENAME TO transfers RLS state",
            run_guard(m, s, d),
        )

        # 14c. Single-quoted string literal containing ALTER TABLE ... FORCE is inert
        m, s, d = build_base_fixture(root / "m14c_string_rls_inert")
        (s / "V002__insert_rls_text.sql").write_text(
            "CREATE TABLE public.unforced_tbl "
            "(id bigint PRIMARY KEY, user_id bigint);\n"
            "INSERT INTO public.system_config (key, value) VALUES (\n"
            "  'doc',\n"
            "  'ALTER TABLE public.unforced_tbl ENABLE ROW LEVEL SECURITY; "
            "ALTER TABLE public.unforced_tbl FORCE ROW LEVEL SECURITY;'\n"
            ");\n",
            encoding="utf-8",
        )
        data = json.loads(m.read_text(encoding="utf-8"))
        data["tables"]["unforced_tbl"] = {
            "owner": "identity",
            "security_class": "user_scoped",
            "rls_posture": "enforced",
            "rls_scope_column": "user_id",
            "read_contracts": [],
        }
        m.write_text(json.dumps(data, indent=2), encoding="utf-8")
        assert_fails_with(
            "14c. RLS DDL inside INSERT string literal is ignored",
            run_guard(m, s, d),
            "MISSING_FORCE_RLS: unforced_tbl",
        )

    print("test-table-ownership-manifest.py: ALL selftest assertions passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
