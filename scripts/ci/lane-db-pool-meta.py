#!/usr/bin/env python3
"""Generate a self-contained SQL reset script from a schema-loaded template DB clone.

The generated SQL runs inside a single `psql -f` round-trip after each pooled test:
  1. Terminates any lingering backends on the slot database.
  2. Verifies a strict catalog + pg_db_role_setting + matview + prepared-xact + large-object
     fingerprint (any DDL/policy/trigger/grant/sequence-def/config drift raises an exception
     so the wrapper falls back to DROP + CREATE DATABASE ... TEMPLATE).
  3. Synchronously detects every initially-empty leaf table whose main heap fork grew
     (`pg_relation_size(oid, 'main') > 0`) and truncates them in one statement.
  4. Verifies every seed table (tables with rows in the template) still matches its exact
     row count and deterministic content md5 (running after TRUNCATE also catches any
     accidental CASCADE into a seed table).
  5. Restores any sequence whose `last_value` drifted back to its template baseline.

No schema objects are ever created inside the slot database itself.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# Single source of truth for the catalog fingerprint expression used during both
# template capture and post-test slot verification. Uses order-independent
# count + 64-bit bit_xor(hashtextextended(...)) + sum(...) to avoid sort/string
# allocation overhead while remaining strictly sensitive to any catalog change.
CATALOG_FP_EXPR = """md5(concat_ws(E'\\n',
  'ns:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      oid::text || '|' || nspname || '|' || nspowner::text || '|' || coalesce(nspacl::text, ''), 1
    )), 0)::text
    FROM pg_namespace
    WHERE nspname NOT IN ('pg_catalog', 'information_schema')
      AND nspname NOT LIKE 'pg_toast%'
      AND nspname NOT LIKE 'pg_temp_%'
  ),
  'cls:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      c.oid::text || '|' || c.relname || '|' || c.relnamespace::text || '|' || c.relkind::text
      || '|' || c.relpersistence::text || '|' || c.relrowsecurity::text || '|' || c.relforcerowsecurity::text
      || '|' || c.relispopulated::text || '|' || c.relhasindex::text || '|' || c.relhasrules::text
      || '|' || c.relhastriggers::text || '|' || c.relchecks::text || '|' || c.relnatts::text
      || '|' || c.relowner::text || '|' || coalesce(c.relacl::text, ''), 2
    )), 0)::text
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND n.nspname NOT LIKE 'pg_temp_%'
  ),
  'att:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      a.attrelid::text || '|' || a.attnum::text || '|' || a.attname || '|' || a.atttypid::text
      || '|' || a.atttypmod::text || '|' || a.attnotnull::text || '|' || a.attisdropped::text, 3
    )), 0)::text
    FROM pg_attribute a
    JOIN pg_class c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE a.attnum > 0
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND n.nspname NOT LIKE 'pg_temp_%'
  ),
  'def:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      d.adrelid::text || '|' || d.adnum::text || '|' || coalesce(d.adbin::text, ''), 4
    )), 0)::text
    FROM pg_attrdef d
    JOIN pg_class c ON c.oid = d.adrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND n.nspname NOT LIKE 'pg_temp_%'
  ),
  'idx:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      i.indexrelid::text || '|' || i.indrelid::text || '|' || i.indisunique::text
      || '|' || i.indisprimary::text || '|' || i.indisvalid::text, 5
    )), 0)::text
    FROM pg_index i
    JOIN pg_class c ON c.oid = i.indrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND n.nspname NOT LIKE 'pg_temp_%'
  ),
  'con:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      con.oid::text || '|' || con.conname || '|' || con.conrelid::text
      || '|' || con.contype::text || '|' || con.convalidated::text || '|' || con.condeferrable::text, 6
    )), 0)::text
    FROM pg_constraint con
    JOIN pg_namespace n ON n.oid = con.connamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND n.nspname NOT LIKE 'pg_temp_%'
  ),
  'seq:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      sq.seqrelid::text || '|' || sq.seqtypid::text || '|' || sq.seqstart::text
      || '|' || sq.seqincrement::text || '|' || sq.seqmax::text || '|' || sq.seqmin::text
      || '|' || sq.seqcache::text || '|' || sq.seqcycle::text, 7
    )), 0)::text
    FROM pg_sequence sq
    JOIN pg_class c ON c.oid = sq.seqrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND n.nspname NOT LIKE 'pg_temp_%'
  ),
  'proc:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      p.oid::text || '|' || p.proname || '|' || p.pronamespace::text || '|' || p.proowner::text
      || '|' || p.proargtypes::text || '|' || p.prorettype::text || '|' || p.prosecdef::text
      || '|' || hashtextextended(coalesce(p.prosrc, ''), 17)::text || '|' || coalesce(p.proacl::text, ''), 8
    )), 0)::text
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND n.nspname NOT LIKE 'pg_temp_%'
  ),
  'trg:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      t.oid::text || '|' || t.tgrelid::text || '|' || t.tgname || '|' || t.tgfoid::text
      || '|' || t.tgenabled::text || '|' || t.tgtype::text, 9
    )), 0)::text
    FROM pg_trigger t
    JOIN pg_class c ON c.oid = t.tgrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE NOT t.tgisinternal
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND n.nspname NOT LIKE 'pg_temp_%'
  ),
  'pol:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      pol.oid::text || '|' || pol.polname || '|' || pol.polrelid::text || '|' || pol.polcmd::text
      || '|' || pol.polpermissive::text || '|' || pol.polroles::text
      || '|' || coalesce(pol.polqual::text, '') || '|' || coalesce(pol.polwithcheck::text, ''), 10
    )), 0)::text
    FROM pg_policy pol
  ),
  'ext:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      oid::text || '|' || extname || '|' || extnamespace::text || '|' || extversion, 11
    )), 0)::text
    FROM pg_extension
  ),
  'typ:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      t.oid::text || '|' || t.typname || '|' || t.typnamespace::text
      || '|' || t.typtype::text || '|' || t.typowner::text, 12
    )), 0)::text
    FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND n.nspname NOT LIKE 'pg_temp_%'
  ),
  'enum:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      e.enumtypid::text || '|' || e.enumsortorder::text || '|' || e.enumlabel, 13
    )), 0)::text
    FROM pg_enum e
  ),
  'evtrg:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      oid::text || '|' || evtname || '|' || evtenabled::text, 14
    )), 0)::text
    FROM pg_event_trigger
  ),
  'pub:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      oid::text || '|' || pubname, 15
    )), 0)::text
    FROM pg_publication
  ),
  'dbrs:' || (
    SELECT count(*)::text || ':' || coalesce(bit_xor(hashtextextended(
      setrole::text || '|' || coalesce(setconfig::text, ''), 16
    )), 0)::text
    FROM pg_db_role_setting
    WHERE setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database())
  ),
  'lo:' || (SELECT count(*)::text FROM pg_largeobject_metadata),
  'px:' || (SELECT count(*)::text FROM pg_prepared_xacts WHERE database = current_database()),
  'mvsz:' || (
    SELECT count(*)::text || ':' || coalesce(sum(pg_relation_size(c.oid, 'main')), 0)::text
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'm'
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND n.nspname NOT LIKE 'pg_temp_%'
  )
))"""

CAPTURE_SQL = f"""
SET TimeZone = 'UTC';
SET DateStyle = 'ISO, MDY';
SET search_path = public, pg_catalog;

BEGIN;
CREATE TEMP TABLE _pool_meta_tables (
  oid oid NOT NULL,
  fqname text NOT NULL,
  row_count bigint NOT NULL,
  row_md5 text NOT NULL
) ON COMMIT DROP;

DO $capture$
DECLARE
  r record;
  v_cnt bigint;
  v_md5 text;
BEGIN
  FOR r IN
    SELECT c.oid, format('%I.%I', n.nspname, c.relname) AS fqname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND n.nspname NOT LIKE 'pg_temp_%'
      AND c.relkind = 'r'
    ORDER BY c.oid
  LOOP
    EXECUTE format(
      'SELECT count(*), md5(coalesce(string_agg(t::text, E''\\n'' ORDER BY t::text), '''')) FROM %s t',
      r.fqname
    ) INTO v_cnt, v_md5;
    INSERT INTO _pool_meta_tables VALUES (r.oid, r.fqname, v_cnt, v_md5);
  END LOOP;
END
$capture$;

SELECT json_build_object(
  'catalog_fp', ({CATALOG_FP_EXPR}),
  'trunc_empty_oids', coalesce((
    WITH RECURSIVE
    seed_tbls AS (SELECT oid FROM _pool_meta_tables WHERE row_count > 0),
    fk_edges AS (
      SELECT confrelid AS parent_oid, conrelid AS child_oid
      FROM pg_constraint
      WHERE contype = 'f' AND confrelid <> conrelid
    ),
    blocked(oid) AS (
      SELECT oid FROM seed_tbls
      UNION
      SELECT e.parent_oid FROM fk_edges e JOIN blocked b ON e.child_oid = b.oid
    )
    SELECT json_agg(t.oid ORDER BY t.oid)
    FROM _pool_meta_tables t
    WHERE t.row_count = 0 AND t.oid NOT IN (SELECT oid FROM blocked)
  ), '[]'::json),
  'delete_empty_oids', coalesce((
    WITH RECURSIVE
    seed_tbls AS (SELECT oid FROM _pool_meta_tables WHERE row_count > 0),
    fk_edges AS (
      SELECT confrelid AS parent_oid, conrelid AS child_oid
      FROM pg_constraint
      WHERE contype = 'f' AND confrelid <> conrelid
    ),
    blocked(oid) AS (
      SELECT oid FROM seed_tbls
      UNION
      SELECT e.parent_oid FROM fk_edges e JOIN blocked b ON e.child_oid = b.oid
    )
    SELECT json_agg(t.oid ORDER BY t.oid)
    FROM _pool_meta_tables t
    WHERE t.row_count = 0 AND t.oid IN (SELECT oid FROM blocked)
  ), '[]'::json),
  'seed_tables', coalesce((
    SELECT json_agg(json_build_object('fqname', fqname, 'count', row_count, 'md5', row_md5) ORDER BY fqname)
    FROM _pool_meta_tables WHERE row_count > 0
  ), '[]'::json),
  'template_domain_ids', coalesce((
    SELECT json_agg(id ORDER BY id) FROM public.domains
  ), '[]'::json),
  'sequences', coalesce((
    SELECT json_agg(json_build_object(
      'schemaname', schemaname,
      'sequencename', sequencename,
      'last_value', last_value,
      'start_value', start_value
    ) ORDER BY schemaname, sequencename)
    FROM pg_sequences
    WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
      AND schemaname NOT LIKE 'pg_toast%'
      AND schemaname NOT LIKE 'pg_temp_%'
  ), '[]'::json)
)::text;
COMMIT;
"""


def sql_lit(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def render_reset_sql(meta: dict) -> str:
    fp = meta["catalog_fp"]
    if not isinstance(fp, str) or not re.fullmatch(r"[0-9a-f]{32}", fp):
        raise ValueError(f"invalid catalog fingerprint: {fp!r}")

    trunc_oids = [int(oid) for oid in meta["trunc_empty_oids"]]
    trunc_array = f"ARRAY[{','.join(str(o) for o in trunc_oids)}]::oid[]" if trunc_oids else "ARRAY[]::oid[]"
    delete_oids = [int(oid) for oid in meta["delete_empty_oids"]]
    delete_array = f"ARRAY[{','.join(str(o) for o in delete_oids)}]::oid[]" if delete_oids else "ARRAY[]::oid[]"
    domain_ids = [int(did) for did in meta.get("template_domain_ids", [])]
    domain_id_array = f"ARRAY[{','.join(str(d) for d in domain_ids)}]::bigint[]" if domain_ids else "ARRAY[]::bigint[]"

    seed_rows = []
    for item in meta["seed_tables"]:
        fqname = str(item["fqname"])
        cnt = int(item["count"])
        digest = str(item["md5"])
        if not re.fullmatch(r"[0-9a-f]{32}", digest):
            raise ValueError(f"invalid seed md5 for {fqname}: {digest!r}")
        seed_rows.append(f"      ({sql_lit(fqname)}, {cnt}::bigint, {sql_lit(digest)})")

    seq_rows = []
    for item in meta["sequences"]:
        schema = str(item["schemaname"])
        name = str(item["sequencename"])
        last_val = "NULL::bigint" if item["last_value"] is None else f"{int(item['last_value'])}::bigint"
        start_val = f"{int(item['start_value'])}::bigint"
        seq_rows.append(f"      ({sql_lit(schema)}, {sql_lit(name)}, {last_val}, {start_val})")

    lines = [
        "-- Auto-generated by scripts/ci/lane-db-pool-meta.py; do not edit.",
        "SET lock_timeout = '5s';",
        "SET statement_timeout = '15s';",
        "SET TimeZone = 'UTC';",
        "SET DateStyle = 'ISO, MDY';",
        "SET search_path = public, pg_catalog;",
        "",
        "DO $pool_reset$",
        "DECLARE",
        "  v_fp text;",
        "  v_dirty text[];",
        "  v_del record;",
        "  v_rec record;",
        "  v_cnt bigint;",
        "  v_md5 text;",
        "  v_seq record;",
        "BEGIN",
        "  PERFORM pg_terminate_backend(pid, 5000)",
        "  FROM pg_stat_activity",
        "  WHERE datname = current_database() AND pid <> pg_backend_pid();",
        "",
        "  IF EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()) THEN",
        "    RAISE EXCEPTION 'pool_reset_drift: lingering backend did not terminate';",
        "  END IF;",
        "",
        f"  SELECT {CATALOG_FP_EXPR} INTO v_fp;",
        f"  IF v_fp <> {sql_lit(fp)} THEN",
        f"    RAISE EXCEPTION 'pool_reset_drift: catalog fingerprint mismatch (got %, expected %)', v_fp, {sql_lit(fp)};",
        "  END IF;",
        "",
        "  -- Truncate dirty initially-empty tables that are not FK-referenced by any seed table",
        "  -- (resets heap to 0 bytes without cascading into seed tables).",
        "  SELECT array_agg(format('%I.%I', n.nspname, c.relname) ORDER BY n.nspname, c.relname)",
        "  INTO v_dirty",
        "  FROM pg_class c",
        "  JOIN pg_namespace n ON n.oid = c.relnamespace",
        f"  WHERE c.oid = ANY({trunc_array})",
        "    AND pg_relation_size(c.oid, 'main') > 0;",
        "",
        "  IF v_dirty IS NOT NULL AND array_length(v_dirty, 1) > 0 THEN",
        "    SET LOCAL session_replication_role = 'replica';",
        "    EXECUTE 'TRUNCATE TABLE ' || array_to_string(v_dirty, ', ') || ' CASCADE';",
        "    RESET session_replication_role;",
        "  END IF;",
        "",
        "  -- Clear dirty initially-empty tables that have an inbound FK from a seed table via",
        "  -- DELETE (so TRUNCATE CASCADE never wipes seed rows); re-clone if heap ever exceeds 4 MiB.",
        "  FOR v_del IN",
        "    SELECT format('%I.%I', n.nspname, c.relname) AS fqname, pg_relation_size(c.oid, 'main') AS sz",
        "    FROM pg_class c",
        "    JOIN pg_namespace n ON n.oid = c.relnamespace",
        f"    WHERE c.oid = ANY({delete_array})",
        "      AND pg_relation_size(c.oid, 'main') > 0",
        "    ORDER BY c.oid",
        "  LOOP",
        "    IF v_del.sz > 4194304 THEN",
        "      RAISE EXCEPTION 'pool_reset_drift: seed-referenced table % exceeded 4 MiB (%)', v_del.fqname, v_del.sz;",
        "    END IF;",
        "    SET LOCAL session_replication_role = 'replica';",
        "    EXECUTE format('DELETE FROM %s', v_del.fqname);",
        "    RESET session_replication_role;",
        "  END LOOP;",
    ]

    if domain_ids:
        lines.extend([
            "",
            "  -- Remove test-created throwaway rows from public.domains (e.g. mk_account's mk.test)",
            "  -- while preserving template seed rows; exact count+md5 verification below still catches",
            "  -- any update/delete to the template seed domain(s).",
            f"  IF EXISTS (SELECT 1 FROM public.domains WHERE id <> ALL({domain_id_array})) THEN",
            "    SET LOCAL session_replication_role = 'replica';",
            f"    DELETE FROM public.domains WHERE id <> ALL({domain_id_array});",
            "    RESET session_replication_role;",
            "  END IF;",
        ])

    if seed_rows:
        lines.extend([
            "",
            "  FOR v_rec IN",
            "    SELECT tbl, expected_cnt, expected_md5",
            "    FROM (VALUES",
            ",\n".join(seed_rows),
            "    ) AS s(tbl, expected_cnt, expected_md5)",
            "  LOOP",
            "    EXECUTE format(",
            "      'SELECT count(*), md5(coalesce(string_agg(t::text, E''\\n'' ORDER BY t::text), '''')) FROM %s t',",
            "      v_rec.tbl",
            "    ) INTO v_cnt, v_md5;",
            "    IF v_cnt <> v_rec.expected_cnt OR v_md5 <> v_rec.expected_md5 THEN",
            "      RAISE EXCEPTION 'pool_reset_drift: seed table % drifted (rows % vs %, md5 % vs %)',",
            "        v_rec.tbl, v_cnt, v_rec.expected_cnt, v_md5, v_rec.expected_md5;",
            "    END IF;",
            "  END LOOP;",
        ])

    if seq_rows:
        lines.extend([
            "",
            "  FOR v_seq IN",
            "    SELECT s.schemaname, s.sequencename, e.exp_val, e.start_val",
            "    FROM (VALUES",
            ",\n".join(seq_rows),
            "    ) AS e(schemaname, sequencename, exp_val, start_val)",
            "    JOIN pg_sequences s",
            "      ON s.schemaname = e.schemaname AND s.sequencename = e.sequencename",
            "    WHERE s.last_value IS DISTINCT FROM e.exp_val",
            "  LOOP",
            "    IF v_seq.exp_val IS NULL THEN",
            "      PERFORM setval(format('%I.%I', v_seq.schemaname, v_seq.sequencename), v_seq.start_val, false);",
            "    ELSE",
            "      PERFORM setval(format('%I.%I', v_seq.schemaname, v_seq.sequencename), v_seq.exp_val, true);",
            "    END IF;",
            "  END LOOP;",
        ])

    lines.extend([
        "END",
        "$pool_reset$;",
        "",
    ])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", required=True, help="Superuser DSN pointing at a freshly cloned template DB (e.g. slot_0)")
    parser.add_argument("--out", type=Path, required=True, help="Output path for the generated SQL reset script")
    args = parser.parse_args()

    res = subprocess.run(
        ["psql", args.dsn, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1"],
        input=CAPTURE_SQL,
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        sys.exit(f"lane-db-pool-meta: psql capture failed:\n{res.stdout}{res.stderr}")

    payload = next((line for line in reversed(res.stdout.splitlines()) if line.strip().startswith("{")), "")
    if not payload:
        sys.exit(f"lane-db-pool-meta: empty JSON metadata from psql:\n{res.stdout}{res.stderr}")

    meta = json.loads(payload)
    reset_sql = render_reset_sql(meta)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = args.out.with_suffix(args.out.suffix + ".tmp")
    tmp_path.write_text(reset_sql)
    tmp_path.replace(args.out)
    print(
        f"lane-db-pool-meta: captured fp={meta['catalog_fp'][:12]} "
        f"trunc_empty={len(meta['trunc_empty_oids'])} delete_empty={len(meta['delete_empty_oids'])} "
        f"seed={len(meta['seed_tables'])} sequences={len(meta['sequences'])}"
    )


if __name__ == "__main__":
    main()
