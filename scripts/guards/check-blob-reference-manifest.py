#!/usr/bin/env python3
"""Static blob-reference manifest and SQL catalog parity guard (Issue #550).

Enforces 5 named invariants over mailserver/sql/dbschema/V*.sql,
config/blob-reference-manifest.json, and mailserver/sql/reducers/blob_gc.sql:
  1. DUPLICATE_MANIFEST_ENTRY   - no (table, column) appears twice in manifest
  2. UNMANIFESTED_BLOB_COLUMN   - every candidate blob/sha256/ref/key column classified
  3. STALE_MANIFEST_ENTRY       - every manifest entry exists in final replayed schema
  4. FK_NOT_LIVE_ROOT           - every FK referencing blobs(sha256) is in live_roots
                                  (or allowed blobs_internal bookkeeping tables)
  5. SQL_CATALOG_DRIFT          - comment-stripped blob_has_live_reference() roots equal
                                  manifest.live_roots bidirectionally

Environment overrides (used by selftests and unit tests):
  BLOB_MANIFEST       Path to blob-reference-manifest.json
  BLOB_SCHEMA_DIR     Path to V*.sql migrations directory
  BLOB_GC_SQL_FILE    Path to mailserver/sql/reducers/blob_gc.sql
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

CATEGORIES: Tuple[str, ...] = (
    "live_roots",
    "blobs_internal",
    "separate_storage_plane",
    "non_blob_digest",
)

# Candidate column names that could hold a blob hash, S3 ref, or SHA-256 digest.
# Pure integer counter columns (e.g., blob_count, blobs_copied, total_blobs) are
# excluded by SQL column type (only text/varchar/char/bytea/jsonb/json/citext).
CANDIDATE_COL_RE = re.compile(
    r"(sha256|blob|minio|raw_ref|object_ref|object_key|storage_ref|storage_key|"
    r"export_ref|report_ref|avatar|staging_key|snapshot_ref|artifact_ref|"
    r"content_ref|s3_key)",
    re.I,
)
CANDIDATE_TYPE_RE = re.compile(
    r"^(?:text|character\s+varying|varchar|char(?:acter)?|bytea|jsonb|json|citext)\b",
    re.I,
)

# Tables under blobs_internal that legitimately hold an FK to public.blobs(sha256)
# without being a live retention root (bookkeeping / GC state / legacy queue).
BLOBS_INTERNAL_FK_ALLOWED: Set[Tuple[str, str]] = {
    ("blob_user_charges", "blob_sha256"),
    ("blob_gc_state", "blob_sha256"),
}

_SQL_KEYWORDS: Set[str] = {
    "where",
    "join",
    "inner",
    "left",
    "right",
    "full",
    "cross",
    "natural",
    "on",
    "using",
    "group",
    "order",
    "having",
    "limit",
    "offset",
    "and",
    "or",
    "not",
    "as",
    "lateral",
    "select",
    "from",
    "exists",
    "union",
    "intersect",
    "except",
}


def migration_sort_key(path: Path) -> Tuple[int, str]:
    m = re.match(r"^V0*([0-9]+)", path.name)
    return (int(m.group(1)) if m else 0, path.name)


def strip_sql_comments(sql: str, strip_inside_dollar: bool = True) -> str:
    """Strip -- line comments and nested /* ... */ block comments.

    Preserves single-quoted string literals and double-quoted identifiers.
    """
    out: List[str] = []
    i = 0
    n = len(sql)
    comment_depth = 0
    in_sq = False
    in_dq = False
    dollar_tag: Optional[str] = None

    while i < n:
        c = sql[i]
        two = sql[i : i + 2]

        if comment_depth > 0:
            if two == "/*":
                comment_depth += 1
                i += 2
            elif two == "*/":
                comment_depth -= 1
                i += 2
                if comment_depth == 0:
                    out.append(" ")
            else:
                if c == "\n":
                    out.append("\n")
                i += 1
            continue

        if in_sq:
            out.append(c)
            if c == "'":
                if i + 1 < n and sql[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                in_sq = False
            i += 1
            continue

        if in_dq:
            out.append(c)
            if c == '"':
                if i + 1 < n and sql[i + 1] == '"':
                    out.append('"')
                    i += 2
                    continue
                in_dq = False
            i += 1
            continue

        if dollar_tag is not None:
            if sql.startswith(dollar_tag, i):
                out.append(dollar_tag)
                i += len(dollar_tag)
                dollar_tag = None
                continue
            if strip_inside_dollar:
                if two == "--":
                    j = sql.find("\n", i)
                    if j == -1:
                        break
                    out.append("\n")
                    i = j + 1
                    continue
                if two == "/*":
                    comment_depth = 1
                    i += 2
                    continue
            if c == "'":
                in_sq = True
                out.append(c)
                i += 1
                continue
            out.append(c)
            i += 1
            continue

        if two == "--":
            j = sql.find("\n", i)
            if j == -1:
                break
            out.append("\n")
            i = j + 1
            continue

        if two == "/*":
            comment_depth = 1
            i += 2
            continue

        if c == "'":
            in_sq = True
            out.append(c)
            i += 1
            continue

        if c == '"':
            in_dq = True
            out.append(c)
            i += 1
            continue

        if c == "$":
            m = re.match(r"\$[a-zA-Z_][a-zA-Z0-9_]*\$|\$\$", sql[i:])
            if m:
                dollar_tag = m.group(0)
                out.append(dollar_tag)
                i += len(dollar_tag)
                continue

        out.append(c)
        i += 1

    return "".join(out)


def _split_top_level_commas(body: str) -> List[str]:
    parts: List[str] = []
    buf: List[str] = []
    depth = 0
    in_sq = False
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if in_sq:
            buf.append(c)
            if c == "'":
                if i + 1 < n and body[i + 1] == "'":
                    buf.append("'")
                    i += 2
                    continue
                in_sq = False
            i += 1
            continue
        if c == "'":
            in_sq = True
            buf.append(c)
        elif c == "(":
            depth += 1
            buf.append(c)
        elif c == ")":
            depth -= 1
            buf.append(c)
        elif c == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(c)
        i += 1
    if buf:
        parts.append("".join(buf).strip())
    return parts


def replay_schema(
    schema_dir: Path,
) -> Tuple[Dict[str, Dict[str, str]], Set[Tuple[str, str]]]:
    """Replay V*.sql migrations in numeric order.

    Returns:
      tables: logical_table -> {column_name: column_def}
      fks_to_blobs: set of (table, column) having FK REFERENCES public.blobs
    """
    migs = sorted(schema_dir.glob("V*.sql"), key=migration_sort_key)
    if not migs:
        raise RuntimeError(f"no V*.sql migrations found under {schema_dir}")

    tables: Dict[str, Dict[str, str]] = {}
    partition_children: Set[str] = set()
    fks_to_blobs: Set[Tuple[str, str]] = set()

    create_part_re = re.compile(
        r"\bCREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
        r'(?:public\.)?("?[a-zA-Z_][a-zA-Z0-9_]*"?)\s+PARTITION\s+OF\b',
        re.I,
    )
    create_tbl_re = re.compile(
        r"\bCREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
        r'(?:public\.)?("?[a-zA-Z_][a-zA-Z0-9_]*"?)\s*\(',
        re.I,
    )
    alter_tbl_re = re.compile(
        r"\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?"
        r'(?:public\.)?("?[a-zA-Z_][a-zA-Z0-9_]*"?)\s+([^;]+);',
        re.I,
    )
    drop_tbl_re = re.compile(
        r"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?"
        r'(?:public\.)?("?[a-zA-Z_][a-zA-Z0-9_]*"?)',
        re.I,
    )
    fk_inline_re = re.compile(r"\bREFERENCES\s+(?:public\.)?blobs\b", re.I)
    fk_table_re = re.compile(
        r'FOREIGN\s+KEY\s*\(\s*("?[a-zA-Z_][a-zA-Z0-9_]*"?)\s*\)\s*'
        r"REFERENCES\s+(?:public\.)?blobs\b",
        re.I,
    )

    for mig in migs:
        raw = strip_sql_comments(mig.read_text(encoding="utf-8"))

        for m in create_part_re.finditer(raw):
            partition_children.add(m.group(1).strip('"').lower())

        for m in create_tbl_re.finditer(raw):
            tname = m.group(1).strip('"').lower()
            pos = m.end()
            depth = 1
            in_sq = False
            n = len(raw)
            while pos < n and depth > 0:
                c = raw[pos]
                if in_sq:
                    if c == "'":
                        if pos + 1 < n and raw[pos + 1] == "'":
                            pos += 2
                            continue
                        in_sq = False
                    pos += 1
                    continue
                if c == "'":
                    in_sq = True
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                pos += 1
            body = raw[m.end() : pos - 1]
            cols = tables.setdefault(tname, {})
            for item in _split_top_level_commas(body):
                if not item:
                    continue
                first = item.split()[0].lower()
                if first in (
                    "constraint",
                    "primary",
                    "unique",
                    "check",
                    "foreign",
                    "exclude",
                    "like",
                ):
                    fk_m = fk_table_re.search(item)
                    if fk_m:
                        fks_to_blobs.add((tname, fk_m.group(1).strip('"').lower()))
                    continue
                col_m = re.match(r'^("?[a-zA-Z_][a-zA-Z0-9_]*"?)\s+(.+)$', item, re.S)
                if col_m:
                    cname = col_m.group(1).strip('"').lower()
                    cdef = " ".join(col_m.group(2).split())
                    cols[cname] = cdef
                    if fk_inline_re.search(cdef):
                        fks_to_blobs.add((tname, cname))

        for m in alter_tbl_re.finditer(raw):
            tname = m.group(1).strip('"').lower()
            clause = m.group(2)
            for pm in re.finditer(
                r'\bATTACH\s+PARTITION\s+(?:public\.)?("?[a-zA-Z_][a-zA-Z0-9_]*"?)',
                clause,
                re.I,
            ):
                partition_children.add(pm.group(1).strip('"').lower())
            for am in re.finditer(
                r"\bADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"
                r'("?[a-zA-Z_][a-zA-Z0-9_]*"?)\s+([a-zA-Z][^,]*)',
                clause,
                re.I,
            ):
                cname = am.group(1).strip('"').lower()
                if cname in (
                    "constraint",
                    "primary",
                    "unique",
                    "check",
                    "foreign",
                    "exclude",
                ):
                    continue
                cdef = " ".join(am.group(2).split())
                tables.setdefault(tname, {})[cname] = cdef
                if fk_inline_re.search(cdef):
                    fks_to_blobs.add((tname, cname))
            for dm in re.finditer(
                r'\bDROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?("?[a-zA-Z_][a-zA-Z0-9_]*"?)',
                clause,
                re.I,
            ):
                cname = dm.group(1).strip('"').lower()
                if tname in tables:
                    tables[tname].pop(cname, None)
                fks_to_blobs.discard((tname, cname))
            for rm in re.finditer(
                r"\bRENAME\s+(?:COLUMN\s+)?"
                r'("?[a-zA-Z_][a-zA-Z0-9_]*"?)\s+TO\s+("?[a-zA-Z_][a-zA-Z0-9_]*"?)',
                clause,
                re.I,
            ):
                old_col = rm.group(1).strip('"').lower()
                new_col = rm.group(2).strip('"').lower()
                if old_col in ("constraint", "to"):
                    continue
                if tname in tables and old_col in tables[tname]:
                    tables[tname][new_col] = tables[tname].pop(old_col)
                if (tname, old_col) in fks_to_blobs:
                    fks_to_blobs.discard((tname, old_col))
                    fks_to_blobs.add((tname, new_col))
            for fk_m in fk_table_re.finditer(clause):
                fks_to_blobs.add((tname, fk_m.group(1).strip('"').lower()))

        for m in drop_tbl_re.finditer(raw):
            tname = m.group(1).strip('"').lower()
            tables.pop(tname, None)
            fks_to_blobs = {pair for pair in fks_to_blobs if pair[0] != tname}

    for part in partition_children:
        tables.pop(part, None)
        fks_to_blobs = {pair for pair in fks_to_blobs if pair[0] != part}

    return tables, fks_to_blobs


def discover_candidate_columns(
    tables: Dict[str, Dict[str, str]],
    fks_to_blobs: Set[Tuple[str, str]],
) -> Set[Tuple[str, str]]:
    """Return every logical (table, column) that must be classified in the manifest."""
    candidates: Set[Tuple[str, str]] = set()
    for tname, cols in tables.items():
        for cname, cdef in cols.items():
            if (tname, cname) in fks_to_blobs:
                candidates.add((tname, cname))
                continue
            if CANDIDATE_COL_RE.search(cname) and CANDIDATE_TYPE_RE.match(cdef):
                candidates.add((tname, cname))
    return candidates


def extract_function_body(sql_text: str, func_name: str) -> str:
    """Extract the comment-stripped body strictly inside `func_name(...)`."""
    stripped = strip_sql_comments(sql_text, strip_inside_dollar=True)
    header_re = re.compile(
        r"\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+"
        rf'(?:public\.)?"?{re.escape(func_name)}"?\s*\(',
        re.I,
    )
    m = header_re.search(stripped)
    if not m:
        raise RuntimeError(f"function {func_name}() not found")
    rest = stripped[m.end() :]
    tag_m = re.search(r"\bAS\s+(\$[a-zA-Z_][a-zA-Z0-9_]*\$|\$\$)", rest, re.I)
    if not tag_m:
        raise RuntimeError(f"function {func_name}() has no dollar-quoted AS body")
    tag = tag_m.group(1)
    body_start = tag_m.end()
    body_end = rest.find(tag, body_start)
    if body_end == -1:
        raise RuntimeError(f"function {func_name}() dollar-quoted body is unterminated")
    return rest[body_start:body_end]


def _extract_balanced_parens(text: str, open_idx: int) -> Tuple[str, int]:
    """Return (inner_text, close_idx) for balanced '(' at open_idx."""
    depth = 1
    in_sq = False
    i = open_idx + 1
    n = len(text)
    while i < n and depth > 0:
        c = text[i]
        if in_sq:
            if c == "'":
                if i + 1 < n and text[i + 1] == "'":
                    i += 2
                    continue
                in_sq = False
            i += 1
            continue
        if c == "'":
            in_sq = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        i += 1
    return text[open_idx + 1 : i - 1], i


def extract_live_roots_from_sql(
    gc_sql_path: Path,
    tables: Dict[str, Dict[str, str]],
) -> Set[Tuple[str, str]]:
    """Parse comment-stripped blob_has_live_reference() for (table, column) roots."""
    body = extract_function_body(
        gc_sql_path.read_text(encoding="utf-8"),
        "blob_has_live_reference",
    )
    # Strip single-quoted string literals for identifier matching, while retaining
    # raw_body for JSONB key extraction checks (e.g. elem->>'sha256' = p_sha256).
    code = re.sub(r"'(?:[^']|'')*'", "''", body)

    roots: Set[Tuple[str, str]] = set()
    exists_re = re.compile(r"\bEXISTS\s*\(", re.I)
    from_re = re.compile(
        r'\bFROM\s+(?:public\.)?("?[a-zA-Z_][a-zA-Z0-9_]*"?)'
        r'(?:\s+(?:AS\s+)?("?[a-zA-Z_][a-zA-Z0-9_]*"?))?',
        re.I,
    )

    pos = 0
    raw_pos = 0
    while True:
        em = exists_re.search(code, pos)
        if not em:
            break
        subquery, next_pos = _extract_balanced_parens(code, em.end() - 1)
        pos = next_pos

        raw_em = exists_re.search(body, raw_pos)
        if raw_em:
            raw_subquery, raw_pos = _extract_balanced_parens(body, raw_em.end() - 1)
        else:
            raw_subquery = subquery

        fm = from_re.search(subquery)
        if not fm:
            continue
        tname = fm.group(1).strip('"').lower()
        # Skip system catalog checks (e.g., pg_roles in BYPASSRLS guard).
        if tname.startswith("pg_"):
            continue
        alias_raw = fm.group(2).strip('"').lower() if fm.group(2) else None
        alias = alias_raw if alias_raw and alias_raw not in _SQL_KEYWORDS else None

        qualifiers = [tname]
        if alias:
            qualifiers.append(alias)
        qual_pat = "|".join(re.escape(q) for q in qualifiers)

        # Match qualified `alias.col = p_sha256` or `p_sha256 = alias.col`
        eq_pat = re.compile(
            rf"\b(?:{qual_pat})\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*p_sha256\b|"
            rf"\bp_sha256\s*=\s*(?:{qual_pat})\.([a-zA-Z_][a-zA-Z0-9_]*)\b",
            re.I,
        )
        for cm in eq_pat.finditer(subquery):
            col = (cm.group(1) or cm.group(2)).lower()
            roots.add((tname, col))

        # Match bare `col = p_sha256` (when unqualified inside single-table EXISTS)
        if alias is None:
            bare_pat = re.compile(
                r"(?<!\.)\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*p_sha256\b|"
                r"\bp_sha256\s*=\s*(?<!\.)([a-zA-Z_][a-zA-Z0-9_]*)\b",
                re.I,
            )
            known_cols = set(tables.get(tname, {}).keys())
            for cm in bare_pat.finditer(subquery):
                col = (cm.group(1) or cm.group(2)).lower()
                if col in known_cols or not known_cols:
                    roots.add((tname, col))

        # Match JSONB array traversal paired with an actual digest comparison
        # on the element alias (e.g., elem->>'sha256' = p_sha256 or
        # elem->>'objectRef' = p_sha256), never merely array traversal.
        jsonb_pat = re.compile(
            rf"\bjsonb_array_elements\s*\(\s*(?:(?:{qual_pat})\.)?"
            r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\)"
            r"(?:\s+(?:AS\s+)?([a-zA-Z_][a-zA-Z0-9_]*))?",
            re.I,
        )
        for jm in jsonb_pat.finditer(raw_subquery):
            col = jm.group(1).lower()
            elem_alias = jm.group(2)
            if not elem_alias or elem_alias.lower() in _SQL_KEYWORDS:
                continue
            elem_pat = re.compile(
                rf"\b{re.escape(elem_alias)}\s*->>\s*'(?:sha256|objectRef)'"
                r"\s*=\s*p_sha256\b|"
                rf"\bp_sha256\s*=\s*{re.escape(elem_alias)}\s*->>\s*"
                r"'(?:sha256|objectRef)'",
                re.I,
            )
            if elem_pat.search(raw_subquery):
                roots.add((tname, col))

    return roots


def extract_live_catalog_roots_from_sql(
    gc_sql_path: Path,
    tables: Dict[str, Dict[str, str]],
) -> Set[Tuple[str, str]]:
    """Parse comment-stripped blob_live_catalog() UNION arms for (table, column) roots."""
    body = extract_function_body(
        gc_sql_path.read_text(encoding="utf-8"),
        "blob_live_catalog",
    )
    cte_m = re.search(r"\bWITH\s+live_shas\s*(?:\([^)]*\))?\s+AS\s*\(", body, re.I)
    if not cte_m:
        raise RuntimeError("blob_live_catalog() missing WITH live_shas AS (...) CTE")
    cte_body, _ = _extract_balanced_parens(body, cte_m.end() - 1)

    arms = re.split(r"\bUNION(?:\s+ALL)?\b", cte_body, flags=re.I)
    from_re = re.compile(
        r'\bFROM\s+(?:public\.)?("?[a-zA-Z_][a-zA-Z0-9_]*"?)'
        r'(?:\s+(?:AS\s+)?("?[a-zA-Z_][a-zA-Z0-9_]*"?))?',
        re.I,
    )
    roots: Set[Tuple[str, str]] = set()
    for arm in arms:
        fm = from_re.search(arm)
        if not fm:
            continue
        tname = fm.group(1).strip('"').lower()
        if tname.startswith("pg_"):
            continue
        alias_raw = fm.group(2).strip('"').lower() if fm.group(2) else None
        alias = alias_raw if alias_raw and alias_raw not in _SQL_KEYWORDS else None
        qualifiers = [tname]
        if alias:
            qualifiers.append(alias)
        qual_pat = "|".join(re.escape(q) for q in qualifiers)

        # Match JSONB array traversal paired with SELECT elem->>'sha256' or elem->>'objectRef'
        jsonb_pat = re.compile(
            rf"\bjsonb_array_elements\s*\(\s*(?:(?:{qual_pat})\.)?"
            r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\)"
            r"(?:\s+(?:AS\s+)?([a-zA-Z_][a-zA-Z0-9_]*))?",
            re.I,
        )
        matched_jsonb = False
        for jm in jsonb_pat.finditer(arm):
            col = jm.group(1).lower()
            elem_alias = jm.group(2)
            if not elem_alias or elem_alias.lower() in _SQL_KEYWORDS:
                continue
            sel_elem_pat = re.compile(
                rf"\bSELECT\b.*?\b{re.escape(elem_alias)}\s*->>\s*'(?:sha256|objectRef)'",
                re.I | re.S,
            )
            if sel_elem_pat.search(arm[: fm.start()]):
                roots.add((tname, col))
                matched_jsonb = True
        if matched_jsonb:
            continue

        # Match SELECT <alias>.<col> FROM ...
        select_clause = arm[: fm.start()]
        qual_col_pat = re.compile(
            rf"\b(?:{qual_pat})\.([a-zA-Z_][a-zA-Z0-9_]*)\b",
            re.I,
        )
        found_qual = False
        for cm in qual_col_pat.finditer(select_clause):
            roots.add((tname, cm.group(1).lower()))
            found_qual = True
        if not found_qual and alias is None:
            known_cols = set(tables.get(tname, {}).keys())
            bare_sel = re.search(r"\bSELECT\s+([a-zA-Z_][a-zA-Z0-9_]*)\b", select_clause, re.I)
            if bare_sel:
                col = bare_sel.group(1).lower()
                if col in known_cols or not known_cols:
                    roots.add((tname, col))
    return roots


def _find_latest_migration_with_function(schema_dir: Path, func_name: str) -> Optional[Path]:
    """Return the latest V*.sql migration defining `func_name()`."""
    header_re = re.compile(
        r"\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+"
        rf'(?:public\.)?"?{re.escape(func_name)}"?\s*\(',
        re.I,
    )
    latest: Optional[Path] = None
    for mig in sorted(schema_dir.glob("V*.sql"), key=migration_sort_key):
        stripped = strip_sql_comments(
            mig.read_text(encoding="utf-8"), strip_inside_dollar=True
        )
        if header_re.search(stripped):
            latest = mig
    return latest


def _find_latest_migration_with_live_ref(schema_dir: Path) -> Optional[Path]:
    """Return the latest V*.sql migration defining blob_has_live_reference()."""
    return _find_latest_migration_with_function(schema_dir, "blob_has_live_reference")


def validate(
    manifest_path: Path,
    schema_dir: Path,
    gc_sql_path: Path,
) -> Tuple[List[str], Dict[str, int]]:
    errors: List[str] = []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if manifest.get("schema_version") != 1:
        errors.append(
            f"INVALID_MANIFEST: schema_version must be 1, "
            f"got {manifest.get('schema_version')!r}"
        )

    tables, fks_to_blobs = replay_schema(schema_dir)
    candidates = discover_candidate_columns(tables, fks_to_blobs)

    seen: Dict[Tuple[str, str], str] = {}
    by_category: Dict[str, Set[Tuple[str, str]]] = {cat: set() for cat in CATEGORIES}

    for cat in CATEGORIES:
        entries = manifest.get(cat)
        if not isinstance(entries, list):
            errors.append(f"INVALID_MANIFEST: category {cat!r} must be a JSON array")
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                errors.append(f"INVALID_MANIFEST: non-object entry in {cat!r}")
                continue
            tname = str(entry.get("table", "")).strip().lower()
            cname = str(entry.get("column", "")).strip().lower()
            if not tname or not cname:
                errors.append(
                    f"INVALID_MANIFEST: entry missing table/column in {cat!r}: {entry}"
                )
                continue
            pair = (tname, cname)
            if pair in seen:
                errors.append(
                    f"DUPLICATE_MANIFEST_ENTRY: {tname}.{cname} appears in both "
                    f"{seen[pair]} and {cat}"
                )
            else:
                seen[pair] = cat
            by_category[cat].add(pair)

    all_manifested = set(seen.keys())

    # 1. UNMANIFESTED_BLOB_COLUMN
    for tname, cname in sorted(candidates - all_manifested):
        errors.append(
            f"UNMANIFESTED_BLOB_COLUMN: {tname}.{cname} is a candidate blob/hash/ref "
            "column not classified in config/blob-reference-manifest.json"
        )

    # 2. STALE_MANIFEST_ENTRY
    for tname, cname in sorted(all_manifested):
        if tname not in tables or cname not in tables[tname]:
            errors.append(
                f"STALE_MANIFEST_ENTRY: {tname}.{cname} (in {seen[(tname, cname)]}) "
                "does not exist in the replayed SQL schema"
            )

    # 3. FK_NOT_LIVE_ROOT
    live_roots = by_category["live_roots"]
    for tname, cname in sorted(fks_to_blobs):
        pair = (tname, cname)
        if pair in live_roots:
            continue
        if pair in BLOBS_INTERNAL_FK_ALLOWED and seen.get(pair) == "blobs_internal":
            continue
        errors.append(
            f"FK_NOT_LIVE_ROOT: {tname}.{cname} has a FOREIGN KEY to public.blobs "
            f"but is classified as {seen.get(pair, 'UNMANIFESTED')!r} instead of "
            "'live_roots'"
        )

    # 4. SQL_CATALOG_DRIFT (bidirectional against blob_has_live_reference in both
    # canonical reducers/blob_gc.sql AND latest migration embedding it, e.g. V293)
    sql_targets: List[Tuple[str, Path]] = [(gc_sql_path.name, gc_sql_path)]
    mig_gc = _find_latest_migration_with_live_ref(schema_dir)
    if mig_gc is None and "blob_gc_state" in tables:
        errors.append(
            "SQL_CATALOG_DRIFT: no dbschema V*.sql migration defines "
            "blob_has_live_reference() alongside blob_gc_state"
        )
    elif mig_gc is not None and mig_gc.resolve() != gc_sql_path.resolve():
        sql_targets.append((mig_gc.name, mig_gc))

    sql_roots: Set[Tuple[str, str]] = set()
    for label, target_path in sql_targets:
        try:
            parsed_roots = extract_live_roots_from_sql(target_path, tables)
        except Exception as exc:
            errors.append(f"SQL_CATALOG_DRIFT: failed to parse {target_path}: {exc}")
            continue
        if target_path == gc_sql_path:
            sql_roots = parsed_roots
        for tname, cname in sorted(live_roots - parsed_roots):
            errors.append(
                f"SQL_CATALOG_DRIFT: manifest live_root {tname}.{cname} is missing "
                f"from blob_has_live_reference() in {label}"
            )
        for tname, cname in sorted(parsed_roots - live_roots):
            errors.append(
                f"SQL_CATALOG_DRIFT: blob_has_live_reference() in {label} scans "
                f"{tname}.{cname} which is not listed in manifest live_roots"
            )

    # 5. SQL_CATALOG_DRIFT for blob_live_catalog() (bidirectional against manifest
    # live_roots in both reducers/blob_gc.sql and latest migration defining it)
    catalog_targets: List[Tuple[str, Path]] = []
    gc_text_stripped = strip_sql_comments(
        gc_sql_path.read_text(encoding="utf-8"), strip_inside_dollar=True
    )
    if re.search(
        r'\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:public\.)?"?blob_live_catalog"?\s*\(',
        gc_text_stripped,
        re.I,
    ):
        catalog_targets.append((gc_sql_path.name, gc_sql_path))
    mig_cat = _find_latest_migration_with_function(schema_dir, "blob_live_catalog")
    if mig_cat is not None and mig_cat.resolve() != gc_sql_path.resolve():
        catalog_targets.append((mig_cat.name, mig_cat))
    elif catalog_targets and mig_cat is None and "blob_gc_state" in tables:
        errors.append(
            "SQL_CATALOG_DRIFT: no dbschema V*.sql migration defines "
            "blob_live_catalog() alongside blob_gc.sql"
        )

    for label, target_path in catalog_targets:
        try:
            cat_roots = extract_live_catalog_roots_from_sql(target_path, tables)
        except Exception as exc:
            errors.append(
                f"SQL_CATALOG_DRIFT: failed to parse blob_live_catalog() in {target_path}: {exc}"
            )
            continue
        for tname, cname in sorted(live_roots - cat_roots):
            errors.append(
                f"SQL_CATALOG_DRIFT: manifest live_root {tname}.{cname} is missing "
                f"from blob_live_catalog() in {label}"
            )
        for tname, cname in sorted(cat_roots - live_roots):
            errors.append(
                f"SQL_CATALOG_DRIFT: blob_live_catalog() in {label} scans "
                f"{tname}.{cname} which is not listed in manifest live_roots"
            )

    stats = {
        "candidates": len(candidates),
        "live_roots": len(live_roots),
        "blobs_internal": len(by_category["blobs_internal"]),
        "separate_storage_plane": len(by_category["separate_storage_plane"]),
        "non_blob_digest": len(by_category["non_blob_digest"]),
        "sql_roots": len(sql_roots),
    }
    return errors, stats


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    manifest_path = Path(
        os.environ.get(
            "BLOB_MANIFEST",
            str(repo_root / "config" / "blob-reference-manifest.json"),
        )
    )
    schema_dir = Path(
        os.environ.get(
            "BLOB_SCHEMA_DIR",
            str(repo_root / "mailserver" / "sql" / "dbschema"),
        )
    )
    gc_sql_path = Path(
        os.environ.get(
            "BLOB_GC_SQL_FILE",
            str(repo_root / "mailserver" / "sql" / "reducers" / "blob_gc.sql"),
        )
    )

    errors, stats = validate(manifest_path, schema_dir, gc_sql_path)
    if errors:
        print(
            f"blob-reference-manifest: FAIL ({len(errors)} violation(s))",
            file=sys.stderr,
        )
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        return 1

    print(
        "blob-reference-manifest: PASS "
        f"(candidates={stats['candidates']}, live_roots={stats['live_roots']}, "
        f"blobs_internal={stats['blobs_internal']}, "
        f"separate_storage_plane={stats['separate_storage_plane']}, "
        f"non_blob_digest={stats['non_blob_digest']}, "
        f"sql_roots={stats['sql_roots']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
