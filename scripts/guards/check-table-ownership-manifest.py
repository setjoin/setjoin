#!/usr/bin/env python3
"""Static table-ownership and 3-class security manifest guard (Issue #539).

Checks:
  1. Comment-aware SQL schema & RLS extractor over V*.sql in numeric version order.
  2. Manifest completeness, owner/security_class validation, FORCE RLS verification,
     and monotonic legacy pending-RLS / legacy cross-domain write ratchets.
  3. Cross-domain SQL read/write enforcement across server/crates/domains/*.
  4. R1-R3 ownership predicate verification for mailbox_scoped / user_scoped tables.

Environment overrides (used by self-tests):
  TABLE_MANIFEST          Path to table-ownership-manifest.json
  TABLE_SCHEMA_DIR        Path to V*.sql migrations directory
  TABLE_RUST_DOMAINS_DIR  Path to server/crates/domains directory
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

VALID_DOMAIN_CRATES: Tuple[str, ...] = (
    "admin-identity",
    "approvals",
    "blobs",
    "calendar",
    "chat",
    "compliance",
    "conditional-access",
    "devices",
    "directory-sync",
    "drive",
    "guests",
    "identity",
    "jmap",
    "mail-security",
    "mailboxes",
    "meet",
    "office",
    "platform",
    "recording",
    "rules",
    "static",
    "user-settings",
)
VALID_OWNERS: Set[str] = set(VALID_DOMAIN_CRATES) | {"foundation"}
VALID_SECURITY_CLASSES: Set[str] = {
    "mailbox_scoped",
    "user_scoped",
    "org_global",
    "system_only",
}
SCOPED_SECURITY_CLASSES: Set[str] = {"mailbox_scoped", "user_scoped"}
VALID_CONTRACT_MODES: Set[str] = {"read_only", "legacy_write_migration_pending"}

# General tenant-ownership predicate tokens accepted for R1-R3 predicate checks.
BASE_SCOPE_TOKENS: Set[str] = {
    "mailbox_id",
    "user_id",
    "account_id",
    "owner_user_id",
    "actor_user_id",
    "requester_user_id",
    "target_mailbox_id",
    "subject_user_id",
    "subject_mailbox_id",
    "sponsor_user_id",
    "guest_user_id",
    "author_user_id",
    "author_id",
    "sender_user_id",
    "delegator_user_id",
    "delegate_user_id",
    "assignee_user_id",
    "uploading_user_id",
    "domain_id",
    "mentioned_user_id",
    # Canonical SQL RLS/authorization predicate helpers
    "mailbox_has_access",
    "admin_can_reach",
    "admin_can_reach_perm",
    "drive_effective_access",
    "drive_has_space_access",
    "drive_is_space_member",
    "drive_runtime_has_node_capability",
    "drive_runtime_has_space_capability",
    "chat_is_member",
    "current_setting",
}

_RUST_CHAR_RE = re.compile(
    r"b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,6}\}|[nrt0'\"\\])|[^'\\\n])'"
)
_RUST_RAW_STR_RE = re.compile(r'(?:(?:b|c)?r)(#*)"')
_SQL_IDENT = r'(?:"([a-z_][a-z0-9_]*)"|([a-z_][a-z0-9_]*))'
_SQL_CLAUSE_STOP = {
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
    "fetch",
    "for",
    "union",
    "intersect",
    "except",
    "returning",
    "set",
    "values",
    "window",
}


class SchemaExtractionError(Exception):
    """Fail-closed error during SQL migration schema / RLS extraction."""


def migration_sort_key(path: Path) -> Tuple[int, str]:
    m = re.match(r"^V0*([0-9]+)", path.name)
    return (int(m.group(1)) if m else 0, path.name)


def _is_ident_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _match_rust_char(src: str, idx: int) -> Optional[int]:
    """Return end index if src[idx:] starts a Rust char or byte-char literal."""
    ch = src[idx]
    if ch == "b":
        if idx > 0 and _is_ident_char(src[idx - 1]):
            return None
        if idx + 1 >= len(src) or src[idx + 1] != "'":
            return None
    elif ch != "'":
        return None
    m = _RUST_CHAR_RE.match(src, idx)
    return m.end() if m is not None else None


def _match_rust_raw_string(src: str, idx: int) -> Optional[Tuple[int, int, str]]:
    """Return (content_start, end_idx, content) if src[idx:] starts a raw string."""
    if idx > 0 and _is_ident_char(src[idx - 1]):
        return None
    m = _RUST_RAW_STR_RE.match(src, idx)
    if m is None:
        return None
    end_delim = '"' + m.group(1)
    content_start = m.end()
    ep = src.find(end_delim, content_start)
    if ep == -1:
        return (content_start, len(src), src[content_start:])
    return (content_start, ep + len(end_delim), src[content_start:ep])


def _skip_rust_normal_string(src: str, idx: int) -> int:
    """Skip a double-quoted Rust string starting at idx, returning index after quote."""
    n = len(src)
    j = idx + 1
    while j < n:
        if src[j] == "\\":
            j += 2
        elif src[j] == '"':
            return j + 1
        else:
            j += 1
    return n


def strip_sql_comments(sql: str, strip_inside_dollar: bool = True) -> str:
    """Strip -- line comments and nested /* ... */ block comments.

    Preserves single-quoted string literals ('...') and double-quoted identifiers.
    When strip_inside_dollar is True, comments inside dollar-quoted bodies
    ($tag$...$tag$) are also stripped because DO $$ ... $$ bodies contain PL/pgSQL
    source (matching scripts/guards/check-rls-coverage.sh D-1 r3 semantics).
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
            m = re.match(r"^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$", sql[i:])
            if m:
                dollar_tag = m.group(0)
                out.append(dollar_tag)
                i += len(dollar_tag)
                continue
        out.append(c)
        i += 1

    return "".join(out)


def _blank_preserving_newlines(text: str) -> str:
    return re.sub(r"[^\n]", " ", text)


def _mask_single_quoted_strings(sql: str) -> str:
    """Replace contents of single-quoted SQL literals with spaces (same offsets)."""
    out: List[str] = []
    i = 0
    n = len(sql)
    while i < n:
        c = sql[i]
        if c == '"':
            out.append(c)
            i += 1
            while i < n:
                ch = sql[i]
                out.append(ch)
                i += 1
                if ch == '"':
                    if i < n and sql[i] == '"':
                        out.append('"')
                        i += 1
                        continue
                    break
            continue
        if c == "'":
            out.append("'")
            i += 1
            while i < n:
                ch = sql[i]
                if ch == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        out.append("  ")
                        i += 2
                        continue
                    out.append("'")
                    i += 1
                    break
                out.append("\n" if ch == "\n" else " ")
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _split_top_level_commas(text: str) -> List[str]:
    parts: List[str] = []
    buf: List[str] = []
    depth = 0
    in_dq = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_dq:
            buf.append(ch)
            if ch == '"':
                if i + 1 < n and text[i + 1] == '"':
                    buf.append('"')
                    i += 2
                    continue
                in_dq = False
            i += 1
            continue
        if ch == '"':
            in_dq = True
            buf.append(ch)
        elif ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")" and depth > 0:
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def _parse_foreach_rls_blocks(
    clean_sql: str,
    filename: str,
) -> Tuple[str, List[Tuple[int, str, str, object, object]]]:
    """Extract FOREACH dynamic RLS blocks and mask non-FOREACH string literals.

    Returns (masked_sql_preserving_offsets, foreach_events).
    """
    foreach_hdr_re = re.compile(
        r"\bforeach\s+([a-z_][a-z0-9_]*)\s+in\s+array\s+array\[([^\]]*)\]\s+loop\b",
        re.IGNORECASE,
    )
    end_loop_re = re.compile(r"\bend\s+loop\b", re.IGNORECASE)
    exec_fmt_re = re.compile(r"\bexecute\s+format\s*\(", re.IGNORECASE)
    sq_lit_re = re.compile(r"'([^']*)'")
    direct_in_loop_re = re.compile(
        r"\balter\s+table\s+(?:only\s+)?(?:public\.)?[a-z_][a-z0-9_]*\s+[a-z]",
        re.IGNORECASE,
    )
    rls_phrase_re = re.compile(r"\brow\s+level\s+security\b", re.IGNORECASE)

    # First locate valid FOREACH spans outside single-quoted string literals.
    masked_all = _mask_single_quoted_strings(clean_sql)
    foreach_spans: List[Tuple[int, int, str, str, str]] = []
    pos = 0
    while True:
        fm = foreach_hdr_re.search(masked_all, pos)
        if fm is None:
            break
        em = end_loop_re.search(masked_all, fm.end())
        if em is None:
            raise SchemaExtractionError(
                f"UNSUPPORTED RLS syntax in {filename}: FOREACH block without END LOOP"
            )
        var = fm.group(1).lower()
        # Use unmasked clean_sql for ARRAY[...] and body so literals stay readable.
        raw_hdr = clean_sql[fm.start() : fm.end()]
        arr_m = re.search(r"array\[([^\]]*)\]", raw_hdr, re.IGNORECASE)
        arr_text = arr_m.group(1) if arr_m else ""
        body = clean_sql[fm.end() : em.start()]
        foreach_spans.append((fm.start(), em.end(), var, arr_text, body))
        pos = em.end()

    events: List[Tuple[int, str, str, object, object]] = []
    out_chars = list(masked_all)

    for start, end, var, arr_text, body in foreach_spans:
        if direct_in_loop_re.search(_mask_single_quoted_strings(body)):
            raise SchemaExtractionError(
                f"UNSUPPORTED RLS syntax in {filename}: "
                "direct ALTER TABLE inside FOREACH block"
            )

        ops: List[str] = []
        resid_parts: List[str] = []
        bpos = 0
        while True:
            ef = exec_fmt_re.search(body, bpos)
            if ef is None:
                resid_parts.append(body[bpos:])
                break
            resid_parts.append(body[bpos : ef.start()])
            after_idx = ef.end()
            after_call = body[after_idx:]
            stripped = after_call.lstrip()
            lm = sq_lit_re.match(stripped)
            if lm is None:
                raise SchemaExtractionError(
                    f"UNSUPPORTED RLS syntax in {filename}: "
                    "EXECUTE format without literal format string"
                )
            lead_ws = len(after_call) - len(stripped)
            fmt_raw = lm.group(1)
            fmt_norm = re.sub(r"\s+", " ", fmt_raw.strip().lower())
            after_lit_idx = after_idx + lead_ws + lm.end()
            if "row level security" not in fmt_norm:
                bpos = after_lit_idx
                continue
            fmt_m = re.match(
                r"^alter table (?:only )?(?:public\.)?%i "
                r"(no force|force|enable|disable) row level security$",
                fmt_norm,
            )
            if fmt_m is None:
                raise SchemaExtractionError(
                    f"UNSUPPORTED RLS syntax in {filename}: "
                    f'unrecognized dynamic RLS format "{fmt_raw}"'
                )
            close_paren = body.find(")", after_lit_idx)
            if close_paren == -1:
                raise SchemaExtractionError(
                    f"UNSUPPORTED RLS syntax in {filename}: "
                    "EXECUTE format without closing ')'"
                )
            arg_raw = body[after_lit_idx:close_paren]
            arg = arg_raw.strip().lstrip(",").strip().lower()
            if arg != var:
                raise SchemaExtractionError(
                    f"UNSUPPORTED RLS syntax in {filename}: "
                    f'format argument "{arg}" != FOREACH variable "{var}"'
                )
            ops.append(fmt_m.group(1))
            bpos = close_paren + 1

        resid_masked = _mask_single_quoted_strings("".join(resid_parts))
        if rls_phrase_re.search(resid_masked):
            raise SchemaExtractionError(
                f"UNSUPPORTED RLS syntax in {filename} (FOREACH block body): "
                "unrecognized ROW LEVEL SECURITY statement inside FOREACH block"
            )

        if ops:
            raw_elems = re.findall(r"'([^']+)'", arr_text)
            if not raw_elems:
                raise SchemaExtractionError(
                    f"UNSUPPORTED RLS syntax in {filename}: "
                    "empty ARRAY in RLS FOREACH block"
                )
            table_names: List[str] = []
            for elem in raw_elems:
                tname = elem.lower()
                if not re.match(r"^[a-z_][a-z0-9_]*$", tname):
                    raise SchemaExtractionError(
                        f"UNSUPPORTED RLS syntax in {filename}: "
                        f"non-identifier table literal '{elem}' in ARRAY"
                    )
                table_names.append(tname)
            events.append((start, "rls_foreach", "public", table_names, ops))

        # Blank out consumed FOREACH span while preserving line offsets.
        blanked = _blank_preserving_newlines(masked_all[start:end])
        out_chars[start:end] = list(blanked)

    return "".join(out_chars), events


def _extract_direct_rls_events(
    masked_sql: str,
    filename: str,
) -> List[Tuple[int, str, str, object, object]]:
    """Extract direct (including comma-separated multi-action) ALTER TABLE RLS events.

    Fails closed if ANY unconsumed ROW LEVEL SECURITY phrase remains in masked_sql.
    """
    rls_phrase_re = re.compile(r"\brow\s+level\s+security\b", re.IGNORECASE)
    alter_stmt_re = re.compile(
        r"\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([^;]+);",
        re.IGNORECASE,
    )
    target_re = re.compile(
        r"^(?:public\.)?([a-z_][a-z0-9_]*)\s+(.+)$", re.IGNORECASE | re.DOTALL
    )
    action_re = re.compile(
        r"^(no\s+force|force|enable|disable)\s+row\s+level\s+security$",
        re.IGNORECASE,
    )

    events: List[Tuple[int, str, str, object, object]] = []
    out_chars = list(masked_sql)

    for m in alter_stmt_re.finditer(masked_sql):
        body = m.group(1)
        if not rls_phrase_re.search(body):
            continue
        tm = target_re.match(body.strip())
        if tm is None:
            raise SchemaExtractionError(
                f"UNSUPPORTED RLS syntax in {filename}: "
                "unrecognized target in ALTER TABLE ... ROW LEVEL SECURITY"
            )
        tname = tm.group(1).lower()
        actions_tail = tm.group(2).strip()
        ops: List[str] = []
        for clause in _split_top_level_commas(actions_tail):
            c_norm = re.sub(r"\s+", " ", clause.strip())
            if not rls_phrase_re.search(c_norm):
                continue
            am = action_re.match(c_norm)
            if am is None:
                raise SchemaExtractionError(
                    f"UNSUPPORTED RLS syntax in {filename}: "
                    f'unrecognized RLS clause "{c_norm}" on {tname}'
                )
            ops.append(re.sub(r"\s+", " ", am.group(1).lower()))
        if not ops:
            raise SchemaExtractionError(
                f"UNSUPPORTED RLS syntax in {filename}: "
                f"failed to parse RLS action on {tname}"
            )
        events.append((m.start(), "rls_direct", "public", tname, ops))
        blanked = _blank_preserving_newlines(masked_sql[m.start() : m.end()])
        out_chars[m.start() : m.end()] = list(blanked)

    residual = "".join(out_chars)
    if rls_phrase_re.search(residual):
        raise SchemaExtractionError(
            f"UNSUPPORTED RLS syntax in {filename}: "
            "unconsumed ROW LEVEL SECURITY statement survived extraction"
        )
    return events


def extract_schema_state(
    schema_dir: Path,
) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
    """Replay V*.sql in numeric version order.

    Returns (logical_tables, partitions, rls_enabled, rls_forced).
    """
    migs = sorted(schema_dir.glob("V*.sql"), key=migration_sort_key)
    if not migs:
        raise SchemaExtractionError(f"No V*.sql migrations found under {schema_dir}")

    tables: Set[str] = set()
    partitions: Set[str] = set()
    rls_enabled: Set[str] = set()
    rls_forced: Set[str] = set()

    create_re = re.compile(
        r"\bCREATE\s+(?:(GLOBAL|LOCAL)\s+)?(?:(TEMP|TEMPORARY)\s+)?(?:UNLOGGED\s+)?"
        r"TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
        r"(?:([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*)?(\"?[a-zA-Z_][a-zA-Z0-9_]*\"?)\s*"
        r"(PARTITION\s+OF\b|\(|AS\b)",
        re.IGNORECASE,
    )
    drop_re = re.compile(r"\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([^;]+)", re.IGNORECASE)
    rename_re = re.compile(
        r"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?"
        r"(?:([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*)?(\"?[a-zA-Z_][a-zA-Z0-9_]*\"?)\s+"
        r"RENAME\s+TO\s+(\"?[a-zA-Z_][a-zA-Z0-9_]*\"?)",
        re.IGNORECASE,
    )
    attach_re = re.compile(
        r"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?"
        r"(?:([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*)?(\"?[a-zA-Z_][a-zA-Z0-9_]*\"?)\s+"
        r"ATTACH\s+PARTITION\s+"
        r"(?:([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*)?(\"?[a-zA-Z_][a-zA-Z0-9_]*\"?)",
        re.IGNORECASE,
    )

    def apply_rls_ops(tname: str, ops: List[str]) -> None:
        for op in ops:
            if op == "enable":
                rls_enabled.add(tname)
            elif op == "disable":
                rls_enabled.discard(tname)
            elif op == "force":
                rls_forced.add(tname)
            elif op == "no force":
                rls_forced.discard(tname)

    for mig in migs:
        raw = mig.read_text(encoding="utf-8", errors="replace")
        clean = strip_sql_comments(raw, strip_inside_dollar=True)
        masked, foreach_events = _parse_foreach_rls_blocks(clean, mig.name)
        direct_rls_events = _extract_direct_rls_events(masked, mig.name)

        events: List[Tuple[int, str, str, object, object]] = []
        events.extend(foreach_events)
        events.extend(direct_rls_events)

        for m in create_re.finditer(masked):
            if m.group(2):  # TEMP / TEMPORARY
                continue
            schema = (m.group(3) or "public").lower()
            tname = m.group(4).strip('"').lower()
            is_part = m.group(5).upper().startswith("PARTITION")
            events.append((m.start(), "create", schema, tname, is_part))

        for m in drop_re.finditer(masked):
            part = re.sub(
                r"\b(?:CASCADE|RESTRICT)\b.*$", "", m.group(1), flags=re.IGNORECASE
            ).strip()
            for item in part.split(","):
                item = item.strip()
                tm = re.match(
                    r"^(?:([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*)?"
                    r"(\"?[a-zA-Z_][a-zA-Z0-9_]*\"?)$",
                    item,
                )
                if tm:
                    schema = (tm.group(1) or "public").lower()
                    tname = tm.group(2).strip('"').lower()
                    events.append((m.start(), "drop", schema, tname, None))

        for m in rename_re.finditer(masked):
            schema = (m.group(1) or "public").lower()
            old = m.group(2).strip('"').lower()
            new = m.group(3).strip('"').lower()
            events.append((m.start(), "rename", schema, old, new))

        for m in attach_re.finditer(masked):
            schema = (m.group(1) or "public").lower()
            child = m.group(4).strip('"').lower()
            parent = m.group(2).strip('"').lower()
            events.append((m.start(), "attach", schema, child, parent))

        events.sort(key=lambda e: e[0])
        for _, kind, schema, target, extra in events:
            if schema != "public":
                continue
            if kind == "create":
                tname = str(target)
                if extra:
                    partitions.add(tname)
                    tables.discard(tname)
                elif tname not in partitions:
                    tables.add(tname)
            elif kind == "drop":
                tname = str(target)
                tables.discard(tname)
                partitions.discard(tname)
                rls_enabled.discard(tname)
                rls_forced.discard(tname)
            elif kind == "rename":
                old_name = str(target)
                new_name = str(extra)
                if old_name in tables:
                    tables.discard(old_name)
                    tables.add(new_name)
                if old_name in partitions:
                    partitions.discard(old_name)
                    partitions.add(new_name)
                if old_name in rls_enabled:
                    rls_enabled.discard(old_name)
                    rls_enabled.add(new_name)
                if old_name in rls_forced:
                    rls_forced.discard(old_name)
                    rls_forced.add(new_name)
            elif kind == "attach":
                tname = str(target)
                partitions.add(tname)
                tables.discard(tname)
            elif kind == "rls_direct":
                apply_rls_ops(str(target), list(extra))  # type: ignore[arg-type]
            elif kind == "rls_foreach":
                for tname in target:  # type: ignore[union-attr]
                    apply_rls_ops(tname, list(extra))  # type: ignore[arg-type]

    if not tables:
        raise SchemaExtractionError(
            f"Zero logical tables extracted from {schema_dir} "
            "— refusing to run fail-open"
        )

    return tables, partitions, rls_enabled, rls_forced


def strip_rust_comments_and_tests(src: str) -> str:
    """Strip // and nested /* */ comments and #[cfg(test)] items, preserving lines."""
    out: List[str] = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        two = src[i : i + 2]
        if two == "//":
            j = src.find("\n", i)
            if j == -1:
                break
            out.append("\n")
            i = j + 1
            continue
        if two == "/*":
            depth = 1
            i += 2
            while i < n and depth > 0:
                if src[i : i + 2] == "/*":
                    depth += 1
                    i += 2
                elif src[i : i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    if src[i] == "\n":
                        out.append("\n")
                    i += 1
            out.append(" ")
            continue
        raw_match = _match_rust_raw_string(src, i)
        if raw_match is not None:
            _, end_i, _ = raw_match
            out.append(src[i:end_i])
            i = end_i
            continue
        char_end = _match_rust_char(src, i)
        if char_end is not None:
            out.append(src[i:char_end])
            i = char_end
            continue
        if c == '"':
            end_i = _skip_rust_normal_string(src, i)
            out.append(src[i:end_i])
            i = end_i
            continue
        out.append(c)
        i += 1

    code = "".join(out)
    res: List[str] = []
    i = 0
    n = len(code)
    cfg_re = re.compile(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]")

    while i < n:
        raw_match = _match_rust_raw_string(code, i)
        if raw_match is not None:
            _, end_i, _ = raw_match
            res.append(code[i:end_i])
            i = end_i
            continue
        char_end = _match_rust_char(code, i)
        if char_end is not None:
            res.append(code[i:char_end])
            i = char_end
            continue
        if code[i] == '"':
            end_i = _skip_rust_normal_string(code, i)
            res.append(code[i:end_i])
            i = end_i
            continue
        if code[i] == "#":
            m = cfg_re.match(code, i)
            if m is not None:
                res.append("\n" * code[i : m.end()].count("\n"))
                j = m.end()
                while j < n:
                    rm = _match_rust_raw_string(code, j)
                    if rm is not None:
                        _, end_j, _ = rm
                        res.append("\n" * code[j:end_j].count("\n"))
                        j = end_j
                        continue
                    ce = _match_rust_char(code, j)
                    if ce is not None:
                        j = ce
                        continue
                    if code[j] == '"':
                        end_j = _skip_rust_normal_string(code, j)
                        res.append("\n" * code[j:end_j].count("\n"))
                        j = end_j
                        continue
                    if code[j] == ";":
                        j += 1
                        break
                    if code[j] == "{":
                        depth = 1
                        j += 1
                        while j < n and depth > 0:
                            rm2 = _match_rust_raw_string(code, j)
                            if rm2 is not None:
                                _, end_j, _ = rm2
                                res.append("\n" * code[j:end_j].count("\n"))
                                j = end_j
                                continue
                            ce2 = _match_rust_char(code, j)
                            if ce2 is not None:
                                j = ce2
                                continue
                            if code[j] == '"':
                                end_j = _skip_rust_normal_string(code, j)
                                res.append("\n" * code[j:end_j].count("\n"))
                                j = end_j
                                continue
                            if code[j] == "{":
                                depth += 1
                            elif code[j] == "}":
                                depth -= 1
                            elif code[j] == "\n":
                                res.append("\n")
                            j += 1
                        break
                    if code[j] == "\n":
                        res.append("\n")
                    j += 1
                i = j
                continue
        res.append(code[i])
        i += 1

    return "".join(res)


def _read_normal_string(code: str, idx: int) -> Tuple[str, int, int]:
    """Read a double-quoted Rust string starting at idx.

    Returns (decoded_text, next_idx, newlines_consumed).
    """
    n = len(code)
    j = idx + 1
    buf: List[str] = []
    newlines = 0
    while j < n:
        ch = code[j]
        if ch == "\\" and j + 1 < n:
            nxt = code[j + 1]
            if nxt == "n":
                buf.append("\n")
            elif nxt == "t":
                buf.append("\t")
            elif nxt == "r":
                buf.append("\r")
            elif nxt == '"':
                buf.append('"')
            elif nxt == "\\":
                buf.append("\\")
            elif nxt == "\n":
                newlines += 1
                j += 2
                while j < n and code[j] in " \t":
                    j += 1
                continue
            else:
                buf.append(nxt)
            j += 2
            continue
        if ch == '"':
            j += 1
            break
        if ch == "\n":
            newlines += 1
        buf.append(ch)
        j += 1
    return "".join(buf), j, newlines


def extract_rust_string_literals(code: str) -> List[Tuple[int, str]]:
    """Extract (start_line, content) for Rust string literals and literal concat!."""
    lits: List[Tuple[int, str]] = []
    i = 0
    n = len(code)
    line = 1
    while i < n:
        c = code[i]
        if c == "\n":
            line += 1
            i += 1
            continue

        if code.startswith("concat!", i) and (
            i == 0 or not _is_ident_char(code[i - 1])
        ):
            cm = re.match(r"concat!\s*\(", code[i:])
            if cm:
                start_line = line
                j = i + len(cm.group(0))
                parts: List[str] = []
                add_lines = 0
                ok = True
                while j < n:
                    ch = code[j]
                    if ch == "\n":
                        add_lines += 1
                        j += 1
                        continue
                    if ch in " \t\r,":
                        j += 1
                        continue
                    rm = _match_rust_raw_string(code, j)
                    if rm is not None:
                        _, end_j, content = rm
                        add_lines += content.count("\n")
                        parts.append(content)
                        j = end_j
                        continue
                    if ch == '"':
                        content, j, nl = _read_normal_string(code, j)
                        add_lines += nl
                        parts.append(content)
                        continue
                    if ch == ")":
                        j += 1
                        break
                    ok = False
                    break
                if ok and parts:
                    lits.append((start_line, "".join(parts)))
                    line += add_lines
                    i = j
                    continue

        raw_match = _match_rust_raw_string(code, i)
        if raw_match is not None:
            _, end_i, content = raw_match
            start_line = line
            line += content.count("\n")
            lits.append((start_line, content))
            i = end_i
            continue

        char_end = _match_rust_char(code, i)
        if char_end is not None:
            i = char_end
            continue

        if c == '"':
            start_line = line
            content, i, nl = _read_normal_string(code, i)
            line += nl
            lits.append((start_line, content))
            continue

        i += 1
    return lits


def _ident_from_match(m: re.Match, g1: int = 1, g2: int = 2) -> str:
    return (m.group(g1) or m.group(g2)).lower()


def _parse_from_item_list(
    sql: str,
    start_idx: int,
    logical_tables: Set[str],
) -> Set[str]:
    """Parse comma-separated table references after FROM or DELETE ... USING."""
    found: Set[str] = set()
    n = len(sql)
    i = start_idx
    ident_re = re.compile(
        r"(?:only\s+|lateral\s+)*(?:public\.)?" + _SQL_IDENT,
        re.IGNORECASE,
    )
    word_re = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")

    while i < n:
        while i < n and sql[i].isspace():
            i += 1
        if i >= n or sql[i] in ";)":
            break

        if sql[i] == "(":
            # Parenthesized subquery/join: skip parens (inner FROM parsed separately).
            depth = 1
            i += 1
            while i < n and depth > 0:
                if sql[i] == "(":
                    depth += 1
                elif sql[i] == ")":
                    depth -= 1
                i += 1
        else:
            wm = word_re.match(sql, i)
            if wm and wm.group(0).lower() in _SQL_CLAUSE_STOP:
                break
            im = ident_re.match(sql, i)
            if im is None:
                break
            tname = _ident_from_match(im)
            after_ident = im.end()
            # Skip table-valued function calls like jsonb_array_elements(...)
            ws_end = after_ident
            while ws_end < n and sql[ws_end].isspace():
                ws_end += 1
            if ws_end < n and sql[ws_end] == "(":
                depth = 1
                i = ws_end + 1
                while i < n and depth > 0:
                    if sql[i] == "(":
                        depth += 1
                    elif sql[i] == ")":
                        depth -= 1
                    i += 1
            else:
                if tname in logical_tables:
                    found.add(tname)
                i = after_ident

        # Advance past optional alias (AS alias / alias) until comma or clause stop.
        while i < n:
            while i < n and sql[i].isspace():
                i += 1
            if i >= n or sql[i] in ";)":
                return found
            if sql[i] == ",":
                i += 1
                break
            if sql[i] == "(":
                # Column alias list like AS t(a, b)
                depth = 1
                i += 1
                while i < n and depth > 0:
                    if sql[i] == "(":
                        depth += 1
                    elif sql[i] == ")":
                        depth -= 1
                    i += 1
                continue
            wm = word_re.match(sql, i)
            if wm is None:
                return found
            wlow = wm.group(0).lower()
            if wlow in _SQL_CLAUSE_STOP:
                return found
            i = wm.end()
    return found


def extract_sql_table_refs(
    slit: str,
    logical_tables: Set[str],
) -> Tuple[List[str], List[str], List[str]]:
    """Extract (reads, writes, upd_del_targets) matching canonical logical_tables."""
    write_re = re.compile(
        r"\b(?:INTO|UPDATE(?:\s+ONLY)?|DELETE\s+FROM(?:\s+ONLY)?|"
        r"TRUNCATE(?:\s+TABLE)?(?:\s+ONLY)?)\s+(?:public\.)?" + _SQL_IDENT,
        re.IGNORECASE,
    )
    upd_del_re = re.compile(
        r"\b(?:UPDATE(?:\s+ONLY)?|DELETE\s+FROM(?:\s+ONLY)?)\s+(?:public\.)?"
        + _SQL_IDENT,
        re.IGNORECASE,
    )
    delete_from_re = re.compile(
        r"\bDELETE\s+FROM\s+(?:ONLY\s+)?(?:public\.)?" + _SQL_IDENT,
        re.IGNORECASE,
    )
    join_re = re.compile(
        r"\bJOIN\s+(?:ONLY\s+)?(?:public\.)?" + _SQL_IDENT,
        re.IGNORECASE,
    )
    from_or_using_re = re.compile(r"\b(?:FROM|USING)\s+", re.IGNORECASE)

    writes_set: Set[str] = set()
    for m in write_re.finditer(slit):
        t = _ident_from_match(m)
        if t in logical_tables:
            writes_set.add(t)

    upd_del_set: Set[str] = set()
    for m in upd_del_re.finditer(slit):
        t = _ident_from_match(m)
        if t in logical_tables:
            upd_del_set.add(t)

    slit_no_del = delete_from_re.sub("DELETE_TARGET ", slit)
    reads_set: Set[str] = set()
    for m in join_re.finditer(slit_no_del):
        t = _ident_from_match(m)
        if t in logical_tables:
            reads_set.add(t)
    for m in from_or_using_re.finditer(slit_no_del):
        reads_set.update(_parse_from_item_list(slit_no_del, m.end(), logical_tables))

    return sorted(reads_set), sorted(writes_set), sorted(upd_del_set)


def extract_predicate_context(sql: str) -> str:
    """Extract only predicate-context clauses (WHERE / ON / HAVING / USING).

    Explicitly excludes SELECT projection lists, FROM, SET, VALUES, GROUP BY,
    ORDER BY, LIMIT, OFFSET, RETURNING, etc., so projection-only mentions like
    `SELECT user_id FROM t WHERE id = $1` do NOT satisfy R1.
    """
    toks = re.split(
        r"(\b(?:SELECT|FROM|WHERE|ON|HAVING|USING|GROUP\s+BY|ORDER\s+BY|"
        r"LIMIT|OFFSET|RETURNING|VALUES|SET|UNION|INTERSECT|EXCEPT|INTO|JOIN)\b)",
        sql,
        flags=re.IGNORECASE,
    )
    capturing = False
    preds: List[str] = []
    for tok in toks:
        u = re.sub(r"\s+", " ", tok.strip().upper())
        if u in ("WHERE", "ON", "HAVING", "USING"):
            capturing = True
            preds.append(" " + tok + " ")
        elif u in (
            "SELECT",
            "FROM",
            "GROUP BY",
            "ORDER BY",
            "LIMIT",
            "OFFSET",
            "RETURNING",
            "VALUES",
            "SET",
            "UNION",
            "INTERSECT",
            "EXCEPT",
            "INTO",
            "JOIN",
        ):
            capturing = False
        elif capturing:
            preds.append(tok)
    return " ".join(preds)


def extract_where_context(sql: str) -> str:
    """Extract only WHERE clause text for UPDATE/DELETE (R3), skipping SET/RETURNING."""
    toks = re.split(
        r"(\b(?:SELECT|FROM|WHERE|HAVING|GROUP\s+BY|ORDER\s+BY|"
        r"LIMIT|OFFSET|RETURNING|VALUES|SET|UNION|INTERSECT|EXCEPT|INTO)\b)",
        sql,
        flags=re.IGNORECASE,
    )
    capturing = False
    preds: List[str] = []
    for tok in toks:
        u = re.sub(r"\s+", " ", tok.strip().upper())
        if u == "WHERE":
            capturing = True
            preds.append(" " + tok + " ")
        elif u in (
            "SELECT",
            "FROM",
            "GROUP BY",
            "ORDER BY",
            "LIMIT",
            "OFFSET",
            "RETURNING",
            "VALUES",
            "SET",
            "UNION",
            "INTERSECT",
            "EXCEPT",
            "INTO",
        ):
            capturing = False
        elif capturing:
            preds.append(tok)
    return " ".join(preds)


def scope_tokens_for_table(entry: dict) -> Set[str]:
    """Return allowed ownership predicate tokens for a scoped table.

    Only permits bare `id` when rls_scope_column is literally `"id"` (e.g. users,
    mailboxes), never for FK chains like `"id -> chat_channel_members.user_id"`.
    """
    toks = set(BASE_SCOPE_TOKENS)
    scope_col = str(entry.get("rls_scope_column") or "").strip().lower()
    if scope_col == "id":
        toks.add("id")
    elif scope_col:
        first = scope_col.split("->")[0].strip()
        if first and first != "id":
            toks.add(first)
        for fk in re.findall(r"\b([a-z_]+_id)\b", scope_col):
            toks.add(fk)
    return toks


def has_scope_token(pred_text: str, allowed_tokens: Set[str]) -> bool:
    if not pred_text.strip():
        return False
    low = pred_text.lower()
    for tok in allowed_tokens:
        if tok == "id":
            pat = (
                r"(?:^|[^a-z0-9_])(?:[a-z_][a-z0-9_]*\.)?"
                r"id\s*(?:=|!=|<>|\bin\b|\bis\b)"
            )
            if re.search(pat, low):
                return True
        else:
            pat = r"(?:^|[^a-z0-9_])" + re.escape(tok) + r"(?:[^a-z0-9_]|$)"
            if re.search(pat, low):
                return True
    return False


def validate_manifest_and_schema(
    manifest: dict,
    logical_tables: Set[str],
    rls_enabled: Set[str],
    rls_forced: Set[str],
) -> List[str]:
    """Check 2: Completeness, schema validity, FORCE RLS enforcement, and ratchets."""
    errors: List[str] = []

    if manifest.get("schema_version") != 1:
        ver = manifest.get("schema_version")
        errors.append(f"INVALID_MANIFEST: schema_version must be 1, got {ver!r}")
        return errors

    tables_map = manifest.get("tables")
    if not isinstance(tables_map, dict):
        errors.append("INVALID_MANIFEST: top-level 'tables' must be an object")
        return errors

    manifest_tables = set(tables_map.keys())
    for t in sorted(logical_tables - manifest_tables):
        errors.append(f"UNCLASSIFIED: {t}")
    for t in sorted(manifest_tables - logical_tables):
        errors.append(f"STALE: {t}")

    pending_ceiling = manifest.get("legacy_rls_pending_ceiling")
    frozen_pending_list = manifest.get("legacy_rls_pending_tables")
    write_ceiling = manifest.get("legacy_write_migration_ceiling")

    if not isinstance(pending_ceiling, int) or pending_ceiling < 0:
        errors.append(
            "INVALID_MANIFEST: legacy_rls_pending_ceiling must be non-negative int"
        )
        pending_ceiling = 0
    if not isinstance(frozen_pending_list, list) or not all(
        isinstance(x, str) for x in frozen_pending_list
    ):
        errors.append(
            "INVALID_MANIFEST: legacy_rls_pending_tables must be a list of table names"
        )
        frozen_pending: Set[str] = set()
    else:
        frozen_pending = set(frozen_pending_list)
        if len(frozen_pending) != len(frozen_pending_list):
            errors.append(
                "INVALID_MANIFEST: legacy_rls_pending_tables contains duplicates"
            )
    if not isinstance(write_ceiling, int) or write_ceiling < 0:
        errors.append(
            "INVALID_MANIFEST: legacy_write_migration_ceiling must be non-negative int"
        )
        write_ceiling = 0

    allowlist = manifest.get("r1_r3_allowlist")
    if not isinstance(allowlist, list):
        errors.append("INVALID_MANIFEST: r1_r3_allowlist must be a list")
    else:
        for idx, item in enumerate(allowlist):
            if not isinstance(item, dict):
                errors.append(f"INVALID_ALLOWLIST: entry #{idx} must be an object")
                continue
            for req in ("file", "table", "reason"):
                if not isinstance(item.get(req), str) or not item[req].strip():
                    errors.append(
                        f"INVALID_ALLOWLIST: entry #{idx} missing non-empty '{req}'"
                    )

    pending_declared: Set[str] = set()
    legacy_write_count = 0

    for t in sorted(manifest_tables):
        entry = tables_map[t]
        if not isinstance(entry, dict):
            errors.append(f"INVALID_ENTRY: {t} must be an object")
            continue

        owner = entry.get("owner")
        sclass = entry.get("security_class")
        posture = entry.get("rls_posture")
        scope_col = entry.get("rls_scope_column")

        if owner not in VALID_OWNERS:
            errors.append(f"INVALID_OWNER: {t} has unknown owner {owner!r}")
        if sclass not in VALID_SECURITY_CLASSES:
            errors.append(
                f"INVALID_SECURITY_CLASS: {t} has unknown security_class {sclass!r}"
            )
            continue

        has_enable_and_force = (t in rls_enabled) and (t in rls_forced)

        if sclass in SCOPED_SECURITY_CLASSES:
            if not isinstance(scope_col, str) or not scope_col.strip():
                errors.append(
                    f"MISSING_SCOPE_COLUMN: {t} ({sclass}) requires non-empty "
                    "rls_scope_column"
                )

            if posture == "enforced":
                if t in logical_tables and not has_enable_and_force:
                    detail = []
                    if t not in rls_enabled:
                        detail.append("ENABLE")
                    if t not in rls_forced:
                        detail.append("FORCE")
                    missing = "+".join(detail)
                    errors.append(
                        f"MISSING_FORCE_RLS: {t} declared rls_posture='enforced' "
                        f"but lacks {missing} ROW LEVEL SECURITY"
                    )
            elif posture == "pending_wave1_cutover":
                pending_declared.add(t)
                tracking = entry.get("rls_tracking_issue")
                if not isinstance(tracking, str) or not tracking.strip():
                    errors.append(
                        f"INVALID_PENDING_RLS: {t} uses pending_wave1_cutover "
                        "without rls_tracking_issue"
                    )
                if t in logical_tables and has_enable_and_force:
                    errors.append(
                        f"STALE_PENDING_RLS: {t} already has ENABLE+FORCE ROW LEVEL "
                        "SECURITY; upgrade rls_posture to 'enforced'"
                    )
                if t not in frozen_pending:
                    errors.append(
                        f"RLS_PENDING_RATCHET: {t} uses pending_wave1_cutover but is "
                        "not in frozen legacy_rls_pending_tables baseline"
                    )
            else:
                errors.append(
                    f"INVALID_RLS_POSTURE: {t} ({sclass}) must use 'enforced' or "
                    f"'pending_wave1_cutover', got {posture!r}"
                )
        else:
            if posture == "enforced":
                if t in logical_tables and not has_enable_and_force:
                    detail = []
                    if t not in rls_enabled:
                        detail.append("ENABLE")
                    if t not in rls_forced:
                        detail.append("FORCE")
                    missing = "+".join(detail)
                    errors.append(
                        f"MISSING_FORCE_RLS: {t} declared rls_posture='enforced' "
                        f"but lacks {missing} ROW LEVEL SECURITY"
                    )
            elif posture != "not_applicable":
                errors.append(
                    f"INVALID_RLS_POSTURE: {t} ({sclass}) must use 'enforced' or "
                    f"'not_applicable', got {posture!r}"
                )

        contracts = entry.get("read_contracts", [])
        if not isinstance(contracts, list):
            errors.append(f"INVALID_CONTRACTS: {t} read_contracts must be an array")
        else:
            seen_consumers: Set[str] = set()
            for c in contracts:
                if not isinstance(c, dict):
                    errors.append(
                        f"INVALID_CONTRACTS: {t} contains non-object contract"
                    )
                    continue
                consumer = c.get("consumer")
                mode = c.get("mode")
                reason = c.get("reason")
                if consumer not in VALID_OWNERS:
                    errors.append(
                        f"INVALID_CONTRACTS: {t} contract has unknown consumer "
                        f"{consumer!r}"
                    )
                elif consumer == owner:
                    errors.append(
                        f"INVALID_CONTRACTS: {t} contract consumer {consumer!r} "
                        "equals owner"
                    )
                elif consumer in seen_consumers:
                    errors.append(
                        f"INVALID_CONTRACTS: {t} has duplicate contract for "
                        f"consumer {consumer!r}"
                    )
                else:
                    seen_consumers.add(consumer)
                if mode not in VALID_CONTRACT_MODES:
                    errors.append(
                        f"INVALID_CONTRACTS: {t} contract for {consumer!r} has "
                        f"invalid mode {mode!r}"
                    )
                if not isinstance(reason, str) or not reason.strip():
                    errors.append(
                        f"INVALID_CONTRACTS: {t} contract for {consumer!r} missing "
                        "non-empty reason"
                    )
                if mode == "legacy_write_migration_pending":
                    legacy_write_count += 1

    if len(pending_declared) > pending_ceiling:
        errors.append(
            f"RLS_PENDING_RATCHET: {len(pending_declared)} pending_wave1_cutover "
            f"tables exceed legacy_rls_pending_ceiling ({pending_ceiling})"
        )
    if len(frozen_pending) > pending_ceiling:
        errors.append(
            f"RLS_PENDING_RATCHET: {len(frozen_pending)} legacy_rls_pending_tables "
            f"exceed legacy_rls_pending_ceiling ({pending_ceiling})"
        )
    for t in sorted(frozen_pending - pending_declared):
        errors.append(
            f"STALE_PENDING_RLS: {t} is in legacy_rls_pending_tables but not "
            "declared pending_wave1_cutover"
        )
    if legacy_write_count > write_ceiling:
        errors.append(
            f"LEGACY_WRITE_RATCHET: {legacy_write_count} "
            f"legacy_write_migration_pending contracts exceed ceiling ({write_ceiling})"
        )

    return errors


def _check_sql_snippet(
    crate: str,
    rel_path: str,
    line_no: int,
    lit: str,
    logical_tables: Set[str],
    tables_map: Dict[str, dict],
    contract_lookup: Dict[Tuple[str, str], str],
    allowlist_pairs: Set[Tuple[str, str]],
    errors: List[str],
    stats: Dict[str, int],
) -> None:
    sql_marker_re = re.compile(
        r"\b(SELECT|INSERT|UPDATE|DELETE|TRUNCATE|WITH)\b", re.IGNORECASE
    )
    if not sql_marker_re.search(lit):
        return
    slit = strip_sql_comments(lit, strip_inside_dollar=False)
    reads, writes, upd_del_raw = extract_sql_table_refs(slit, logical_tables)
    if not writes and not reads:
        return
    stats["sql_literals"] += 1

    # Check 3: Cross-domain SQL access
    for t in writes:
        owner = tables_map.get(t, {}).get("owner")
        if owner == crate:
            continue
        mode = contract_lookup.get((crate, t))
        if mode != "legacy_write_migration_pending":
            errors.append(
                f"UNCONTRACTED_CROSS_DOMAIN_WRITE: {crate} -> {t} "
                f"(owner={owner}) at {rel_path}:{line_no}"
            )

    for t in reads:
        owner = tables_map.get(t, {}).get("owner")
        if owner == crate:
            continue
        mode = contract_lookup.get((crate, t))
        if mode not in VALID_CONTRACT_MODES:
            errors.append(
                f"UNCONTRACTED_CROSS_DOMAIN_READ: {crate} -> {t} "
                f"(owner={owner}) at {rel_path}:{line_no}"
            )

    # Check 4: R1-R3 predicate enforcement on mailbox_scoped / user_scoped tables
    upd_del_targets = [
        t
        for t in upd_del_raw
        if tables_map.get(t, {}).get("security_class") in SCOPED_SECURITY_CLASSES
    ]
    if upd_del_targets:
        where_ctx = extract_where_context(slit)
        for t in upd_del_targets:
            allowed_toks = scope_tokens_for_table(tables_map[t])
            if not has_scope_token(where_ctx, allowed_toks):
                if (rel_path, t) in allowlist_pairs:
                    stats["r3_allowlisted"] += 1
                else:
                    snippet = re.sub(r"\s+", " ", slit).strip()[:120]
                    errors.append(
                        f"R3_MISSING_PREDICATE: {rel_path}:{line_no} table={t} "
                        f"(UPDATE/DELETE lacks ownership predicate in WHERE): {snippet}"
                    )

    if re.search(r"\bSELECT\b", slit, re.IGNORECASE):
        scoped_reads = [
            t
            for t in reads
            if tables_map.get(t, {}).get("security_class") in SCOPED_SECURITY_CLASSES
        ]
        if scoped_reads:
            pred_ctx = extract_predicate_context(slit)
            for t in scoped_reads:
                allowed_toks = scope_tokens_for_table(tables_map[t])
                if not has_scope_token(pred_ctx, allowed_toks):
                    if (rel_path, t) in allowlist_pairs:
                        stats["r1_allowlisted"] += 1
                    else:
                        snippet = re.sub(r"\s+", " ", slit).strip()[:120]
                        errors.append(
                            f"R1_MISSING_PREDICATE: {rel_path}:{line_no} table={t} "
                            "(SELECT lacks ownership predicate in WHERE/JOIN ON/HAVING)"
                            f": {snippet}"
                        )


def check_rust_domains(
    manifest: dict,
    logical_tables: Set[str],
    domains_dir: Path,
    repo_root: Path,
) -> Tuple[List[str], Dict[str, int]]:
    """Checks 3 & 4: Cross-domain SQL access and R1-R3 predicate enforcement."""
    errors: List[str] = []
    stats = {
        "files_scanned": 0,
        "sql_literals": 0,
        "r1_allowlisted": 0,
        "r3_allowlisted": 0,
    }

    if not domains_dir.exists():
        return errors, stats

    tables_map: Dict[str, dict] = manifest.get("tables", {})
    contract_lookup: Dict[Tuple[str, str], str] = {}
    for t, entry in tables_map.items():
        if not isinstance(entry, dict):
            continue
        for c in entry.get("read_contracts", []):
            if (
                isinstance(c, dict)
                and isinstance(c.get("consumer"), str)
                and isinstance(c.get("mode"), str)
            ):
                contract_lookup[(c["consumer"], t)] = c["mode"]

    allowlist_pairs: Set[Tuple[str, str]] = set()
    for item in manifest.get("r1_r3_allowlist", []):
        if (
            isinstance(item, dict)
            and isinstance(item.get("file"), str)
            and isinstance(item.get("table"), str)
        ):
            file_norm = item["file"].replace("\\", "/")
            allowlist_pairs.add((file_norm, item["table"].lower()))

    def make_rel_path(path: Path, crate: str, crate_dir: Path) -> str:
        try:
            return str(path.resolve().relative_to(repo_root.resolve())).replace(
                "\\", "/"
            )
        except ValueError:
            rel_inner = path.relative_to(crate_dir)
            return f"server/crates/domains/{crate}/{rel_inner}".replace("\\", "/")

    for crate_dir in sorted(domains_dir.iterdir()):
        if not crate_dir.is_dir():
            continue
        crate = crate_dir.name
        src_dir = crate_dir / "src"
        if not src_dir.exists():
            continue

        for rs_file in sorted(src_dir.rglob("*.rs")):
            if (
                rs_file.name.endswith("_test.rs")
                or rs_file.name.endswith("_tests.rs")
                or rs_file.name == "tests.rs"
            ):
                continue
            stats["files_scanned"] += 1
            raw = rs_file.read_text(encoding="utf-8", errors="replace")
            code = strip_rust_comments_and_tests(raw)
            rel_path = make_rel_path(rs_file, crate, crate_dir)
            for line_no, lit in extract_rust_string_literals(code):
                _check_sql_snippet(
                    crate,
                    rel_path,
                    line_no,
                    lit,
                    logical_tables,
                    tables_map,
                    contract_lookup,
                    allowlist_pairs,
                    errors,
                    stats,
                )

        # Also scan include_str!("*.sql") SQL files under domain src/.
        for sql_file in sorted(src_dir.rglob("*.sql")):
            stats["files_scanned"] += 1
            raw_sql = sql_file.read_text(encoding="utf-8", errors="replace")
            rel_path = make_rel_path(sql_file, crate, crate_dir)
            _check_sql_snippet(
                crate,
                rel_path,
                1,
                raw_sql,
                logical_tables,
                tables_map,
                contract_lookup,
                allowlist_pairs,
                errors,
                stats,
            )

    return errors, stats


def main(argv: Optional[List[str]] = None) -> int:
    _ = argv
    repo_root = Path(__file__).resolve().parents[2]
    default_manifest = str(repo_root / "config/table-ownership-manifest.json")
    default_schema = str(repo_root / "sql/dbschema")
    default_domains = str(repo_root / "server/crates/domains")

    manifest_path = Path(os.environ.get("TABLE_MANIFEST", default_manifest))
    schema_dir = Path(os.environ.get("TABLE_SCHEMA_DIR", default_schema))
    domains_dir = Path(os.environ.get("TABLE_RUST_DOMAINS_DIR", default_domains))

    try:
        logical_tables, partitions, rls_enabled, rls_forced = extract_schema_state(
            schema_dir
        )
    except SchemaExtractionError as exc:
        print(f"ERROR [Check 1 - Schema Extraction]: {exc}", file=sys.stderr)
        return 3

    if not manifest_path.is_file():
        print(
            f"ERROR [Check 2 - Manifest]: manifest file not found: {manifest_path}",
            file=sys.stderr,
        )
        return 1

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"ERROR [Check 2 - Manifest]: failed to parse {manifest_path}: {exc}",
            file=sys.stderr,
        )
        return 1

    errors: List[str] = []
    errors.extend(
        validate_manifest_and_schema(manifest, logical_tables, rls_enabled, rls_forced)
    )
    domain_errors, stats = check_rust_domains(
        manifest, logical_tables, domains_dir, repo_root
    )
    errors.extend(domain_errors)

    if errors:
        print(
            f"table-ownership-manifest guard FAILED ({len(errors)} violation(s); "
            f"{len(logical_tables)} logical tables, "
            f"{len(partitions)} partitions excluded):",
            file=sys.stderr,
        )
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        return 1

    tables_map = manifest["tables"]
    enforced_cnt = sum(
        1 for e in tables_map.values() if e.get("rls_posture") == "enforced"
    )
    pending_cnt = sum(
        1
        for e in tables_map.values()
        if e.get("rls_posture") == "pending_wave1_cutover"
    )
    na_cnt = sum(
        1 for e in tables_map.values() if e.get("rls_posture") == "not_applicable"
    )
    read_contracts = sum(
        1
        for e in tables_map.values()
        for c in e.get("read_contracts", [])
        if c.get("mode") == "read_only"
    )
    write_contracts = sum(
        1
        for e in tables_map.values()
        for c in e.get("read_contracts", [])
        if c.get("mode") == "legacy_write_migration_pending"
    )
    pending_ceil = manifest["legacy_rls_pending_ceiling"]
    write_ceil = manifest["legacy_write_migration_ceiling"]
    print(
        "table-ownership-manifest: PASS "
        f"(tables={len(logical_tables)}, partitions_excluded={len(partitions)}, "
        f"rls_enforced={enforced_cnt}, rls_pending={pending_cnt}/{pending_ceil}, "
        f"rls_na={na_cnt}, cross_domain_reads={read_contracts}, "
        f"legacy_cross_domain_writes={write_contracts}/{write_ceil}, "
        f"r1_r3_allowlist={len(manifest['r1_r3_allowlist'])}, "
        f"files={stats['files_scanned']}, sql_literals={stats['sql_literals']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
