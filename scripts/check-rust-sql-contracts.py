#!/usr/bin/env python3
"""Static guard for Setjoin's zero-proc-macro typed SQL contract catalog (#541).

Enforces:
- PROC_MACRO_FORBIDDEN: zero `proc-macro = true` in `crates/sql-catalog` or
  `tests/sql-contracts`, zero `syn`/`quote`/`sqlx` in `crates/sql-catalog`, and
  zero `sqlx`/`sqlx-macros` in `server-rust/Cargo.lock`.
- SQL_INTERPOLATION_FORBIDDEN: zero runtime `format!` SQL interpolation in
  catalog-enforced crates and monotonic downward ratchet on legacy crates.
- UNCATALOGED_SQL: zero uncataloged raw SQL literals outside `src/sql.rs` in
  catalog-enforced crates and monotonic downward ratchet on legacy crates.
- AUDIT_POSTURE_*: `SqlAuditPosture::ReducerWritesCoreAudit` is permitted ONLY
  in `crates/domains/*/src/sql.rs`, must parse strictly as a single top-level
  `SELECT [public.]<fn>(...)`, and must target a PL/pgSQL reducer in
  `mailserver/sql/reducers/*.sql` that invokes `audit_write(..., 'core')`
  outside any `EXCEPTION WHEN OTHERS` handler (#546a).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from dataclasses import dataclass

CATALOG_ENFORCED_DEFAULT = [
    "approvals",
    "blobs",
    "calendar",
    "rules",
    "user-settings",
]

SQL_START_RE = re.compile(
    r"^\s*(?:SELECT\b|INSERT\s+INTO\b|UPDATE\s+[A-Za-z_][A-Za-z0-9_.\"]*\s+SET\b"
    r"|DELETE\s+FROM\b|WITH\s+(?:RECURSIVE\s+)?[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*\([^)]*\))?\s+AS\s*\()",
    re.IGNORECASE,
)

SQL_STRUCTURE_RE = re.compile(
    r"\b(?:FROM|WHERE|VALUES|SET|RETURNING|INTO|JOIN)\b|\$\d+|\w+\s*\(",
    re.IGNORECASE,
)

SQL_FORMAT_HELPER_RE = re.compile(
    r"to_char\s*\([^)]*AT\s+TIME\s+ZONE",
    re.IGNORECASE,
)

BANNED_CATALOG_DEPS_RE = re.compile(
    r"^\s*(?:syn|quote|proc-macro2|sqlx|sqlx-macros)\s*=",
    re.MULTILINE,
)

PROC_MACRO_FLAG_RE = re.compile(
    r"^\s*proc-macro\s*=\s*true\b",
    re.MULTILINE,
)

SQLX_LOCK_RE = re.compile(
    r'^\s*name\s*=\s*"(?:sqlx|sqlx-macros)"\s*$',
    re.MULTILINE,
)

# Infrastructure files allowed to reference `ReducerWritesCoreAudit` directly.
AUDIT_POSTURE_INFRA_FILES = {
    "crates/sql-catalog/src/lib.rs",
    "crates/pg/src/capability.rs",
    "crates/pg/src/tests.rs",
    "tests/sql-contracts/src/main.rs",
}

REDUCER_DEF_RE = re.compile(
    r"\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+"
    r"(?:public\.)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
    re.IGNORECASE,
)

SELECT_CALL_RE = re.compile(
    r"^\s*SELECT\s+(?:public\.)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
    re.IGNORECASE,
)

FORBIDDEN_ARG_SQL_RE = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|WITH|FROM|UNION|INTERSECT|EXCEPT)\b",
    re.IGNORECASE,
)

VALID_CALL_TAIL_RE = re.compile(
    r"^\s*(?:::\s*[a-zA-Z_][a-zA-Z0-9_\s]*(?:\[\])?)*"
    r"(?:\s+AS\s+[a-zA-Z_][a-zA-Z0-9_]*)?\s*$",
    re.IGNORECASE,
)

ACTOR_FIRST_ARG_RE = re.compile(
    r"^\s*\$1(?:\s*::\s*(?:bigint|int8))?\s*$",
    re.IGNORECASE,
)


@dataclass
class Token:
    """Minimal Rust lexical token for comment/test-aware SQL scanning."""

    kind: str  # "ident", "string", "punct"
    value: str
    line: int


def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_"


def _is_ident_cont(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _match_raw_string(src: str, pos: int) -> tuple[int, str] | None:
    """Parse r\"...\", r#\"...\"#, br#\"...\"#, cr#\"...\"# starting at pos."""
    n = len(src)
    i = pos
    if src[i] in ("b", "c") and i + 1 < n and src[i + 1] == "r":
        i += 2
    elif src[i] == "r":
        i += 1
    else:
        return None
    hashes = 0
    while i < n and src[i] == "#":
        hashes += 1
        i += 1
    if i >= n or src[i] != '"':
        return None
    i += 1
    start = i
    closing = '"' + ("#" * hashes)
    end = src.find(closing, start)
    if end == -1:
        return (n, src[start:])
    return (end + len(closing), src[start:end])


def _match_normal_string(src: str, pos: int) -> tuple[int, str]:
    """Parse normal/byte/c string literal starting at the opening quote."""
    n = len(src)
    i = pos + 1
    chars: list[str] = []
    while i < n:
        ch = src[i]
        if ch == "\\":
            if i + 1 < n:
                nxt = src[i + 1]
                if nxt == "\n":
                    i += 2
                    while i < n and src[i] in (" ", "\t", "\r"):
                        i += 1
                    continue
                if nxt == "n":
                    chars.append("\n")
                elif nxt == "t":
                    chars.append("\t")
                elif nxt == "r":
                    chars.append("\r")
                else:
                    chars.append(nxt)
                i += 2
                continue
        if ch == '"':
            return (i + 1, "".join(chars))
        chars.append(ch)
        i += 1
    return (n, "".join(chars))


def _skip_char_or_lifetime(src: str, pos: int) -> int:
    """Advance past a Rust char literal ('a', '\\'', '\\\\', '\"') or lifetime."""
    n = len(src)
    i = pos + 1
    if i >= n:
        return n
    if src[i] == "\\":
        # Consume backslash + escaped char, then scan forward to closing `'`.
        i += 2
        while i < n and src[i] != "'":
            i += 1
        return min(i + 1, n)
    if i + 1 < n and src[i + 1] == "'":
        return i + 2
    # Lifetime token like 'a or 'static: consume single quote only.
    return pos + 1


def tokenize_rust(src: str) -> list[Token]:
    """Tokenize Rust source skipping line/nested-block comments and char literals."""
    tokens: list[Token] = []
    n = len(src)
    i = 0
    line = 1
    while i < n:
        ch = src[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch in (" ", "\t", "\r"):
            i += 1
            continue
        # Line comment
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            nl = src.find("\n", i + 2)
            if nl == -1:
                break
            i = nl
            continue
        # Nested block comment
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            i += 2
            while i < n and depth > 0:
                if src[i] == "\n":
                    line += 1
                    i += 1
                elif src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth += 1
                    i += 2
                elif src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            continue
        # Raw strings: r"...", r#"..."#, br#"..."#, cr#"..."#
        raw_match = _match_raw_string(src, i)
        if raw_match is not None:
            end_pos, text = raw_match
            tokens.append(Token("string", text, line))
            line += src[i:end_pos].count("\n")
            i = end_pos
            continue
        # Byte/C strings: b"...", c"..."
        if ch in ("b", "c") and i + 1 < n and src[i + 1] == '"':
            end_pos, text = _match_normal_string(src, i + 1)
            tokens.append(Token("string", text, line))
            line += src[i:end_pos].count("\n")
            i = end_pos
            continue
        # Byte char literal: b'...'
        if ch == "b" and i + 1 < n and src[i + 1] == "'":
            end_pos = _skip_char_or_lifetime(src, i + 1)
            line += src[i:end_pos].count("\n")
            i = end_pos
            continue
        # Normal string literal
        if ch == '"':
            end_pos, text = _match_normal_string(src, i)
            tokens.append(Token("string", text, line))
            line += src[i:end_pos].count("\n")
            i = end_pos
            continue
        # Char literal or lifetime
        if ch == "'":
            end_pos = _skip_char_or_lifetime(src, i)
            line += src[i:end_pos].count("\n")
            i = end_pos
            continue
        # Identifier
        if _is_ident_start(ch):
            start = i
            i += 1
            while i < n and _is_ident_cont(src[i]):
                i += 1
            tokens.append(Token("ident", src[start:i], line))
            continue
        # Single-char punctuation
        tokens.append(Token("punct", ch, line))
        i += 1
    return tokens


def _split_top_level_args(parts: list[str]) -> list[list[str]]:
    """Split a balanced parenthesized argument list by top-level commas."""
    groups: list[list[str]] = []
    cur: list[str] = []
    depth = 0
    for item in parts:
        if item == "(":
            depth += 1
            cur.append(item)
        elif item == ")":
            depth -= 1
            cur.append(item)
        elif item == "," and depth == 0:
            if cur:
                groups.append(cur)
                cur = []
        else:
            cur.append(item)
    if cur:
        groups.append(cur)
    return groups


def _cfg_pred_is_test_only(parts: list[str]) -> bool:
    """Return True iff a `cfg(...)` predicate guarantees `test` is enabled."""
    if parts == ["test"]:
        return True
    if len(parts) >= 3 and parts[0] == "all" and parts[1] == "(" and parts[-1] == ")":
        return any(
            _cfg_pred_is_test_only(arg) for arg in _split_top_level_args(parts[2:-1])
        )
    return False


def _is_cfg_test_attr(attr_parts: list[str]) -> bool:
    """Return True for `#[cfg(test)]` or `#[cfg(all(test, ...))]`, never `not(test)`."""
    if (
        len(attr_parts) >= 3
        and attr_parts[0] == "cfg"
        and attr_parts[1] == "("
        and attr_parts[-1] == ")"
    ):
        return _cfg_pred_is_test_only(attr_parts[2:-1])
    return False


def strip_cfg_test_tokens(tokens: list[Token]) -> list[Token]:
    """Drop items annotated with `#[cfg(test)]` (or `#[cfg(all(test, ...))]`)."""
    out: list[Token] = []
    n = len(tokens)
    i = 0
    while i < n:
        if (
            tokens[i].kind == "punct"
            and tokens[i].value == "#"
            and i + 1 < n
            and tokens[i + 1].kind == "punct"
            and tokens[i + 1].value == "["
        ):
            # Capture balanced [...] attribute
            depth = 0
            j = i + 1
            attr_parts: list[str] = []
            while j < n:
                if tokens[j].kind == "punct" and tokens[j].value == "[":
                    depth += 1
                    if depth > 1:
                        attr_parts.append(tokens[j].value)
                elif tokens[j].kind == "punct" and tokens[j].value == "]":
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
                    attr_parts.append(tokens[j].value)
                else:
                    attr_parts.append(tokens[j].value)
                j += 1
            is_cfg_test = _is_cfg_test_attr(attr_parts)
            if is_cfg_test:
                # Skip any stacked attributes before the item
                k = j
                while (
                    k + 1 < n
                    and tokens[k].kind == "punct"
                    and tokens[k].value == "#"
                    and tokens[k + 1].kind == "punct"
                    and tokens[k + 1].value == "["
                ):
                    adepth = 0
                    k += 1
                    while k < n:
                        if tokens[k].kind == "punct" and tokens[k].value == "[":
                            adepth += 1
                        elif tokens[k].kind == "punct" and tokens[k].value == "]":
                            adepth -= 1
                            if adepth == 0:
                                k += 1
                                break
                        k += 1
                # Skip until matching `{ ... }` block or terminating `;`
                brace_depth = 0
                seen_brace = False
                while k < n:
                    tk = tokens[k]
                    if tk.kind == "punct" and tk.value == "{":
                        brace_depth += 1
                        seen_brace = True
                    elif tk.kind == "punct" and tk.value == "}":
                        brace_depth -= 1
                        if seen_brace and brace_depth == 0:
                            k += 1
                            break
                    elif tk.kind == "punct" and tk.value == ";" and not seen_brace:
                        k += 1
                        break
                    k += 1
                i = k
                continue
        out.append(tokens[i])
        i += 1
    return out


def looks_like_sql(text: str) -> bool:
    """Return True when a string literal contains an executable SQL statement."""
    if not SQL_START_RE.search(text):
        return False
    return bool(SQL_STRUCTURE_RE.search(text))


def looks_like_format_sql(text: str) -> bool:
    """Return True when a `format!` template builds a SQL statement or fragment."""
    if looks_like_sql(text):
        return True
    return bool(SQL_FORMAT_HELPER_RE.search(text))


def _extract_format_template(arg_tokens: list[Token]) -> tuple[str, int] | None:
    """Extract the template text and line from a `format!` first argument."""
    if not arg_tokens:
        return None
    if arg_tokens[0].kind == "string":
        return (arg_tokens[0].value, arg_tokens[0].line)
    # Handle `format!(concat!("SELECT ", "{col} FROM ..."))` (including nested concat!).
    if (
        len(arg_tokens) >= 3
        and arg_tokens[0].kind == "ident"
        and arg_tokens[0].value == "concat"
        and arg_tokens[1].kind == "punct"
        and arg_tokens[1].value == "!"
    ):
        parts = [tk.value for tk in arg_tokens if tk.kind == "string"]
        if parts:
            return ("".join(parts), arg_tokens[0].line)
    return None


def scan_rust_file(
    rs_path: pathlib.Path,
    is_catalog_file: bool,
) -> tuple[list[int], list[int]]:
    """Return (format_sql_lines, uncataloged_sql_lines) for one Rust source file."""
    src = rs_path.read_text(encoding="utf-8", errors="ignore")
    tokens = strip_cfg_test_tokens(tokenize_rust(src))
    format_lines: list[int] = []
    uncataloged_lines: list[int] = []

    n = len(tokens)
    i = 0
    while i < n:
        tok = tokens[i]
        # Detect `format!( ... )`
        if (
            tok.kind == "ident"
            and tok.value == "format"
            and i + 2 < n
            and tokens[i + 1].kind == "punct"
            and tokens[i + 1].value == "!"
            and tokens[i + 2].kind == "punct"
            and tokens[i + 2].value in ("(", "[", "{")
        ):
            open_ch = tokens[i + 2].value
            expected_close = {"(": ")", "[": "]", "{": "}"}[open_ch]
            depth = 1
            j = i + 3
            first_arg: list[Token] = []
            in_first_arg = True
            while j < n and depth > 0:
                tj = tokens[j]
                if tj.kind == "punct" and tj.value == open_ch:
                    depth += 1
                    if in_first_arg:
                        first_arg.append(tj)
                elif tj.kind == "punct" and tj.value == expected_close:
                    depth -= 1
                    if depth > 0 and in_first_arg:
                        first_arg.append(tj)
                elif depth == 1 and tj.kind == "punct" and tj.value == ",":
                    in_first_arg = False
                elif in_first_arg:
                    first_arg.append(tj)
                j += 1
            tmpl = _extract_format_template(first_arg)
            if tmpl is not None and looks_like_format_sql(tmpl[0]):
                format_lines.append(tmpl[1])
            i = j
            continue

        if tok.kind == "string" and not is_catalog_file and looks_like_sql(tok.value):
            uncataloged_lines.append(tok.line)
        i += 1

    return (format_lines, uncataloged_lines)


def check_proc_macro_ban(server_rust: pathlib.Path, errors: list[str]) -> None:
    """Enforce zero proc-macro expansion overhead and zero sqlx dependency."""
    catalog_toml = server_rust / "crates/sql-catalog/Cargo.toml"
    contracts_toml = server_rust / "tests/sql-contracts/Cargo.toml"
    lock_file = server_rust / "Cargo.lock"

    for manifest in (catalog_toml, contracts_toml):
        if manifest.is_file():
            text = manifest.read_text(encoding="utf-8", errors="ignore")
            if PROC_MACRO_FLAG_RE.search(text):
                errors.append(
                    f"PROC_MACRO_FORBIDDEN: {manifest.relative_to(server_rust)} "
                    "declares proc-macro = true"
                )
            if manifest == catalog_toml and BANNED_CATALOG_DEPS_RE.search(text):
                errors.append(
                    "PROC_MACRO_FORBIDDEN: crates/sql-catalog/Cargo.toml depends on "
                    "banned proc-macro/sqlx crate"
                )

    if lock_file.is_file():
        lock_text = lock_file.read_text(encoding="utf-8", errors="ignore")
        if SQLX_LOCK_RE.search(lock_text):
            errors.append(
                "PROC_MACRO_FORBIDDEN: server-rust/Cargo.lock contains sqlx or "
                "sqlx-macros"
            )


def _strip_sql_comments(sql: str) -> str:
    """Strip SQL `-- ...` and `/* ... */` comments, preserving single-quoted strings."""
    out: list[str] = []
    n = len(sql)
    i = 0
    while i < n:
        ch = sql[i]
        if ch == "'":
            out.append(ch)
            i += 1
            while i < n:
                out.append(sql[i])
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        out.append(sql[i + 1])
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            nl = sql.find("\n", i + 2)
            if nl == -1:
                break
            out.append("\n")
            i = nl + 1
            continue
        if ch == "/" and i + 1 < n and sql[i + 1] == "*":
            depth = 1
            i += 2
            while i < n and depth > 0:
                if sql[i] == "/" and i + 1 < n and sql[i + 1] == "*":
                    depth += 1
                    i += 2
                elif sql[i] == "*" and i + 1 < n and sql[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            out.append(" ")
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _strip_sql_single_quoted(sql: str) -> str:
    """Replace single-quoted SQL literals with spaces for keyword scanning."""
    out: list[str] = []
    n = len(sql)
    i = 0
    while i < n:
        if sql[i] == "'":
            out.append(" ")
            i += 1
            while i < n:
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        out.append(sql[i])
        i += 1
    return "".join(out)


def _split_sql_top_level_args(args_str: str) -> list[str]:
    """Split a SQL function argument list on top-level commas."""
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    n = len(args_str)
    i = 0
    while i < n:
        ch = args_str[i]
        if ch == "'":
            cur.append(ch)
            i += 1
            while i < n:
                cur.append(args_str[i])
                if args_str[i] == "'":
                    if i + 1 < n and args_str[i + 1] == "'":
                        cur.append(args_str[i + 1])
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    if cur or parts:
        parts.append("".join(cur))
    return parts


def parse_single_select_reducer_call(sql: str) -> str | None:
    """Return lowercase fn name iff sql is SELECT [public.]fn($1, ...)."""
    cleaned = _strip_sql_comments(sql).strip()
    if not cleaned:
        return None
    if ";" in _strip_sql_single_quoted(cleaned):
        return None
    m = SELECT_CALL_RE.match(cleaned)
    if not m:
        return None
    fn_name = m.group(1).lower()
    open_idx = m.end() - 1
    depth = 0
    i = open_idx
    n = len(cleaned)
    close_idx = -1
    while i < n:
        ch = cleaned[i]
        if ch == "'":
            i += 1
            while i < n:
                if cleaned[i] == "'":
                    if i + 1 < n and cleaned[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                close_idx = i
                break
        i += 1
    if close_idx == -1:
        return None
    raw_args = cleaned[open_idx + 1 : close_idx]
    args_src = _strip_sql_single_quoted(raw_args)
    if FORBIDDEN_ARG_SQL_RE.search(args_src):
        return None
    top_args = _split_sql_top_level_args(raw_args)
    if not top_args or not ACTOR_FIRST_ARG_RE.match(top_args[0]):
        return None
    tail = cleaned[close_idx + 1 :]
    if not VALID_CALL_TAIL_RE.match(tail):
        return None
    return fn_name


def _tokenize_plpgsql(body: str) -> list[tuple[str, str]]:
    """Tokenize PL/pgSQL body into (kind, value) skipping comments."""
    tokens: list[tuple[str, str]] = []
    n = len(body)
    i = 0
    while i < n:
        ch = body[i]
        if ch in (" ", "\t", "\r", "\n"):
            i += 1
            continue
        if ch == "-" and i + 1 < n and body[i + 1] == "-":
            nl = body.find("\n", i + 2)
            if nl == -1:
                break
            i = nl + 1
            continue
        if ch == "/" and i + 1 < n and body[i + 1] == "*":
            depth = 1
            i += 2
            while i < n and depth > 0:
                if body[i] == "/" and i + 1 < n and body[i + 1] == "*":
                    depth += 1
                    i += 2
                elif body[i] == "*" and i + 1 < n and body[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            continue
        if ch == "'":
            i += 1
            chars: list[str] = []
            while i < n:
                if body[i] == "'":
                    if i + 1 < n and body[i + 1] == "'":
                        chars.append("'")
                        i += 2
                        continue
                    i += 1
                    break
                chars.append(body[i])
                i += 1
            tokens.append(("str", "".join(chars)))
            continue
        if ch.isalpha() or ch == "_":
            start = i
            i += 1
            while i < n and (body[i].isalnum() or body[i] == "_"):
                i += 1
            tokens.append(("word", body[start:i].lower()))
            continue
        if ch in ("(", ")", ",", ";", "."):
            tokens.append(("punct", ch))
        i += 1
    return tokens


def _extract_dollar_quoted_body(src: str, start_pos: int) -> str | None:
    """Extract the first `$tag$ ... $tag$` body starting at or after `start_pos`."""
    m = re.search(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$", src[start_pos:])
    if not m:
        return None
    delim = m.group(0)
    body_start = start_pos + m.end()
    body_end = src.find(delim, body_start)
    if body_end == -1:
        return None
    return src[body_start:body_end]


def load_reducer_bodies(root: pathlib.Path) -> dict[str, list[tuple[str, str]]]:
    """Load `CREATE [OR REPLACE] FUNCTION` bodies from `mailserver/sql/reducers/`."""
    bodies: dict[str, list[tuple[str, str]]] = {}
    reducers_dir = root / "mailserver/sql/reducers"
    if not reducers_dir.is_dir():
        return bodies
    for sql_file in sorted(reducers_dir.glob("*.sql")):
        src = sql_file.read_text(encoding="utf-8", errors="ignore")
        rel = sql_file.relative_to(root).as_posix()
        for m in REDUCER_DEF_RE.finditer(src):
            fn_name = m.group(1).lower()
            body = _extract_dollar_quoted_body(src, m.end())
            if body is not None:
                bodies.setdefault(fn_name, []).append((rel, body))
    return bodies


def analyze_reducer_audit(
    body: str, extra_core_fns: set[str] | None = None
) -> tuple[bool, bool]:
    """Return `(has_core_audit, has_swallowed_audit)` for a PL/pgSQL function body."""
    toks = _tokenize_plpgsql(body)
    n = len(toks)
    # Stack entries are either `"case"` or `[in_exc, has_audit, has_when_others]`.
    stack: list[str | list[bool]] = []
    has_core_audit = False
    has_swallowed_audit = False

    def _current_begin() -> list[bool] | None:
        for frame in reversed(stack):
            if isinstance(frame, list):
                return frame
        return None

    i = 0
    while i < n:
        kind, val = toks[i]
        if kind == "word" and val == "begin":
            stack.append([False, False, False])
            i += 1
            continue
        if kind == "word" and val == "case":
            stack.append("case")
            i += 1
            continue
        if kind == "word" and val == "exception":
            cur = _current_begin()
            if cur is not None:
                cur[0] = True
            i += 1
            continue
        if kind == "word" and val == "when":
            cur = _current_begin()
            if cur is not None and cur[0]:
                # Scan until `then` to detect `WHEN ... OTHERS ... THEN`.
                k = i + 1
                while k < n and not (toks[k][0] == "word" and toks[k][1] == "then"):
                    if toks[k][0] == "word" and toks[k][1] == "others":
                        cur[2] = True
                    k += 1
            i += 1
            continue
        if kind == "word" and val == "end":
            nxt = toks[i + 1] if i + 1 < n else None
            if nxt is not None and nxt[0] == "word" and nxt[1] in ("if", "loop"):
                i += 2
                continue
            if nxt is not None and nxt[0] == "word" and nxt[1] == "case":
                if stack and stack[-1] == "case":
                    stack.pop()
                i += 2
                continue
            if stack and stack[-1] == "case":
                stack.pop()
                i += 1
                continue
            if stack and isinstance(stack[-1], list):
                frame = stack.pop()
                assert isinstance(frame, list)
                if frame[1] and frame[2]:
                    has_swallowed_audit = True
                parent = _current_begin()
                if parent is not None and frame[1]:
                    parent[1] = True
            i += 1
            continue
        if (
            kind == "word"
            and val == "audit_write"
            and i + 1 < n
            and toks[i + 1] == ("punct", "(")
        ):
            cur = _current_begin()
            if cur is not None:
                cur[1] = True
            depth = 1
            j = i + 2
            args: list[list[tuple[str, str]]] = []
            cur_arg: list[tuple[str, str]] = []
            while j < n and depth > 0:
                tk = toks[j]
                if tk == ("punct", "("):
                    depth += 1
                    cur_arg.append(tk)
                elif tk == ("punct", ")"):
                    depth -= 1
                    if depth > 0:
                        cur_arg.append(tk)
                elif depth == 1 and tk == ("punct", ","):
                    args.append(cur_arg)
                    cur_arg = []
                else:
                    cur_arg.append(tk)
                j += 1
            if cur_arg:
                args.append(cur_arg)
            if args and len(args[-1]) == 1 and args[-1][0] == ("str", "core"):
                has_core_audit = True
            i = j
            continue
        if (
            extra_core_fns
            and kind == "word"
            and val in extra_core_fns
            and i + 1 < n
            and toks[i + 1] == ("punct", "(")
        ):
            cur = _current_begin()
            if cur is not None:
                cur[1] = True
            has_core_audit = True
        i += 1

    # Handle any unclosed top-level frame defensively.
    for frame in stack:
        if isinstance(frame, list) and frame[1] and frame[2]:
            has_swallowed_audit = True

    return (has_core_audit, has_swallowed_audit)


def compute_core_audit_closure(
    reducer_bodies: dict[str, list[tuple[str, str]]],
) -> set[str]:
    """Fixed-point set of reducers that directly or transitively invoke
    `audit_write(..., 'core')` without swallowing it in EXCEPTION WHEN OTHERS."""
    core_fns: set[str] = set()
    for _ in range(4):
        changed = False
        for fn, defs in reducer_bodies.items():
            if fn in core_fns:
                continue
            for _rel, body in defs:
                has_core, has_swallowed = analyze_reducer_audit(body, core_fns)
                if has_core and not has_swallowed:
                    core_fns.add(fn)
                    changed = True
                    break
        if not changed:
            break
    return core_fns


def _extract_const_sql_expr(expr_tokens: list[Token]) -> str | None:
    """Resolve a static SQL string literal or `concat!(...)` expression."""
    if not expr_tokens:
        return None
    if len(expr_tokens) == 1 and expr_tokens[0].kind == "string":
        return expr_tokens[0].value
    if (
        len(expr_tokens) >= 4
        and expr_tokens[0].kind == "ident"
        and expr_tokens[0].value == "concat"
        and expr_tokens[1].kind == "punct"
        and expr_tokens[1].value == "!"
        and expr_tokens[2].kind == "punct"
        and expr_tokens[2].value == "("
        and expr_tokens[-1].kind == "punct"
        and expr_tokens[-1].value == ")"
    ):
        parts: list[str] = []
        for tk in expr_tokens[3:-1]:
            if tk.kind == "string":
                parts.append(tk.value)
            elif tk.kind == "punct" and tk.value == ",":
                continue
            else:
                return None
        return "".join(parts)
    return None


def _extract_contract_sql_field(body_tokens: list[Token]) -> str | None:
    """Extract the `sql: ...` field from tokens inside `SqlContract { ... }`."""
    n = len(body_tokens)
    depth = 0
    i = 0
    while i < n:
        tk = body_tokens[i]
        if tk.kind == "punct" and tk.value in ("(", "[", "{"):
            depth += 1
        elif tk.kind == "punct" and tk.value in (")", "]", "}"):
            depth -= 1
        elif (
            depth == 0
            and tk.kind == "ident"
            and tk.value == "sql"
            and i + 1 < n
            and body_tokens[i + 1].kind == "punct"
            and body_tokens[i + 1].value == ":"
        ):
            j = i + 2
            val_tokens: list[Token] = []
            fdepth = 0
            while j < n:
                tj = body_tokens[j]
                if tj.kind == "punct" and tj.value in ("(", "[", "{"):
                    fdepth += 1
                    val_tokens.append(tj)
                elif tj.kind == "punct" and tj.value in (")", "]", "}"):
                    fdepth -= 1
                    val_tokens.append(tj)
                elif fdepth == 0 and tj.kind == "punct" and tj.value == ",":
                    break
                else:
                    val_tokens.append(tj)
                j += 1
            return _extract_const_sql_expr(val_tokens)
        i += 1
    return None


def _is_audit_posture_allowed_file(rel: str) -> bool:
    if rel in AUDIT_POSTURE_INFRA_FILES:
        return True
    parts = pathlib.PurePosixPath(rel).parts
    if len(parts) == 4 and parts[:3] == ("crates", "pg", "tests"):
        return True
    return False


def _is_domain_sql_catalog(rel: str) -> bool:
    parts = pathlib.PurePosixPath(rel).parts
    return (
        len(parts) == 5
        and parts[0] == "crates"
        and parts[1] == "domains"
        and parts[3] == "src"
        and parts[4] == "sql.rs"
    )


def check_audit_posture_contracts(
    root: pathlib.Path,
    server_rust: pathlib.Path,
    errors: list[str],
) -> None:
    """Enforce all 4 `ReducerWritesCoreAudit` static security rules (#546a)."""
    reducer_bodies: dict[str, list[tuple[str, str]]] | None = None
    core_audit_fns: set[str] | None = None

    for rs_path in sorted(server_rust.rglob("*.rs")):
        rel_parts = rs_path.relative_to(server_rust).parts
        if "target" in rel_parts or (rel_parts and rel_parts[0] == "pilot"):
            continue
        rel = rs_path.relative_to(server_rust).as_posix()
        src = rs_path.read_text(encoding="utf-8", errors="ignore")
        if "ReducerWritesCoreAudit" not in src:
            continue
        tokens = tokenize_rust(src)
        audit_tok_indices = [
            idx
            for idx, tk in enumerate(tokens)
            if tk.kind == "ident" and tk.value == "ReducerWritesCoreAudit"
        ]
        if not audit_tok_indices:
            continue

        if _is_audit_posture_allowed_file(rel):
            continue

        # Rule 1: forbid ReducerWritesCoreAudit outside crates/domains/*/src/sql.rs.
        if not _is_domain_sql_catalog(rel):
            for idx in audit_tok_indices:
                errors.append(
                    f"AUDIT_POSTURE_FORBIDDEN: {rel}:{tokens[idx].line} "
                    "(ReducerWritesCoreAudit is only permitted in "
                    "crates/domains/*/src/sql.rs)"
                )
            continue

        # Inside crates/domains/*/src/sql.rs: every occurrence must live directly
        # inside a `SqlContract { ... }` literal and pass Rules 2, 3, and 4.
        if reducer_bodies is None:
            reducer_bodies = load_reducer_bodies(root)
            core_audit_fns = compute_core_audit_closure(reducer_bodies)

        covered_indices: set[int] = set()
        n = len(tokens)
        i = 0
        while i < n:
            if (
                tokens[i].kind == "ident"
                and tokens[i].value == "SqlContract"
                and i + 1 < n
                and tokens[i + 1].kind == "punct"
                and tokens[i + 1].value == "{"
            ):
                depth = 1
                j = i + 2
                while j < n and depth > 0:
                    if tokens[j].kind == "punct" and tokens[j].value == "{":
                        depth += 1
                    elif tokens[j].kind == "punct" and tokens[j].value == "}":
                        depth -= 1
                    j += 1
                block_audit = [idx for idx in audit_tok_indices if i + 2 <= idx < j - 1]
                if block_audit:
                    covered_indices.update(block_audit)
                    line = tokens[block_audit[0]].line
                    sql_text = _extract_contract_sql_field(tokens[i + 2 : j - 1])
                    if sql_text is None:
                        errors.append(
                            f"AUDIT_POSTURE_SQL_INVALID: {rel}:{line} "
                            "(cannot statically resolve sql field for "
                            "ReducerWritesCoreAudit contract)"
                        )
                        i = j
                        continue
                    # Rule 2: single top-level SELECT [public.]<fn>($1, ...) only.
                    fn_name = parse_single_select_reducer_call(sql_text)
                    if fn_name is None:
                        errors.append(
                            f"AUDIT_POSTURE_SQL_INVALID: {rel}:{line} "
                            "(ReducerWritesCoreAudit SQL must be a single "
                            "top-level SELECT [public.]<fn>($1, ...) with $1 as "
                            "first actor arg and no CTEs or inline DML)"
                        )
                        i = j
                        continue
                    # Rule 3 & 4: resolve reducer body, require 'core' audit_write
                    # and forbid EXCEPTION WHEN OTHERS wrapping audit_write.
                    defs = reducer_bodies.get(fn_name, [])
                    if not defs:
                        errors.append(
                            f"AUDIT_POSTURE_REDUCER_MISSING: {rel}:{line} "
                            f"(reducer '{fn_name}' not found in "
                            "mailserver/sql/reducers/*.sql)"
                        )
                        i = j
                        continue
                    any_core = False
                    for def_rel, body in defs:
                        has_core, has_swallowed = analyze_reducer_audit(body, core_audit_fns)
                        if has_swallowed:
                            errors.append(
                                f"AUDIT_POSTURE_SWALLOWED_AUDIT: {rel}:{line} "
                                f"(reducer '{fn_name}' in {def_rel} wraps "
                                "audit_write in EXCEPTION WHEN OTHERS)"
                            )
                        if has_core:
                            any_core = True
                    if not any_core:
                        errors.append(
                            f"AUDIT_POSTURE_CORE_AUDIT_MISSING: {rel}:{line} "
                            f"(reducer '{fn_name}' does not invoke "
                            "audit_write(..., 'core'))"
                        )
                i = j
                continue
            i += 1

        for idx in audit_tok_indices:
            if idx not in covered_indices:
                errors.append(
                    f"AUDIT_POSTURE_FORBIDDEN: {rel}:{tokens[idx].line} "
                    "(ReducerWritesCoreAudit must appear directly inside a "
                    "SqlContract struct literal)"
                )


def collect_domain_findings(
    server_rust: pathlib.Path,
) -> tuple[dict[str, list[int]], dict[str, list[int]]]:
    """Scan all `crates/domains/*/src/**/*.rs` files."""
    domains_dir = server_rust / "crates/domains"
    fmt_map: dict[str, list[int]] = {}
    raw_map: dict[str, list[int]] = {}
    if not domains_dir.is_dir():
        return (fmt_map, raw_map)

    for rs_path in sorted(domains_dir.rglob("*.rs")):
        rel_domain = rs_path.relative_to(domains_dir).parts
        if len(rel_domain) < 2 or rel_domain[1] != "src":
            continue
        rel = rs_path.relative_to(server_rust).as_posix()
        # `crates/domains/<crate>/src/sql.rs` is the typed contract catalog file.
        is_catalog = len(rel_domain) == 3 and rel_domain[2] == "sql.rs"
        fmt_lines, raw_lines = scan_rust_file(rs_path, is_catalog)
        if fmt_lines:
            fmt_map[rel] = fmt_lines
        if raw_lines:
            raw_map[rel] = raw_lines
    return (fmt_map, raw_map)


def main() -> int:
    """Entry point for `check-rust-sql-contracts.py`."""
    default_root = pathlib.Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=default_root,
        help="Repository root containing server-rust/ and config/",
    )
    parser.add_argument(
        "--ratchet",
        type=pathlib.Path,
        default=None,
        help="Path to sql-contracts-legacy-ratchet.json",
    )
    parser.add_argument(
        "--write-ratchet",
        action="store_true",
        help="Write/refresh the monotonic legacy ratchet manifest and exit 0",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    server_rust = root / "server-rust"
    ratchet_path = (
        args.ratchet.resolve()
        if args.ratchet is not None
        else root / "config/sql-contracts-legacy-ratchet.json"
    )

    errors: list[str] = []
    check_proc_macro_ban(server_rust, errors)
    check_audit_posture_contracts(root, server_rust, errors)
    fmt_map, raw_map = collect_domain_findings(server_rust)

    if args.write_ratchet:
        enforced = list(CATALOG_ENFORCED_DEFAULT)
        payload = {
            "description": (
                "Monotonic legacy SQL baseline for pre-Wave-1.8 domain crates "
                "(#541). Counts may only decrease until Wave 1.8 (#546) reaches 0."
            ),
            "catalog_enforced_crates": enforced,
            "format_sql": {k: len(v) for k, v in sorted(fmt_map.items())},
            "uncataloged_sql": {k: len(v) for k, v in sorted(raw_map.items())},
        }
        ratchet_path.parent.mkdir(parents=True, exist_ok=True)
        ratchet_path.write_text(
            json.dumps(payload, indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        print(
            "wrote ratchet: "
            f"enforced={len(enforced)}, "
            f"legacy_format_sql={sum(payload['format_sql'].values())}, "
            f"legacy_uncataloged_sql={sum(payload['uncataloged_sql'].values())}"
        )
        return 0

    if not ratchet_path.is_file():
        errors.append(
            f"RATCHET_MISSING: legacy ratchet manifest not found at {ratchet_path}"
        )
        enforced_set: set[str] = set(CATALOG_ENFORCED_DEFAULT)
        allowed_fmt: dict[str, int] = {}
        allowed_raw: dict[str, int] = {}
    else:
        ratchet = json.loads(ratchet_path.read_text(encoding="utf-8"))
        enforced_set = set(ratchet.get("catalog_enforced_crates", []))
        allowed_fmt = {k: int(v) for k, v in ratchet.get("format_sql", {}).items()}
        allowed_raw = {k: int(v) for k, v in ratchet.get("uncataloged_sql", {}).items()}

    for rel, lines in sorted(fmt_map.items()):
        crate_name = rel.split("/")[2]
        if crate_name in enforced_set:
            for ln in lines:
                errors.append(
                    f"SQL_INTERPOLATION_FORBIDDEN: {rel}:{ln} "
                    f"(catalog-enforced crate '{crate_name}' forbids format! SQL)"
                )
            continue
        cap = allowed_fmt.get(rel, 0)
        if len(lines) > cap:
            errors.append(
                f"SQL_INTERPOLATION_FORBIDDEN: {rel} has {len(lines)} format! SQL "
                f"site(s) at lines {lines}, exceeding ratchet cap {cap}"
            )

    for rel, lines in sorted(raw_map.items()):
        crate_name = rel.split("/")[2]
        if crate_name in enforced_set:
            for ln in lines:
                errors.append(
                    f"UNCATALOGED_SQL: {rel}:{ln} "
                    f"(catalog-enforced crate '{crate_name}' forbids raw SQL "
                    "outside src/sql.rs)"
                )
            continue
        cap = allowed_raw.get(rel, 0)
        if len(lines) > cap:
            errors.append(
                f"UNCATALOGED_SQL: {rel} has {len(lines)} uncataloged SQL "
                f"literal(s) at lines {lines}, exceeding ratchet cap {cap}"
            )

    if errors:
        for err in errors:
            print(f"FAIL: {err}", file=sys.stderr)
        return 1

    total_fmt = sum(len(v) for v in fmt_map.values())
    total_raw = sum(len(v) for v in raw_map.values())
    print(
        "check-rust-sql-contracts.py: PASS "
        f"(enforced_crates={len(enforced_set)}, "
        f"legacy_format_sql={total_fmt}, "
        f"legacy_uncataloged_sql={total_raw})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
