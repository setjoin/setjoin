#!/usr/bin/env bash
# check-scope-revocation-coverage.sh — CI guard enforcing Wave 2.5 (#552)
# revocation coverage: EVERY CREATE [OR REPLACE] FUNCTION block executing
# DELETE FROM (mailbox_delegates|calendar_acls|chat_channel_members|drive_space_members)
# MUST call emit_scope_revoked(...) inside that same function body (unless
# explicitly allowlisted as non-revocation cleanup/cascade).
#
# Usage:
#   bash scripts/guards/check-scope-revocation-coverage.sh
#   bash scripts/guards/check-scope-revocation-coverage.sh --self-test
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REDUCERS_DIR="${SCOPE_REVOCATION_REDUCERS_DIR:-$ROOT/sql/reducers}"

# Explicit allowlist of reducers (`file.sql` or `file.sql:func_name`) whose
# DELETE on the watched tables is non-revocation cleanup/cascade (empty today;
# every live DELETE function revokes scope access and calls emit_scope_revoked).
ALLOWLIST="${SCOPE_REVOCATION_ALLOWLIST:-}"

run_check() {
  local dir="$1"
  local allow="$2"
  python3 - "$dir" "$allow" <<'PYEOF'
import re
import sys
from pathlib import Path

reducers_dir = Path(sys.argv[1])
allowlist = {x.strip() for x in sys.argv[2].split(",") if x.strip()}

if not reducers_dir.is_dir():
    print(f"scope-revocation-coverage guard: directory missing: {reducers_dir}", file=sys.stderr)
    sys.exit(2)

DELETE_RE = re.compile(
    r"\bDELETE\s+FROM\s+(?:public\.)?(mailbox_delegates|calendar_acls|chat_channel_members|drive_space_members)\b",
    re.I,
)
EMIT_RE = re.compile(
    r"\b(?:PERFORM|SELECT)\s+(?:public\.)?emit_scope_revoked\s*\(",
    re.I,
)
FUNC_HDR_RE = re.compile(
    r"\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:public\.)?([a-zA-Z0-9_]+)\s*\(",
    re.I,
)
DOLLAR_TAG_RE = re.compile(r"\$(?:[a-zA-Z_][a-zA-Z0-9_]*)?\$")


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"--[^\n]*", "", src)


def extract_functions(cleaned: str):
    """Yield (func_name, body_text) for every CREATE [OR REPLACE] FUNCTION block."""
    pos = 0
    n = len(cleaned)
    while pos < n:
        m = FUNC_HDR_RE.search(cleaned, pos)
        if not m:
            break
        func_name = m.group(1)
        # Find the AS $tag$ body delimiter after the function header.
        as_match = re.search(r"\bAS\s+(\$(?:[a-zA-Z_][a-zA-Z0-9_]*)?\$)", cleaned[m.end():], re.I)
        if not as_match:
            pos = m.end()
            continue
        tag = as_match.group(1)
        body_start = m.end() + as_match.end()
        body_end = cleaned.find(tag, body_start)
        if body_end == -1:
            yield (func_name, cleaned[body_start:])
            break
        yield (func_name, cleaned[body_start:body_end])
        pos = body_end + len(tag)


checked = 0
problems = []

for path in sorted(reducers_dir.glob("*.sql")):
    cleaned = strip_comments(path.read_text())
    if path.name in allowlist:
        continue
    funcs = list(extract_functions(cleaned))
    if not funcs:
        hits = sorted({m.group(1).lower() for m in DELETE_RE.finditer(cleaned)})
        if hits and not EMIT_RE.search(cleaned):
            problems.append(
                f"{path.name}: executes DELETE FROM {', '.join(hits)} without calling emit_scope_revoked(...)"
            )
        continue
    for func_name, body in funcs:
        hits = sorted({m.group(1).lower() for m in DELETE_RE.finditer(body)})
        if not hits:
            continue
        if f"{path.name}:{func_name}" in allowlist:
            continue
        checked += 1
        if not EMIT_RE.search(body):
            problems.append(
                f"{path.name}:{func_name}: executes DELETE FROM {', '.join(hits)} without calling emit_scope_revoked(...)"
            )

if problems:
    print("scope-revocation-coverage guard FAILED:", file=sys.stderr)
    for p in problems:
        print(f"  - {p}", file=sys.stderr)
    sys.exit(1)

print(
    f"scope-revocation-coverage guard: clean ({checked} authority-revoking reducer function(s) call emit_scope_revoked)."
)
PYEOF
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  # Positive fixture: reducer with DELETE + emit_scope_revoked passes.
  cat >"$tmp/good_revoke.sql" <<'SQL'
CREATE OR REPLACE FUNCTION good_revoke(p_uid bigint, p_ch bigint) RETURNS void AS $$
BEGIN
  DELETE FROM chat_channel_members WHERE channel_id = p_ch AND user_id = p_uid;
  PERFORM public.emit_scope_revoked(p_uid, 'channel', p_ch, 'member_removed', NULL);
END;
$$ LANGUAGE plpgsql;
SQL
  if ! run_check "$tmp" "" >/dev/null 2>&1; then
    echo "self-test FAILED: valid reducer was rejected" >&2
    exit 1
  fi

  # Negative fixture 1: single function with DELETE and NO emit_scope_revoked fails.
  cat >"$tmp/bad_revoke.sql" <<'SQL'
CREATE OR REPLACE FUNCTION bad_revoke(p_uid bigint, p_mb bigint) RETURNS void AS $$
BEGIN
  -- emit_scope_revoked() in a comment must NOT satisfy the guard
  DELETE FROM mailbox_delegates WHERE mailbox_id = p_mb AND user_id = p_uid;
END;
$$ LANGUAGE plpgsql;
SQL
  if run_check "$tmp" "" >/dev/null 2>&1; then
    echo "self-test FAILED: missing emit_scope_revoked was not caught" >&2
    exit 1
  fi

  # Allowlist fixture: explicitly allowlisted file:function passes.
  if ! run_check "$tmp" "bad_revoke.sql:bad_revoke" >/dev/null 2>&1; then
    echo "self-test FAILED: allowlisted function was rejected" >&2
    exit 1
  fi

  # Negative fixture 2: combined file with ONE valid function and ONE uncovered
  # DELETE FROM function in the SAME file MUST FAIL (per-function check).
  cat >"$tmp/mixed_file.sql" <<'SQL'
CREATE OR REPLACE FUNCTION covered_fn(p_uid bigint, p_sp bigint) RETURNS void AS $body$
BEGIN
  DELETE FROM drive_space_members WHERE space_id = p_sp AND user_id = p_uid;
  PERFORM public.emit_scope_revoked(p_uid, 'space', p_sp, 'member_revoked', NULL);
END;
$body$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION uncovered_fn(p_uid bigint, p_cal bigint) RETURNS void AS $body$
BEGIN
  DELETE FROM calendar_acls WHERE calendar_id = p_cal AND user_id = p_uid;
END;
$body$ LANGUAGE plpgsql;
SQL
  if run_check "$tmp" "bad_revoke.sql" >/dev/null 2>&1; then
    echo "self-test FAILED: uncovered function in multi-function file was not caught" >&2
    exit 1
  fi

  echo "scope-revocation-coverage guard self-test: PASS"
  exit 0
fi

run_check "$REDUCERS_DIR" "$ALLOWLIST"
