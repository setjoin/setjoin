#!/usr/bin/env bash
# check-audit-coverage.sh — WP3 audit-coverage guard (review-remediation wave).
#
# Enforces scripts/audit-coverage.tsv against the ACTUAL mailserver/sql/reducers
# tree: every defined function is classified exactly once, MUST functions call
# audit_write() in their OWN body, exemptions carry real reasons, and READ_ONLY
# rows are re-derived (a READ_ONLY row whose body now mutates fails). This is
# the regression wall for the WP3 decision: lifecycle/authority transitions
# audit through the single audit_write() path; high-frequency user content and
# transport/GC mechanics stay exempt by explicit reasoned rows — never by
# silence. A new reducer function fails this guard until it is classified.
#
# The single-INSERT-path invariant (only audit_write.sql touches
# admin_audit_log) stays with mailserver/internal/audit/coverage_guard_test.go;
# this guard owns the CALL-side coverage contract.
#
# Env overrides (self-test harness):
#   AUDIT_REDUCERS_ROOT  default mailserver/sql/reducers
#   AUDIT_COVERAGE_TSV   default scripts/audit-coverage.tsv
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REDUCERS_ROOT="${AUDIT_REDUCERS_ROOT:-$ROOT/mailserver/sql/reducers}"
TSV="${AUDIT_COVERAGE_TSV:-$ROOT/scripts/audit-coverage.tsv}"

if [ ! -f "$TSV" ]; then
  echo "audit-coverage guard: inventory missing: $TSV" >&2
  exit 2
fi
if [ ! -d "$REDUCERS_ROOT" ]; then
  echo "audit-coverage guard: reducers root missing: $REDUCERS_ROOT" >&2
  exit 2
fi

python3 - "$REDUCERS_ROOT" "$TSV" <<'PYEOF'
import re
import sys
from pathlib import Path

reducers_root, tsv_path = Path(sys.argv[1]), Path(sys.argv[2])
problems = []
die = problems.append

VALID = {"MUST", "EXEMPT", "READ_ONLY", "AUDIT_SINK"}
DML = re.compile(
    r"\b(INSERT\s+INTO|UPDATE\s+[a-zA-Z_\"][a-zA-Z0-9_\"]*|DELETE\s+FROM|TRUNCATE|"
    r"ALTER\s+TABLE|CREATE\s+(?:TABLE|INDEX)|DROP\s+TABLE|"
    r"GRANT\s|REVOKE\s|CREATE\s+ROLE|DROP\s+ROLE|ALTER\s+ROLE)\b",
    re.I,
)


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"--[^\n]*", "", src)


class UnsupportedSyntax(Exception):
    pass


def defined_functions(nc: str):
    # Returns fn -> [bodies]. Fail-closed hardening (astra round 1): quoted
    # identifiers are recognized; tagged dollar-quoting ($tag$...$tag$) is
    # recognized with the SAME tag on both ends; EVERY overload's body is
    # collected (an unaudited first overload must not hide behind the last);
    # a CREATE FUNCTION whose body cannot be extracted raises instead of
    # silently classifying an empty string.
    out = {}
    for m in re.finditer(
        r'CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+("?([a-zA-Z_][a-zA-Z0-9_]*)"?)', nc, re.I
    ):
        name = m.group(2)
        rest = nc[m.end():]
        body = None
        b = re.search(r"\$\$(.*?)\$\$", rest, re.S)
        if b:
            body = b.group(1)
        else:
            t = re.search(r"\$([a-zA-Z_][a-zA-Z0-9_]*)\$", rest)
            if t:
                tag = t.group(1)
                b2 = re.search(
                    r"\$" + re.escape(tag) + r"\$(.*?)\$" + re.escape(tag) + r"\$", rest, re.S
                )
                if b2:
                    body = b2.group(1)
        if body is None:
            raise UnsupportedSyntax(
                f"function {name!r} has no extractable $$/$tag$ body"
            )
        out.setdefault(name, []).append(body)
    return out


# ── source census ────────────────────────────────────────────────────────────
source = {}   # fn -> (file, [bodies]) — every overload, same file only
for f in sorted(reducers_root.glob("*.sql")):
    try:
        found = defined_functions(strip_comments(f.read_text()))
    except UnsupportedSyntax as exc:
        die(f"UNPARSEABLE: {f.name}: {exc} — extend the guard before landing it")
        continue
    for name, bodies in found.items():
        if name in source and source[name][0] != f.name:
            die(
                f"DUPLICATE-DEFINITION: {name} defined in both "
                f"{source[name][0]} and {f.name}"
            )
        elif name in source:
            source[name] = (f.name, source[name][1] + bodies)
        else:
            source[name] = (f.name, list(bodies))

# ── inventory parse ──────────────────────────────────────────────────────────
rows = {}
sink_rows = []
for lineno, raw in enumerate(
    tsv_path.read_text().splitlines(), start=1
):
    if not raw.strip():
        continue
    fields = raw.split("\t")
    if len(fields) != 5:
        die(f"SCHEMA line {lineno}: expected 5 TAB fields, got {len(fields)}: {raw[:80]}")
        continue
    fname, fn, cls, tier, reason = fields
    if cls not in VALID:
        die(f"CLASS line {lineno}: {fname}:{fn} bad class {cls!r}")
        continue
    if fn == "*" or "*" in fn:
        die(f"WILDCARD line {lineno}: {fname}:{fn} — rows name one function each")
        continue
    if (fn, cls) != ("audit_write", "AUDIT_SINK") and cls == "AUDIT_SINK":
        die(f"SINK line {lineno}: {fname}:{fn} — audit_write.sql is the only sink")
    if cls == "AUDIT_SINK":
        sink_rows.append((lineno, fname, fn))
    if cls == "MUST" and tier not in ("core", "routine"):
        die(f"TIER line {lineno}: {fname}:{fn} MUST needs tier core|routine, got {tier!r}")
    if cls in ("EXEMPT", "READ_ONLY", "AUDIT_SINK") and tier not in ("-", ""):
        die(f"TIER line {lineno}: {fname}:{fn} {cls} tier must be '-', got {tier!r}")
    if cls in ("EXEMPT", "READ_ONLY") and not reason.strip():
        die(f"REASON line {lineno}: {fname}:{fn} {cls} needs a reason")
    if fn in rows:
        die(f"DUPLICATE line {lineno}: {fn} already classified at line {rows[fn][0]}")
        continue
    rows[fn] = (lineno, fname, cls, tier, reason, raw)

missing = sorted(set(source) - set(rows))
for fn in missing:
    die(
        f"UNCLASSIFIED: {source[fn][0]}:{fn} has no inventory row — "
        "classify it (MUST/EXEMPT/READ_ONLY) with a reason before it lands"
    )
stale = sorted(set(rows) - set(source))
for fn, (lineno, fname, *_rest) in rows.items():
    if fn not in source:
        die(f"STALE line {lineno}: {fname}:{fn} is not defined under {reducers_root}")

# ── per-class body contracts (checked per OVERLOAD body) ────────────────────
for fn, (lineno, fname, cls, tier, reason, _raw) in sorted(rows.items()):
    if fn not in source:
        continue
    bodies = source[fn][1]
    if cls == "MUST":
        for body in bodies:
            # A real call is PERFORM/SELECT audit_write( — prose inside a
            # string literal ('call audit_write() here') does not match the
            # call shape. (Literal STRIPPING was tried first and is fragile:
            # one unpaired apostrophe in a body flips the pairing and
            # swallows real calls — federation_peer_set tripped exactly that.)
            if not re.search(
                r"\b(?:PERFORM|SELECT)\s+(?:[a-zA-Z_][a-zA-Z0-9_]*\.)?audit_write\s*\(",
                body,
                re.I,
            ):
                die(
                    f"MUST-NO-CALL: {fname}:{fn} is classified MUST but an "
                    "overload body never calls audit_write() (a sibling's, a "
                    "comment's or a string literal's occurrence does not count)"
                )
                continue
            # Tier cross-check: the tier the body actually passes to
            # audit_write must match the inventory row (a row saying core
            # over a routine call misstates the lean/full gate).
            # The tier argument IS a string literal — check the ORIGINAL
            # body (the literal-strip above is only for call presence).
            calls_routine = re.search(
                r"(?:PERFORM|SELECT)\s+(?:[a-zA-Z_][a-zA-Z0-9_]*\.)?audit_write\s*\([^;]*?'routine'", body, re.S | re.I
            )
            if calls_routine and tier != "routine":
                die(
                    f"TIER-MISMATCH: {fname}:{fn} row says tier={tier!r} but "
                    "its audit_write call passes 'routine' (row must say routine)"
                )
            if tier == "routine" and not calls_routine:
                die(
                    f"TIER-MISMATCH: {fname}:{fn} row says tier='routine' but "
                    "its audit_write call does not pass 'routine'"
                )
    elif cls == "READ_ONLY":
        for body in bodies:
            # Literal-stripped code: 'grant' inside an error message is
            # prose, not a GRANT statement.
            if DML.search(re.sub(r"'(?:[^']|'')*'", "''", body)):
                die(
                    f"READ_ONLY-MUTATES: {fname}:{fn} is classified READ_ONLY but an "
                    "overload body contains DML — reclassify it (MUST or EXEMPT with a reason)"
                )
    if cls == "AUDIT_SINK" and len(sink_rows) > 1:
        continue  # already reported per row above

if len(sink_rows) == 0:
    die("NO-SINK: no AUDIT_SINK row for audit_write")
elif len(sink_rows) > 1:
    die(f"MULTI-SINK: {len(sink_rows)} AUDIT_SINK rows (lines {[r[0] for r in sink_rows]})")

if problems:
    print(f"audit-coverage guard FAILED — {len(problems)} problem(s):")
    for p in problems:
        print(f"  {p}")
    sys.exit(2)

counts = {}
for _lineno, _fname, cls, *_rest in rows.values():
    counts[cls] = counts.get(cls, 0) + 1
print(
    "audit-coverage guard: clean — {total} functions classified "
    "(MUST {must} / EXEMPT {exempt} / READ_ONLY {ro} / AUDIT_SINK {sink})".format(
        total=len(rows),
        must=counts.get("MUST", 0),
        exempt=counts.get("EXEMPT", 0),
        ro=counts.get("READ_ONLY", 0),
        sink=counts.get("AUDIT_SINK", 0),
    )
)
PYEOF
