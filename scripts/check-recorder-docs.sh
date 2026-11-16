#!/usr/bin/env bash
# check-recorder-docs.sh: conformance READMEs must not tell people to record a fault-named test
# through the dispatch-only gofree-record workflow. The recorder skips fault tests
# (scripts/gofree-record.sh: `--skip mutant --skip fault`), so such an instruction cannot work.
#
# Paragraph rule: a blank-line-separated paragraph is flagged when it names the recording path
# (gofree-record, dispatch or case_filter) AND names a fault-named test (`*_fault_*`, `fault_x`,
# `x_fault`) AND does not say the case is skipped or native. Paragraphs that drive a separate
# env-var recording mode (identity-login GOFREE_RECORD_REFRESH_FAULTS) name no dispatch path and pass.
#   check-recorder-docs.sh [DIR]    scan DIR (default server-rust/tests/conformance)
#   check-recorder-docs.sh --self-test
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

scan() {
  python3 -I - "$1" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
record = re.compile(r"gofree-record|dispatch|case_filter", re.I)
fault = re.compile(r"_fault(?![A-Za-z])|(?<![A-Za-z])fault_", re.I)
allowed = re.compile(r"skip|native", re.I)
bad = []
for readme in sorted(root.rglob("README.md")):
    for n, para in enumerate(re.split(r"\n\s*\n", readme.read_text(encoding="utf-8")), 1):
        if record.search(para) and fault.search(para) and not allowed.search(para):
            bad.append(f"{readme}: paragraph {n}: {' '.join(para.split())[:160]}")
for line in bad:
    print("RECORDER-DOCS-FAIL " + line)
sys.exit(1 if bad else 0)
PY
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/check-recorder-docs.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/bad" "$tmp/good"
  cat > "$tmp/bad/README.md" <<'EOF2'
# Fixture

Record with the dispatch-only `gofree-record.yml`, `case_filter` = `guest_fault_rollback`.
EOF2
  cat > "$tmp/good/README.md" <<'EOF2'
# Fixture

`session_faults` records with GOFREE_RECORD_REFRESH_FAULTS=1; ordinary strict
runs replay without Go. Fault recorders own their named containers.
EOF2
  if scan "$tmp/bad" > /dev/null; then
    echo "check-recorder-docs: self-test FAIL: flagged fixture passed" >&2; exit 1
  fi
  if ! scan "$tmp/good" > /dev/null; then
    echo "check-recorder-docs: self-test FAIL: allowed fixture was flagged" >&2; exit 1
  fi
  echo "check-recorder-docs: self-test PASS"
  exit 0
fi

target="${1:-$ROOT/server-rust/tests/conformance}"
if scan "$target"; then
  echo "check-recorder-docs: PASS ($target)"
else
  echo "check-recorder-docs: FAIL: conformance README instructs recording a fault-named test through gofree-record/dispatch (the recorder skips fault tests)" >&2
  exit 1
fi
