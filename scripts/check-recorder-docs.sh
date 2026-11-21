#!/usr/bin/env bash
# check-recorder-docs.sh: conformance READMEs must not tell people to record a fault-named test
# through the dispatch-only gofree-record workflow. The recorder skips fault tests
# (scripts/gofree-record.sh: `--skip mutant --skip fault`), so such an instruction cannot work.
#
# Paragraph rule: a blank-line-separated paragraph is flagged when it names the recording path
# (gofree-record, dispatch or case_filter) AND names a fault-named test (`fault`, `faults`,
# `*_fault_*`, `*_faults`, `fault_x`, `faults_x`) AND does not state, as whole words, that the
# fault cases are skipped or native. Separate env-var recording modes
# (identity-login GOFREE_RECORD_REFRESH_FAULTS) name no dispatch path and pass.
#   check-recorder-docs.sh [DIR]    scan DIR (default server-rust/tests/conformance)
#   check-recorder-docs.sh --self-test
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

scan() {
  python3 -I - "$1" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
record = re.compile(r"gofree-record|dispatch|case_filter", re.I)
fault = re.compile(r"_faults?(?![A-Za-z])|(?<![A-Za-z])faults?_|(?<![A-Za-z_])faults?(?![A-Za-z_])", re.I)
allowed = re.compile(r"\b(?:skip|skips|skipped|skipping|native)\b", re.I)
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
  for d in bad-fault bad-alternative bad-plural good-identity-login; do mkdir -p "$tmp/$d"; done
  cat > "$tmp/bad-fault/README.md" <<'EOF2'
# Fixture

Record with the dispatch-only `gofree-record.yml`, `case_filter` = `guest_fault_rollback`.
EOF2
  cat > "$tmp/bad-alternative/README.md" <<'EOF2'
# Fixture

As an alternative, record `guest_fault_rollback` using `gofree-record.yml`.
EOF2
  cat > "$tmp/bad-plural/README.md" <<'EOF2'
# Fixture

Dispatch `refresh_faults` through gofree-record with `case_filter` set to that name.
EOF2
  cat > "$tmp/good-identity-login/README.md" <<'EOF2'
# Fixture

`session_faults` records with GOFREE_RECORD_REFRESH_FAULTS=1; ordinary strict
runs replay without Go. Fault recorders own their named containers.
EOF2
  status=0
  for d in bad-fault bad-alternative bad-plural; do
    if scan "$tmp/$d" > /dev/null; then
      echo "check-recorder-docs: self-test FAIL: $d fixture passed" >&2; status=1
    fi
  done
  if ! scan "$tmp/good-identity-login" > /dev/null; then
    echo "check-recorder-docs: self-test FAIL: identity-login fixture was flagged" >&2; status=1
  fi
  [ "$status" -eq 0 ] && echo "check-recorder-docs: self-test PASS"
  exit "$status"
fi

target="${1:-$ROOT/server-rust/tests/conformance}"
if scan "$target"; then
  echo "check-recorder-docs: PASS ($target)"
else
  echo "check-recorder-docs: FAIL: conformance README instructs recording a fault-named test through gofree-record/dispatch (the recorder skips fault tests)" >&2
  exit 1
fi
