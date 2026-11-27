#!/usr/bin/env bash
# check-worker-supervisor.sh — Wave 2.2 (#549) ratchet freezing legacy
# `WorkerDatabase::from_dsns` call sites with per-file exact occurrence-count
# ceilings so no new un-supervised worker can be introduced outside
# `WorkerSupervisor` (neither in a new file nor by adding calls to an
# existing allowlisted file, including multiple calls on one line).
#
# Usage:
#   scripts/check-worker-supervisor.sh             # check repo tree
#   scripts/check-worker-supervisor.sh --self-test # prove guard fires on all violation modes
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN_ROOT="${WORKER_SUPERVISOR_SCAN_ROOT:-$ROOT/server-rust}"

# Frozen per-file occurrence ceilings for legacy pre-Wave-2.2 files calling
# `WorkerDatabase::from_dsns` (relative to server-rust/). Shrinking counts or
# removing files is allowed; exceeding any ceiling or adding a new file fails CI.
ALLOWLIST=(
  "bins/auth/src/main.rs:1"
  "bins/auth/src/revocations.rs:1"
  "bins/gateway/src/imap_runtime.rs:1"
  "bins/gateway/src/runtime/mod.rs:2"
  "bins/gateway/src/runtime/routes.rs:4"
  "bins/gateway/src/runtime/workers.rs:24"
  "bins/gateway/src/smtp_outbound.rs:1"
  "bins/gateway/src/smtp_runtime.rs:1"
  "bins/gateway/src/telemetry.rs:1"
  "bins/setjoind/src/lib.rs:2"
  "crates/backup/src/worker.rs:1"
  "crates/protocols/federation/src/runtime.rs:1"
  "crates/threat/src/lib.rs:1"
)

max_allowed_for() {
  local rel="$1" entry path cap
  for entry in "${ALLOWLIST[@]}"; do
    path="${entry%%:*}"
    cap="${entry##*:}"
    if [[ "$path" == "$rel" ]]; then
      echo "$cap"
      return 0
    fi
  done
  return 1
}

run_check() {
  local base="$1"
  local fail=0
  local found=0
  local total_calls=0
  local grep_files="" grep_status=0
  local file count rel cap

  if [[ ! -d "$base/bins" || ! -d "$base/crates" ]]; then
    echo "worker-supervisor guard: FAILED (missing required scan directories under $base)" >&2
    return 1
  fi

  set +e
  grep_files="$(grep -rl 'WorkerDatabase::from_dsns' "$base/bins" "$base/crates")"
  grep_status=$?
  set -e
  if [[ "$grep_status" -gt 1 ]]; then
    echo "worker-supervisor guard: FAILED (grep error exit $grep_status)" >&2
    return 1
  fi

  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    case "$file" in
      */tests/*) continue ;;
    esac
    count="$(grep -o 'WorkerDatabase::from_dsns' "$file" | wc -l | tr -d '[:space:]')"
    [[ "$count" =~ ^[0-9]+$ ]] || continue
    [[ "$count" -gt 0 ]] || continue
    rel="${file#"$base"/}"
    found=$((found + 1))
    total_calls=$((total_calls + count))
    if ! cap="$(max_allowed_for "$rel")"; then
      echo "  VIOLATION: new legacy WorkerDatabase::from_dsns call site: $rel ($count call(s))" >&2
      echo "  -> wire new background workers through WorkerSupervisor + WorkerPool instead." >&2
      fail=1
    elif [[ "$count" -gt "$cap" ]]; then
      echo "  VIOLATION: allowlisted file $rel exceeded call ceiling ($count > $cap)" >&2
      echo "  -> wire new background workers through WorkerSupervisor + WorkerPool instead." >&2
      fail=1
    fi
  done < <(printf '%s\n' "$grep_files" | LC_ALL=C sort)

  if [[ "$fail" -ne 0 ]]; then
    echo "worker-supervisor guard: FAILED" >&2
    return 1
  fi
  echo "worker-supervisor guard: PASS ($found allowlisted legacy files, $total_calls total calls; 0 violations)"
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/check-worker-supervisor.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT

  # (a) Missing scan directories must fail closed.
  if run_check "$tmp/does-not-exist" >/dev/null 2>&1; then
    echo "check-worker-supervisor --self-test: FAILED (missing scan tree did not fail)" >&2
    exit 1
  fi

  mkdir -p "$tmp/bins/gateway/src" "$tmp/crates"

  # (b) New un-allowlisted file must fail.
  cat >"$tmp/bins/gateway/src/rogue_worker.rs" <<'EOF'
fn rogue() {
    let _ = WorkerDatabase::from_dsns("postgres://x", None);
}
EOF
  if run_check "$tmp" >/dev/null 2>&1; then
    echo "check-worker-supervisor --self-test: FAILED (planted new file violation was not caught)" >&2
    exit 1
  fi
  rm -f "$tmp/bins/gateway/src/rogue_worker.rs"

  # (c) Two calls on a SINGLE line in an allowlisted file (ceiling 1) must fail.
  cat >"$tmp/bins/gateway/src/telemetry.rs" <<'EOF'
fn two_on_one_line() { let _ = (WorkerDatabase::from_dsns("postgres://x", None), WorkerDatabase::from_dsns("postgres://y", None)); }
EOF
  if run_check "$tmp" >/dev/null 2>&1; then
    echo "check-worker-supervisor --self-test: FAILED (two same-line calls in allowlisted file not caught)" >&2
    exit 1
  fi

  # (d) Exact ceiling passes cleanly.
  cat >"$tmp/bins/gateway/src/telemetry.rs" <<'EOF'
fn one() { let _ = WorkerDatabase::from_dsns("postgres://x", None); }
EOF
  if ! run_check "$tmp" >/dev/null 2>&1; then
    echo "check-worker-supervisor --self-test: FAILED (clean fixture failed)" >&2
    exit 1
  fi
  echo "check-worker-supervisor --self-test: PASS"
  exit 0
fi

run_check "$SCAN_ROOT"
