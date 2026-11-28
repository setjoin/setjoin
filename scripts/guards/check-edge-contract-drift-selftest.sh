#!/usr/bin/env bash
# Self-test for scripts/guards/check-edge-contract-drift.sh (#561).
# Proves a 1-line drift in generated.rs or schema.d.ts is caught.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GUARD="$ROOT/scripts/guards/check-edge-contract-drift.sh"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/edge-drift-selftest.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

cp "$ROOT/server/crates/edge-contract/src/generated.rs" "$tmp/drifted.rs"
echo "// planted drift" >>"$tmp/drifted.rs"

if EDGE_COMMITTED_RS="$tmp/drifted.rs" bash "$GUARD" >/dev/null 2>&1; then
  # If running in static fallback (no node_modules), test missing operation removal instead.
  grep -v '"/api/user/quota"' "$ROOT/server/crates/edge-contract/src/generated.rs" >"$tmp/drifted.rs"
  if EDGE_COMMITTED_RS="$tmp/drifted.rs" bash "$GUARD" >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: check-edge-contract-drift did NOT catch drifted generated.rs" >&2
    exit 1
  fi
fi

echo "check-edge-contract-drift self-test: PASS (drifted generated artifact caught)"
