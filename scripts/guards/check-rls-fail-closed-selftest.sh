#!/usr/bin/env bash
# Self-test for scripts/guards/check-rls-fail-closed.sh.
# Plants WarnReleaseN, BootPosture::bare(), install.sh permissive/exit-2,
# upgrade.sh exit-2, and missing DB_WORKER_DSN regressions in temp copies and
# proves the guard fires on every one before passing on HEAD.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GUARD="$ROOT/scripts/guards/check-rls-fail-closed.sh"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/check-rls-fail-closed-selftest.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# Copy only the small subset of files the guard inspects.
mkdir -p "$tmp/server-rust/crates/boot/src" \
  "$tmp/server-rust/crates/pg/src" \
  "$tmp/server-rust/bins/auth/src" \
  "$tmp/server-rust/bins/gateway/src" \
  "$tmp/server-rust/bins/mailctl/src/direct" \
  "$tmp/server-rust/bins/updater/src"
cp "$ROOT/server-rust/crates/boot/src/lib.rs" "$tmp/server-rust/crates/boot/src/lib.rs"
cp "$ROOT/server-rust/crates/pg/src/rls_preflight.rs" "$tmp/server-rust/crates/pg/src/rls_preflight.rs"
cp "$ROOT/server-rust/bins/auth/src/main.rs" "$tmp/server-rust/bins/auth/src/main.rs"
cp "$ROOT/server-rust/bins/mailctl/src/direct/rls.rs" "$tmp/server-rust/bins/mailctl/src/direct/rls.rs"
cp "$ROOT/server-rust/bins/updater/src/run.rs" "$tmp/server-rust/bins/updater/src/run.rs"
cp "$ROOT/mailserver/deploy/scripts/install.sh" "$tmp/install.sh"
cp "$ROOT/mailserver/deploy/scripts/upgrade.sh" "$tmp/upgrade.sh"
cp "$ROOT/scripts/ci/server-rust-parallel-lane.sh" "$tmp/parallel-lane.sh"

run_guard() {
  SERVER_RUST_DIR="$tmp/server-rust" \
    INSTALL_SH="$tmp/install.sh" \
    UPGRADE_SH="$tmp/upgrade.sh" \
    PARALLEL_LANE_SH="$tmp/parallel-lane.sh" \
    bash "$GUARD"
}

expect_fire() {
  local label="$1" needle="$2" out=""
  if out="$(run_guard 2>&1)"; then
    echo "selftest FAIL: guard passed on planted mutant ($label)" >&2
    exit 1
  fi
  if ! printf '%s\n' "$out" | grep -Fq -- "$needle"; then
    echo "selftest FAIL ($label): missing expected diagnostic '$needle' in:" >&2
    printf '%s\n' "$out" >&2
    exit 1
  fi
}

# Baseline on clean copy must pass.
run_guard >/dev/null

# Mutant 1: WarnReleaseN planted in a production bin (including future setjoind).
mkdir -p "$tmp/server-rust/bins/setjoind/src"
printf 'let _ = EnforcementMode::WarnReleaseN;\n' >"$tmp/server-rust/bins/setjoind/src/main.rs"
expect_fire "WarnReleaseN in bins/setjoind/src" "production entrypoint references WarnReleaseN"
rm -rf "$tmp/server-rust/bins/setjoind"

# Mutant 2: BootPosture::bare() reverted to WarnReleaseN.
cp "$ROOT/server-rust/crates/pg/src/rls_preflight.rs" "$tmp/rls_preflight.orig"
awk '/pub fn bare\(\) -> Self/,/^[[:space:]]*\}/ { gsub(/FailClosedReleaseNPlus1/, "WarnReleaseN") } { print }' \
  "$tmp/rls_preflight.orig" >"$tmp/server-rust/crates/pg/src/rls_preflight.rs"
expect_fire "BootPosture::bare() WarnReleaseN" "BootPosture::bare() in rls_preflight.rs uses WarnReleaseN"
mv "$tmp/rls_preflight.orig" "$tmp/server-rust/crates/pg/src/rls_preflight.rs"

# Mutant 3: install.sh exit-2 advisory branch planted.
cp "$tmp/install.sh" "$tmp/install.orig"
printf 'if [ "$_preflight_rc" -eq 2 ]; then info warn; fi\n' >>"$tmp/install.sh"
expect_fire "install.sh exit-2 advisory" "install.sh still treats mailctl schema preflight exit 2 as advisory"
mv "$tmp/install.orig" "$tmp/install.sh"

# Mutant 4: upgrade.sh exit-2 advisory branch planted.
cp "$tmp/upgrade.sh" "$tmp/upgrade.orig"
printf 'if [ "$_preflight_rc" -eq 2 ]; then echo warn; fi\n' >>"$tmp/upgrade.sh"
expect_fire "upgrade.sh exit-2 advisory" "upgrade.sh still treats mailctl schema preflight exit 2 as advisory"
mv "$tmp/upgrade.orig" "$tmp/upgrade.sh"

# Mutant 5: upgrade.sh drops Step 0 pre-stop run_rls_preflight_gate call
# (docstring comment remains, proving comment lines cannot satisfy the guard).
cp "$tmp/upgrade.sh" "$tmp/upgrade.orig"
awk '
  /1\. Stopping services/ { seen_stop=1 }
  !seen_stop && /run_rls_preflight_gate / && !/^[[:space:]]*#/ { next }
  { print }
' "$tmp/upgrade.orig" >"$tmp/upgrade.sh"
expect_fire "missing pre-stop run_rls_preflight_gate in upgrade.sh" "upgrade.sh lacks a pre-stop run_rls_preflight_gate call before Step 1"
mv "$tmp/upgrade.orig" "$tmp/upgrade.sh"

# Mutant 6: parallel lane drops DB_WORKER_DSN export.
cp "$tmp/parallel-lane.sh" "$tmp/parallel-lane.orig"
grep -v '^export DB_WORKER_DSN=' "$tmp/parallel-lane.orig" >"$tmp/parallel-lane.sh"
expect_fire "missing DB_WORKER_DSN in parallel lane" "server-rust-parallel-lane.sh does not export DB_WORKER_DSN"
mv "$tmp/parallel-lane.orig" "$tmp/parallel-lane.sh"

# Real repository HEAD must pass.
bash "$GUARD" >/dev/null
printf 'check-rls-fail-closed selftest: PASS (all 6 planted mutants caught + HEAD clean).\n'
