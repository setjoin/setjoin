#!/usr/bin/env bash
# check-rls-fail-closed.sh — Wave 1.9 (#547) Release N+1 fail-closed FORCE RLS guard.
#
# Prevents regressions back to Release N advisory/permissive behavior:
#   1. Zero `EnforcementMode::WarnReleaseN` in `server-rust/crates/boot/src/`
#      or any `server-rust/bins/*/src/` production binary (including future
#      `setjoind`).
#   2. `BootPosture::bare()` in `rls_preflight.rs` stays on
#      `EnforcementMode::FailClosedReleaseNPlus1`.
#   3. `install.sh` refuses `--permissive-dsn` / `PERMISSIVE_DSN=1` and has no
#      exit-2 advisory branch for `mailctl schema preflight`.
#   4. `upgrade.sh` has a pre-stop `schema preflight` gate before Step 1 and no
#      exit-2 advisory branch for `mailctl schema preflight`.
#   5. `scripts/ci/server-rust-parallel-lane.sh` exports both `DB_APP_DSN` and
#      `DB_WORKER_DSN`.
#
# Self-test: scripts/guards/check-rls-fail-closed-selftest.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SERVER_RUST_DIR="${SERVER_RUST_DIR:-$ROOT/server-rust}"
INSTALL_SH="${INSTALL_SH:-$ROOT/mailserver/deploy/scripts/install.sh}"
UPGRADE_SH="${UPGRADE_SH:-$ROOT/mailserver/deploy/scripts/upgrade.sh}"
PARALLEL_LANE_SH="${PARALLEL_LANE_SH:-$ROOT/scripts/ci/server-rust-parallel-lane.sh}"

fail=0
report() {
  printf '  [RLS-FAIL-CLOSED] %s\n' "$*" >&2
  fail=1
}

printf '==> RLS fail-closed guard (#547)\n'

# 1. Dynamically scan crates/boot/src and bins/*/src for EnforcementMode::WarnReleaseN.
scan_dirs=()
if [ -d "$SERVER_RUST_DIR/crates/boot/src" ]; then
  scan_dirs+=("$SERVER_RUST_DIR/crates/boot/src")
else
  report "missing boot crate source directory: $SERVER_RUST_DIR/crates/boot/src"
fi

shopt -s nullglob
for bin_src in "$SERVER_RUST_DIR"/bins/*/src; do
  [ -d "$bin_src" ] && scan_dirs+=("$bin_src")
done
shopt -u nullglob

if [ "${#scan_dirs[@]}" -lt 2 ]; then
  report "expected server-rust/bins/*/src directories under $SERVER_RUST_DIR"
else
  while IFS= read -r match; do
    [ -z "$match" ] && continue
    report "production entrypoint references WarnReleaseN: $match"
  done < <(grep -rn 'WarnReleaseN' "${scan_dirs[@]}" 2>/dev/null || true)

  while IFS= read -r match; do
    [ -z "$match" ] && continue
    report "production entrypoint references retired run_with_mode: $match"
  done < <(grep -rn 'run_with_mode' "${scan_dirs[@]}" 2>/dev/null || true)
fi

# 2. BootPosture::bare() must use FailClosedReleaseNPlus1.
preflight_rs="$SERVER_RUST_DIR/crates/pg/src/rls_preflight.rs"
if [ ! -f "$preflight_rs" ]; then
  report "missing $preflight_rs"
else
  bare_block="$(awk '/pub fn bare\(\) -> Self/,/^[[:space:]]*\}/' "$preflight_rs")"
  if printf '%s\n' "$bare_block" | grep -Fq 'WarnReleaseN'; then
    report "BootPosture::bare() in rls_preflight.rs uses WarnReleaseN"
  fi
  if ! printf '%s\n' "$bare_block" | grep -Fq 'FailClosedReleaseNPlus1'; then
    report "BootPosture::bare() in rls_preflight.rs does not use FailClosedReleaseNPlus1"
  fi
fi

# 3. install.sh must refuse --permissive-dsn / PERMISSIVE_DSN and exit 2.
if [ ! -f "$INSTALL_SH" ]; then
  report "missing $INSTALL_SH"
else
  if grep -Eq '^[[:space:]]*--permissive-dsn\)[[:space:]]*PERMISSIVE_DSN=1' "$INSTALL_SH"; then
    report "install.sh still accepts --permissive-dsn instead of refusing"
  fi
  if grep -Fq 'permissive-dsn posture: no constrained roles' "$INSTALL_SH"; then
    report "install.sh still contains retired permissive credential heredoc"
  fi
  if grep -Eq '_preflight_rc"?[[:space:]]*-eq[[:space:]]*2' "$INSTALL_SH"; then
    report "install.sh still treats mailctl schema preflight exit 2 as advisory"
  fi
  if ! grep -Fq 'die "--permissive-dsn was retired' "$INSTALL_SH"; then
    report "install.sh does not refuse --permissive-dsn with die"
  fi
  if ! grep -Fq 'die "PERMISSIVE_DSN was retired' "$INSTALL_SH"; then
    report "install.sh does not refuse PERMISSIVE_DSN with die"
  fi
fi

# 4. upgrade.sh must enforce pre-stop preflight and refuse exit 2.
if [ ! -f "$UPGRADE_SH" ]; then
  report "missing $UPGRADE_SH"
else
  if grep -Eq '_preflight_rc"?[[:space:]]*-eq[[:space:]]*2' "$UPGRADE_SH"; then
    report "upgrade.sh still treats mailctl schema preflight exit 2 as advisory"
  fi
  prestop_line="$(grep -n 'run_rls_preflight_gate' "$UPGRADE_SH" | grep -Ev '^[0-9]+:[[:space:]]*#' | grep -v 'run_rls_preflight_gate()' | head -1 | cut -d: -f1 || true)"
  stop_line="$(grep -n '1\. Stopping services' "$UPGRADE_SH" | head -1 | cut -d: -f1 || true)"
  if [ -z "$prestop_line" ] || [ -z "$stop_line" ] || [ "$prestop_line" -ge "$stop_line" ]; then
    report "upgrade.sh lacks a pre-stop run_rls_preflight_gate call before Step 1"
  fi
fi

# 5. server-rust-parallel-lane.sh must export both DB_APP_DSN and DB_WORKER_DSN.
if [ ! -f "$PARALLEL_LANE_SH" ]; then
  report "missing $PARALLEL_LANE_SH"
else
  if ! grep -Eq '^export DB_APP_DSN=' "$PARALLEL_LANE_SH"; then
    report "server-rust-parallel-lane.sh does not export DB_APP_DSN"
  fi
  if ! grep -Eq '^export DB_WORKER_DSN=' "$PARALLEL_LANE_SH"; then
    report "server-rust-parallel-lane.sh does not export DB_WORKER_DSN"
  fi
fi

if [ "$fail" -ne 0 ]; then
  printf 'RLS fail-closed guard FAILED.\n' >&2
  exit 1
fi
printf 'RLS fail-closed guard: PASS.\n'
