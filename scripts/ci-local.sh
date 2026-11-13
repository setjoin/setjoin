#!/usr/bin/env bash
# ci-local.sh — run the xinchuang-ci.yml pipeline locally, before you push.
#
# GitHub Actions minutes are finite; this reproduces the same gates on your
# machine using the existing scripts. It mirrors the three CI jobs:
#   1. SQL-injection grep + cross-compile check (arm64, loong64)  [cross-compile-check]
#   2. DB-backed Go tests + the pgTAP reducer suite               [unit-tests-amd64]
#   3. (native) cross-build smoke is QEMU/Docker-only — skipped here unless --smoke
# plus lint and the structural guard scripts CI doesn't yet run.
#
# Prereqs: Go, and (for the test stage) a running Postgres reachable as the DSN
# below — the same one scripts/test.sh / load-test-schema.sh use. Start one with:
#   scripts/setup-test-env.sh        (or your own postgres on 127.0.0.1:5432, user 'mail')
#
# Usage:
#   bash scripts/ci-local.sh              # full local CI
#   bash scripts/ci-local.sh --no-db      # skip the DB stages (compile/lint only)
#   bash scripts/ci-local.sh --smoke      # also run the QEMU cross-arch smoke (needs Docker)
#
# Exit non-zero on the first failing stage (set -e), naming it — so a green run
# here means CI should be green too. For exact-GitHub-fidelity instead, use `act`
# (https://github.com/nektos/act): `act -j unit-tests-amd64` runs the real YAML in
# Docker, but it is heavier and needs Docker + a postgres service container.

set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

RUN_DB=1
SMOKE=0
for a in "$@"; do
  case "$a" in
    --no-db) RUN_DB=0 ;;
    --smoke) SMOKE=1 ;;
    *) echo "unknown flag: $a"; exit 2 ;;
  esac
done

fail=0
stage() { printf '\n\033[1m══ %s ══\033[0m\n' "$1"; }
run()   { echo "+ $*"; if "$@"; then echo "  ✓ $1"; else echo "  ✗ FAILED: $*"; fail=1; fi; }

# ── 1. SQL-injection check (single home: the guard script CI also runs) ───────
stage "SQL injection check"
run bash scripts/check-sql-injection.sh

# ── 2. Lint ───────────────────────────────────────────────────────────────────
stage "Lint (golangci-lint)"
run bash scripts/lint.sh

# ── 3. Cross-compile check (arm64 + loong64) ─────────────────────────────────
stage "Cross-compile (arm64, loong64)"
for arch in arm64 loong64; do
  for mod in authserver mailserver shared mailctl; do
    echo "+ $mod → linux/$arch"
    if ( cd "$mod" && GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build ./... ); then
      echo "  ✓ $mod/$arch"
    else
      echo "  ✗ FAILED: $mod cross-compile $arch"
      fail=1
    fi
  done
done

# ── 4. Structural guards ──────────────────────────────────────────────────────
# The full manifest (scripts/run-guards.sh — every scripts/check-*.sh, self-test
# first) runs INSIDE scripts/test.sh at stage 5, so guards execute exactly once.
# Only when the DB stages are skipped do we run the manifest here, minus the
# DB-needing guards, so --no-db still gets every static verdict.
if [ "$RUN_DB" = 0 ]; then
  stage "Structural guards (static — full manifest, --no-db)"
  run bash scripts/run-guards.sh --no-db
fi

# ── 5. DB-backed Go tests + pgTAP (the gap CI used to skip) ───────────────────
if [ "$RUN_DB" = 1 ]; then
  stage "DB-backed tests + pgTAP (REQUIRE_DB fail-closed)"
  # Same DSN as scripts/test.sh; REQUIRE_DB makes a missing DB FAIL not skip.
  export DB_DSN="${DB_DSN:-postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable}"
  export REQUIRE_DB=1
  if bash scripts/test.sh; then echo "  ✓ tests + pgTAP"; else echo "  ✗ FAILED: scripts/test.sh"; fail=1; fi
else
  stage "DB-backed tests + pgTAP"
  echo "  (skipped — --no-db)"
fi

# ── 6. QEMU cross-arch smoke (optional; needs Docker) ────────────────────────
if [ "$SMOKE" = 1 ]; then
  stage "Cross-arch QEMU smoke"
  for arch in arm64 loong64; do
    run bash scripts/cross-build.sh --arch "$arch" --smoke
  done
fi

printf '\n'
if [ "$fail" = 0 ]; then
  echo "✅ ci-local: ALL STAGES PASSED — CI should be green."
else
  echo "❌ ci-local: one or more stages FAILED (see ✗ above)."
fi
exit "$fail"
