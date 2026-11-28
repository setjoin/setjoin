#!/usr/bin/env bash
source "$(dirname "$0")/../_base.sh"

# Structural guards live in the manifest now (scripts/run-guards.sh, run by
# scripts/test.sh and CI) — lint.sh is linters-only so guards run exactly once
# per gate instead of once per orchestrator.

echo "==> Checking webmail (svelte-check + tsc)"
cd "$ROOT/mailserver/webmail" && npm run check

echo "==> Linting webmail TypeScript/Svelte (ESLint)"
cd "$ROOT/mailserver/webmail" && npm run lint

echo "==> Linting webmail styles (Stylelint)"
cd "$ROOT/mailserver/webmail" && npm run lint:css

echo "All linters passed."
