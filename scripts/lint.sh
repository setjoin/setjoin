#!/usr/bin/env bash
source "$(dirname "$0")/_base.sh"

# Structural guards live in the manifest now (scripts/run-guards.sh, run by
# scripts/test.sh and CI) — lint.sh is linters-only so guards run exactly once
# per gate instead of once per orchestrator.

while IFS=$'\t' read -r module_id module_path module_workspace _kind _tags _gowork; do
  [[ "$module_workspace" == "workspace" ]] || continue
  echo "==> Linting $module_id"
  (cd "$ROOT/$module_path" && golangci-lint run ./...)
done < <(node "$ROOT/scripts/go-module-catalog.mjs" list lint)

# asrbot (B3 Task 12): NOT in go.work (eng E1). No asrbot/.golangci.yml —
# golangci-lint's upward config search reuses this repo's root
# .golangci.yml (mailserver/.golangci.yml stays a mailserver-local
# override, untouched by this). --build-tags mirrors build.sh/test.sh's
# -tags nolibopusfile (see build.sh's comment for the full rationale). A
# LOUD named skip when libopus isn't installed, never a silent one.
if pkg-config --exists opus 2>/dev/null; then
  echo "==> Linting asrbot"
  cd "$ROOT/asrbot" && GOWORK=off golangci-lint run --build-tags nolibopusfile ./...
else
  echo "==> SKIP asrbot lint (libopus not installed — brew install opus / apt install libopus-dev)"
fi

echo "==> Checking webmail (svelte-check + tsc)"
cd "$ROOT/mailserver/webmail" && npm run check

echo "==> Linting webmail TypeScript/Svelte (ESLint)"
cd "$ROOT/mailserver/webmail" && npm run lint

echo "==> Linting webmail styles (Stylelint)"
cd "$ROOT/mailserver/webmail" && npm run lint:css

echo "All linters passed."
