#!/usr/bin/env bash
# CONTRACT: capability-app-catalog
# Keeps launch order, landing paths, route ownership, and guards derived from
# webmail/src/lib/nav/navConfig.ts. Behavioral coverage lives beside the module.
source "$(dirname "$0")/_base.sh"

CATALOG="${APP_CATALOG_FILE:-$ROOT/mailserver/webmail/src/lib/nav/navConfig.ts}"
SESSION="${APP_SESSION_FILE:-$ROOT/mailserver/webmail/src/lib/stores/session.ts}"
LAYOUT="${APP_LAYOUT_FILE:-$ROOT/mailserver/webmail/src/routes/+layout.svelte}"

usage() {
  echo "usage: check-app-catalog.sh [--self-test|--help]"
}

diagnostic() {
  local value="$1" cause="$2" fix="$3"
  echo "E_APP_CATALOG_DRIFT: capability-app catalog drift" >&2
  echo "  value: $value" >&2
  echo "  cause: $cause" >&2
  echo "  fix: $fix" >&2
  echo "  rerun: bash scripts/check-app-catalog.sh" >&2
}

check_contract() {
  local failed=0 app
  for literal in 'prefixes: readonly string[]' 'export const APP_ORDER' 'export const APP_PATHS' 'export function appForPath'; do
    if ! grep -Fq -- "$literal" "$CATALOG"; then
      diagnostic "$CATALOG" "missing catalog authority: $literal" "restore the derived authority in navConfig.ts"
      failed=1
    fi
  done
  for app in mail calendar contacts tasks approvals drive chat meet; do
    if ! grep -Eq "id: '$app'.*path: '/[^']+'.*prefixes: \['/[^']+'\]" "$CATALOG"; then
      diagnostic "$app" "catalog row is missing its canonical path/prefix" "add the complete app row to RAIL_APPS"
      failed=1
    fi
  done
  if ! grep -Fq "import { APP_ORDER, APP_PATHS } from '\$lib/nav/navConfig';" "$SESSION"; then
    diagnostic "$SESSION" "session landing logic is not catalog-derived" "import APP_ORDER and APP_PATHS from navConfig"
    failed=1
  fi
  if grep -Eq '^(const|let) APP_ORDER|const APP_PATHS' "$SESSION"; then
    diagnostic "$SESSION" "session.ts redeclares app order or paths" "delete the duplicate and use navConfig exports"
    failed=1
  fi
  if ! grep -Fq "GUEST_APPS, appForPath" "$LAYOUT" || ! grep -Fq 'const app = appForPath(p);' "$LAYOUT"; then
    diagnostic "$LAYOUT" "layout guards do not resolve routes through appForPath" "use the catalog helper for member and Guest guards"
    failed=1
  fi
  if grep -Eq "p\.startsWith\('/(inbox|calendar|contacts|tasks|approvals|drive|chat|meet)'|Record<string, AppId>" "$LAYOUT"; then
    diagnostic "$LAYOUT" "layout contains a second raw-prefix app map" "remove it and call appForPath(pathname)"
    failed=1
  fi
  [[ "$failed" -eq 0 ]]
}

run_behavior() {
  (
    cd "$ROOT/mailserver/webmail"
    npx vitest run src/lib/nav/navConfig.test.ts src/routes/layout.test.ts
  )
}

case "${1:-}" in
  --help) usage ;;
  --self-test)
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    sed '/export function appForPath/d' "$CATALOG" > "$tmp/navConfig.ts"
    original="$CATALOG"
    CATALOG="$tmp/navConfig.ts"
    set +e
    diagnostic_output="$(check_contract 2>&1)"
    diagnostic_status=$?
    set -e
    if [[ "$diagnostic_status" -eq 0 ]]; then
      echo "check-app-catalog self-test: broken catalog was accepted" >&2
      exit 1
    fi
    diagnostic_output="${diagnostic_output//$tmp/<self-test-fixture>}"
    printf '%s\n' "$diagnostic_output" >&2
    CATALOG="$original"
    echo "check-app-catalog self-test: PASS"
    ;;
  "")
    check_contract
    run_behavior
    echo "check-app-catalog: PASS"
    ;;
  *) usage >&2; exit 2 ;;
esac
