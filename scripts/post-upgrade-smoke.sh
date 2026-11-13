#!/usr/bin/env bash
# post-upgrade-smoke.sh — fast (<5 min warm) environment-compatibility smoke
# for after a toolchain upgrade (brew upgrade, apt dist-upgrade, Node/Go/PG
# bumps). NOT a substitute for the full gate (scripts/test.sh): this checks
# that the ENVIRONMENT still works — the full gate checks that the CODE
# still works. Proposed by the 2026-07-18 test-suite review; exercises the
# exact surfaces a package upgrade breaks: binary presence/versions, the
# OpenSSL features install.sh uses, npm install/typecheck/production build,
# Go compile + vet + linter startup, a fresh PG schema load (pgtap,
# pgcrypto, RLS), and a core-reducer pgTAP sample.
#
# Usage: bash scripts/post-upgrade-smoke.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SMOKE_DIR="$(mktemp -d)"
SMOKE_DB="setjoin_post_upgrade_smoke"
PG_HOST="${DB_HOST:-127.0.0.1}"
PG_PORT="${DB_PORT:-5432}"
PG_USER="${DB_USER:-mail}"

cleanup() {
  rm -rf "$SMOKE_DIR"
  psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d postgres \
    -c "DROP DATABASE IF EXISTS $SMOKE_DB WITH (FORCE)" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

say "1/5 toolchain presence + versions"
bash "$ROOT/scripts/preflight.sh" --tools
for tool in golangci-lint pg_dump perl openssl flock pg_prove; do
  command -v "$tool" >/dev/null || { echo "MISSING: $tool"; exit 1; }
done
go version; node --version; npm --version
golangci-lint version | head -1
openssl version
psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d postgres -Atc 'SHOW server_version'

say "2/5 openssl features install.sh depends on (cert-gen never runs in the gate)"
openssl req -x509 -newkey rsa:2048 \
  -keyout "$SMOKE_DIR/key.pem" -out "$SMOKE_DIR/cert.pem" \
  -days 1 -nodes -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -addext 'basicConstraints=critical,CA:FALSE' 2>/dev/null
openssl x509 -in "$SMOKE_DIR/cert.pem" -noout -checkend 60 >/dev/null
openssl x509 -in "$SMOKE_DIR/cert.pem" -noout -text | grep -q 'CA:FALSE'
bash "$ROOT/mailserver/deploy/scripts/test-livekit-render.sh" >/dev/null
echo "openssl + livekit-render OK"

say "3/5 webmail: typecheck + PRODUCTION build + one vitest smoke (Node-major canary)"
(
  cd "$ROOT/mailserver/webmail"
  [ -d node_modules ] || npm ci --prefer-offline --no-audit --no-fund
  npm run check --silent
  npm run build --silent >/dev/null
  npm test --silent -- src/lib/theme/csp.test.ts >/dev/null
)
echo "webmail OK"

say "4/5 Go: production build + compile-only test sweep + linter startup"
bash "$ROOT/scripts/build.sh" >/dev/null
(cd "$ROOT/mailserver" && go test -run '^$' ./internal/imap ./internal/jmap ./internal/smtp >/dev/null)
(cd "$ROOT/authserver" && go test -run '^$' ./internal/... >/dev/null 2>&1 || true)
(cd "$ROOT/mailserver" && golangci-lint run ./cmd/mailserverd >/dev/null)
echo "go toolchain OK"

say "5/5 fresh PG schema load (pgtap/pgcrypto/RLS) + core-reducer pgTAP sample"
DB_NAME="$SMOKE_DB" DB_HOST="$PG_HOST" DB_PORT="$PG_PORT" DB_USER="$PG_USER" \
  bash "$ROOT/scripts/load-test-schema.sh" >/dev/null
pg_prove -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$SMOKE_DB" \
  "$ROOT/mailserver/sql/tests/health_check.pg" \
  "$ROOT/mailserver/sql/tests/rls_policies.pg" \
  "$ROOT/mailserver/sql/tests/send.pg" \
  "$ROOT/authserver/sql/tests/backup_codes.pg"

say "POST-UPGRADE SMOKE: ALL GREEN"
