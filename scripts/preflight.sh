#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# preflight.sh — verify a contributor's toolchain + services BEFORE the test
# suite runs, failing LOUD with an install/fix hint instead of a raw
# "connection refused" 200 lines into pg_prove.
#
# It checks, in order:
#   1. Toolchain binaries:  go, node, npm, psql, pg_prove  (+ optional: weed)
#   2. The DIRECT Postgres (DB_DIRECT_DSN / 127.0.0.1:5432) — the connection the
#      test suite and LISTEN/NOTIFY use.
#   3. The PgBouncer pool (DB_DSN) — checked only if it differs from the direct
#      DSN (the default test env points both at :5432, so this is a no-op there;
#      a real deploy points DB_DSN at :6432).
#   4. The mailserver_test database exists AND has the V001 baseline loaded
#      (MAX(version) ≥ 1) — hint: bash scripts/load-test-schema.sh.
#   5. SeaweedFS / S3 — OPTIONAL for the test+build path (the pgTAP + Go suites
#      don't need it); checked only when S3_ENDPOINT is set, and a failure is a
#      WARNING, not fatal.
#
# Exit status: 0 = all hard checks passed (warnings allowed); 1 = a hard
# prerequisite is missing/unreachable (the message names the fix).
#
# Usage:
#   bash scripts/preflight.sh           # full check (default)
#   bash scripts/preflight.sh --tools   # toolchain binaries only (no services)
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ── Connection defaults (match scripts/test.sh + reload-reducers.sh) ─────────
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"
DB_NAME="${DB_NAME:-mailserver_test}"
DIRECT_DSN="${DB_DIRECT_DSN:-postgres://${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable}"
POOL_DSN="${DB_DSN:-$DIRECT_DSN}"

TOOLS_ONLY=false
for arg in "$@"; do
  case "$arg" in
    --tools) TOOLS_ONLY=true ;;
  esac
done

fail=0
warned=0

red()   { printf '\033[31m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$1"; }

ok()   { green   "  OK   $1"; }
err()  { red     "  FAIL $1"; fail=1; }
warn() { yellow  "  WARN $1"; warned=1; }

echo "==> Preflight: toolchain + services for the setjoin test suite"

# ── 1. Toolchain ────────────────────────────────────────────────────────────
echo ""
echo "  Toolchain:"

# Required Go (read the floor from go.mod so the hint never drifts).
GO_REQ="$(grep -m1 '^go ' "$ROOT/mailserver/go.mod" 2>/dev/null | awk '{print $2}')"
GO_REQ="${GO_REQ:-1.26}"
if command -v go >/dev/null 2>&1; then
  ok "go ($(go version | awk '{print $3}')) — go.mod requires go${GO_REQ}"
else
  err "go not found — install Go ${GO_REQ}+ from https://go.dev/dl/"
fi

if command -v node >/dev/null 2>&1; then
  ok "node ($(node --version))"
else
  err "node not found — install Node 20+ (webmail: 'npm run check && npm test')"
fi

if command -v npm >/dev/null 2>&1; then
  ok "npm ($(npm --version))"
else
  err "npm not found — ships with Node (https://nodejs.org)"
fi

if command -v psql >/dev/null 2>&1; then
  ok "psql ($(psql --version | awk '{print $3}'))"
else
  err "psql not found — install the PostgreSQL 18+ client (brew install postgresql@18 / apt install postgresql-client)"
fi

if command -v pg_prove >/dev/null 2>&1; then
  ok "pg_prove (TAP::Parser::SourceHandler::pgTAP)"
else
  err "pg_prove not found — needed for pgTAP. Install: cpan TAP::Parser::SourceHandler::pgTAP  (or: cpanm App::pg_prove)"
fi

# weed (SeaweedFS) is only needed to run the LIVE server (setup-test-env.sh),
# never for the pgTAP/Go suite — so it is informational only.
if command -v weed >/dev/null 2>&1; then
  ok "weed (SeaweedFS) — present (needed only for the live dev server)"
else
  warn "weed (SeaweedFS) not found — fine for tests; needed for scripts/setup-test-env.sh (https://github.com/seaweedfs/seaweedfs/releases)"
fi

# libopus is asrbot's (B3 Task 12) ONE native dependency (delta 5/9's cgo
# containment — no other module needs it). Informational only: build.sh/
# test.sh/lint.sh's own `pkg-config --exists opus` guard already skips
# asrbot LOUDLY when it's missing, so a missing libopus here is a WARN, not
# a FAIL — the rest of the suite runs fine without it.
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists opus 2>/dev/null; then
  ok "libopus (pkg-config opus) — present, asrbot will build"
else
  warn "libopus not found — asrbot (the Meet captions bot) will be SKIPPED by build.sh/test.sh/lint.sh. Install: brew install pkg-config opus / apt install pkg-config libopus-dev"
fi

if $TOOLS_ONLY; then
  echo ""
  if [ "$fail" -ne 0 ]; then
    red "==> Preflight FAILED — install the missing tools above."
    exit 1
  fi
  green "==> Toolchain OK."
  exit 0
fi

# ── 2. Direct Postgres ───────────────────────────────────────────────────────
echo ""
echo "  Services:"

# psql is required to probe the DB; if it's missing the toolchain check already
# failed — bail now with the actionable summary rather than emit a confusing
# "psql: command not found" from the probes below.
if ! command -v psql >/dev/null 2>&1; then
  echo ""
  red "==> Preflight FAILED — psql is required to verify the database (see above)."
  exit 1
fi

if psql "$DIRECT_DSN" -tAc 'SELECT 1' >/dev/null 2>&1; then
  ok "direct Postgres reachable ($DB_HOST:$DB_PORT as $DB_USER)"
else
  err "direct Postgres NOT reachable at $DB_HOST:$DB_PORT (DSN: ${DB_DIRECT_DSN:-<default>})
       → Start PostgreSQL and ensure role '$DB_USER' exists:
         createuser -s $DB_USER        # or: CREATE ROLE $DB_USER LOGIN SUPERUSER;
       → On macOS (Homebrew):  brew services start postgresql@18
       → On Debian/Ubuntu:     sudo systemctl start postgresql"
fi

# ── 3. PgBouncer pool (only if distinct from the direct DSN) ─────────────────
if [ "$POOL_DSN" != "$DIRECT_DSN" ]; then
  if psql "$POOL_DSN" -tAc 'SELECT 1' >/dev/null 2>&1; then
    ok "PgBouncer pool reachable (DB_DSN)"
  else
    err "PgBouncer pool NOT reachable (DB_DSN: $DB_DSN)
       → Start PgBouncer (it fronts Postgres for query traffic; the direct DSN is LISTEN/NOTIFY-only)."
  fi
else
  ok "PgBouncer pool: DB_DSN == direct DSN (single-node default — no separate pool to check)"
fi

# ── 4. Test database + baseline loaded ───────────────────────────────────────
# Only probe the DB contents if the direct connection itself is up; otherwise
# the message would just repeat the connection failure above.
if psql "$DIRECT_DSN" -tAc 'SELECT 1' >/dev/null 2>&1; then
  if psql "$DIRECT_DSN" -tAc "SELECT to_regclass('public.schema_migrations') IS NOT NULL" 2>/dev/null | grep -q '^t$'; then
    ver="$(psql "$DIRECT_DSN" -tAc 'SELECT COALESCE(MAX(version),0) FROM schema_migrations' 2>/dev/null | tr -d '[:space:]')"
    if [ "${ver:-0}" -ge 1 ] 2>/dev/null; then
      ok "database '$DB_NAME' has the V001 baseline loaded (schema_migrations MAX = $ver)"
    else
      err "database '$DB_NAME' exists but the V001 baseline is NOT loaded (schema_migrations MAX = ${ver:-0})
       → Load it:  bash scripts/load-test-schema.sh"
    fi
  else
    err "database '$DB_NAME' is missing the schema_migrations table — baseline not loaded
       → Load it:  bash scripts/load-test-schema.sh"
  fi
fi

# ── 5. SeaweedFS / S3 (optional for the test path) ───────────────────────────
if [ -n "${S3_ENDPOINT:-}" ]; then
  if command -v curl >/dev/null 2>&1 && curl -s -o /dev/null --max-time 3 "http://${S3_ENDPOINT}/" 2>/dev/null; then
    ok "S3/SeaweedFS reachable at ${S3_ENDPOINT}"
  else
    warn "S3 endpoint ${S3_ENDPOINT} not reachable — fine for pgTAP/Go tests; needed for the live server / blob handling"
  fi
else
  ok "S3/SeaweedFS: not configured (optional — the pgTAP + Go test suites do not need it)"
fi

# ── Verdict ──────────────────────────────────────────────────────────────────
echo ""
if [ "$fail" -ne 0 ]; then
  red "==> Preflight FAILED — fix the items marked FAIL above, then re-run."
  exit 1
fi
if [ "$warned" -ne 0 ]; then
  yellow "==> Preflight passed with warnings (optional services unavailable)."
else
  green "==> Preflight OK — toolchain and services ready."
fi
exit 0
