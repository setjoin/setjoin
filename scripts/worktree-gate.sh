#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# worktree-gate.sh — build + pgTAP + Go-DB-test gate against a NAMED test DB,
# so parallel git worktrees each get their own database instead of clobbering
# the shared mailserver_test fixtures (the pollution class: one worktree's
# `go test ./...` seeds users, another worktree's pgTAP run reads them).
#
# Reuses load-test-schema.sh's existing DB_NAME parameterization (env-
# overridable, default mailserver_test, zero change for existing callers) —
# this script just points it, and the Go suites' DB_DSN, at a caller-chosen
# name instead of hardcoding one.
#
# Usage:
#   bash scripts/worktree-gate.sh <db-name>
#   e.g. bash scripts/worktree-gate.sh mailserver_test2
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB="${1:?usage: worktree-gate.sh <db-name>}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"
DSN="postgres://${DB_USER}@${DB_HOST}:${DB_PORT}/${DB}?sslmode=disable"

echo "==> worktree-gate: $DB"

echo "==> 1/3 load-test-schema ($DB)"
DB_NAME="$DB" DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" \
  bash "$ROOT/scripts/load-test-schema.sh"

echo "==> 2/3 go build"
( cd "$ROOT/authserver" && go build ./... )
( cd "$ROOT/mailserver" && go build ./... )

echo "==> 2/3 go test (DB_DSN -> $DB)"
export DB_DSN="$DSN"
export TEST_DB_DSN="$DSN"
export REQUIRE_DB=1
( cd "$ROOT/authserver" && go test ./... )
( cd "$ROOT/mailserver" && go test ./... )

# The Go suite above mutates $DB (seeded users/mailboxes/messages/blobs/jobs);
# pgTAP's own fixtures (_fixtures.sql) assume a pristine DB, so a Go-test row
# left behind collides with a pgTAP fixture (e.g. duplicate users_pkey) and
# fails an unrelated pgTAP file. Reload before pgTAP — same ordering
# scripts/test.sh uses for mailserver_test.
echo "==> reloading $DB before pgTAP (isolate from Go-suite residue)"
DB_NAME="$DB" DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" \
  bash "$ROOT/scripts/load-test-schema.sh"

echo "==> 3/3 pgTAP ($DB)"
pg_prove -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB" "$ROOT/mailserver/sql/tests/"*.pg
pg_prove -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB" "$ROOT/authserver/sql/tests/"*.pg

echo "==> worktree-gate: green against $DB"
