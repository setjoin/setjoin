#!/usr/bin/env bash
# Executed INSIDE the setjoin-ci-linux-tc throwaway container (linux/arm64) by
# the xinchuang tagged-lane job. Mirrors the previous docker-based tagged lane:
# build + vet + test with -tags xinchuang, DB-backed (native LISTEN, the
# OnReconnect compensation hook) with REQUIRE_DB fail-closed.
set -euo pipefail

REPO="${REPO_MOUNT:-/work}"
cd "$REPO"

CI_PG_PORT="${CI_PG_PORT:-25432}" # container-local
CI_PG_PASSWORD="$(openssl rand -hex 24)"
echo "::add-mask::$CI_PG_PASSWORD"
PGDATA="$(mktemp -d /tmp/ci-pgdata.XXXXXX)"
chown postgres:postgres "$PGDATA"
pwfile="$(mktemp)"
printf '%s\n' "$CI_PG_PASSWORD" >"$pwfile"
chown postgres:postgres "$pwfile"
su postgres -c "$(command -v initdb) -D '$PGDATA' -U mail --pwfile='$pwfile' -A scram-sha-256 --auth-local=scram-sha-256" \
  >/tmp/initdb.log 2>&1 || {
  cat /tmp/initdb.log
  exit 1
}
rm -f "$pwfile"
su postgres -c "$(command -v pg_ctl) -D '$PGDATA' -l /tmp/pg.log -o '-c listen_addresses=127.0.0.1 -c port=$CI_PG_PORT' -w start" \
  >/tmp/pgctl.log 2>&1 || {
  cat /tmp/pg.log /tmp/pgctl.log
  exit 1
}
# Credentials BEFORE any client connection: createdb over TCP hits SCRAM, and
# without PGPASSWORD libpq prompts on stdin (which never answers in CI) — the
# 60-minute timeout in the first migrated run was exactly this.
export PGPASSWORD="$CI_PG_PASSWORD"
export DB_DSN="postgres://mail:${CI_PG_PASSWORD}@127.0.0.1:${CI_PG_PORT}/mailserver_test?sslmode=disable"
export TEST_DB_DSN="$DB_DSN"
cleanup() {
  su postgres -c "$(command -v pg_ctl) -D '$PGDATA' -m fast stop" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Fail-closed: with REQUIRE_DB set, a missing DB_DSN is a hard failure (the
# lane used to SKIP silently when the DB was absent).
export REQUIRE_DB=1

echo "== tagged build + vet + test (-tags xinchuang) =="
(cd mailserver &&
  go build -tags xinchuang ./... &&
  go vet -tags xinchuang ./... &&
  go test -tags xinchuang ./internal/xinchuang/...)

echo "tagged lane: PASS"
