#!/usr/bin/env bash
# Entirely private cluster and fixed loopback peers inside the disposable CI container.
set -euo pipefail
export PATH=/usr/lib/postgresql/17/bin:$PATH
PGDATA_FIXTURE=$(mktemp -d /tmp/gofree-rel3-pg.XXXXXX)
chown postgres:postgres "$PGDATA_FIXTURE"
cleanup() {
  runuser -u postgres -- pg_ctl -D "$PGDATA_FIXTURE" -m fast -w stop >/dev/null
  rm -rf -- "$PGDATA_FIXTURE"
}
trap cleanup EXIT
runuser -u postgres -- initdb -D "$PGDATA_FIXTURE" -A trust --no-locale >/dev/null
runuser -u postgres -- pg_ctl -D "$PGDATA_FIXTURE" -o '-h 127.0.0.1 -p 55452 -c max_locks_per_transaction=512 -c shared_buffers=32MB' -l "$PGDATA_FIXTURE/server.log" -w start >/dev/null
export DB_HOST=127.0.0.1 DB_PORT=55452 DB_USER=postgres PGPASSWORD=gofree DB_NAME=${REL_FIXTURE_DB:-gofree_e2e_rel2}
export TEST_DB_DSN=postgres://postgres:gofree@127.0.0.1:55452/$DB_NAME
bash scripts/load-test-schema.sh >"$PGDATA_FIXTURE/schema.log" 2>&1 || { tail -50 "$PGDATA_FIXTURE/schema.log"; exit 1; }
# Password/role setup is confined to this container's new cluster.
psql -h 127.0.0.1 -p 55452 -U postgres -d "$DB_NAME" -v ON_ERROR_STOP=1 -qc "ALTER ROLE setjoin_updater PASSWORD 'updater_e2e'"
fixture_cases="apply interrupted tampered-artifact nested-comment rollback"
if [ -n "${REL3_RECOVERY_CASE:-}" ]; then fixture_cases=apply; fi
for fixture_case in $fixture_cases; do
  REL2_INSTALLER_CASE="$fixture_case" python3 server-rust/bins/updater/tests/installer.py "$@"
done

if [ "${REL3_RECORD_ALL_RECOVERY:-}" = 1 ]; then
  REL3_RECOVERY_CASE=response-loss REL2_INSTALLER_CASE=apply python3 server-rust/bins/updater/tests/installer.py "$@"
fi
if [ "${REL3_RECOVERY_CASE:-}" = authored ] && [ "${2:-}" != --go ]; then
  REL3_RECOVERY_CASE=response-loss REL2_INSTALLER_CASE=apply python3 server-rust/bins/updater/tests/installer.py "$@"
  REL3_RECOVERY_CASE='' REL3_SWAP_ONLY=1 REL2_INSTALLER_CASE=apply python3 server-rust/bins/updater/tests/installer.py "$@"
fi
