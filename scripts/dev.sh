#!/usr/bin/env bash
source "$(dirname "$0")/_base.sh"

echo "==> Starting full local stack (PostgreSQL, PgBouncer, SeaweedFS, gateway)"

# ── Build ────────────────────────────────────────
echo "  Building authserver..."
(cd "$ROOT/authserver" && go build -o authserverd ./cmd/authserverd)

echo "  Building mailserver..."
(cd "$ROOT/mailserver" && go build -o mailserverd ./cmd/mailserverd)

# ── Check prerequisites ──────────────────────────
if ! pg_isready -h 127.0.0.1 -p 5433 -U mail >/dev/null 2>&1; then
    echo "  ERROR: PostgreSQL not reachable at 127.0.0.1:5433 (PgBouncer)"
    echo "  Start PostgreSQL and PgBouncer first, then re-run."
    exit 1
fi
echo "  PostgreSQL + PgBouncer: OK"

if ! curl -s http://127.0.0.1:9333/cluster/status >/dev/null 2>&1; then
    echo "  Starting SeaweedFS master..."
    weed master -mdir=/tmp/seaweedfs/master -port=9333 &
    WEED_MASTER_PID=$!
    sleep 2
fi
echo "  SeaweedFS master: OK"

if ! curl -s http://127.0.0.1:8888/ >/dev/null 2>&1; then
    echo "  Starting SeaweedFS filer..."
    weed filer -master=127.0.0.1:9333 -port=8888 -dir=/tmp/seaweedfs/filer &
    WEED_FILER_PID=$!
    sleep 1
fi
echo "  SeaweedFS filer: OK"

# ── Start services ───────────────────────────────
WEED_MASTER_PID=""
WEED_FILER_PID=""
AUTH_PID=""
GW_PID=""

cleanup() {
    echo ""
    echo "==> Shutting down..."
    [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
    [ -n "$AUTH_PID" ] && kill "$AUTH_PID" 2>/dev/null || true
    [ -n "$WEED_FILER_PID" ] && kill "$WEED_FILER_PID" 2>/dev/null || true
    [ -n "$WEED_MASTER_PID" ] && kill "$WEED_MASTER_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    echo "==> Stopped."
}
trap cleanup EXIT INT TERM

echo "  Starting authserver on :8443..."
"$ROOT/authserver/authserverd" &
AUTH_PID=$!
sleep 1

echo "  Loading reducers..."
bash "$ROOT/scripts/reload-reducers.sh"
echo ""
echo "  Starting gateway on :80..."
"$ROOT/mailserver/mailserverd" &
GW_PID=$!
sleep 1

echo ""
echo "==> All services running:"
echo "    Gateway:    http://localhost:80"
echo "    Authserver: http://localhost:8443"
echo "    SeaweedFS:  http://localhost:8888  (filer)"
echo "    SeaweedFS:  http://localhost:9333  (master)"
echo "    PostgreSQL: 127.0.0.1:5433 (via PgBouncer)"
echo ""
echo "    Press Ctrl+C to stop."

wait
