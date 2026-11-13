#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# setjoin test environment setup — production-like, self-contained in /tmp
#
# What it does:
#   1. Generates self-signed TLS cert, JWT secret, DB encryption key
#   2. Creates a fresh mailserver_test database
#   3. Runs all authserver + mailserver migrations
#   4. Loads all PL/pgSQL reducers
#   5. Writes a single config.yaml (shared by gateway + authserver)
#   6. Starts SeaweedFS (master + filer, fresh volumes)
#   7. Starts authserver (internal-only, 127.0.0.1:8443)
#   8. Starts gateway (h2c on :8443, proxies /auth/* to authserver)
#
# Usage:
#   bash scripts/setup-test-env.sh
#   bash scripts/setup-test-env.sh --keep-running  # don't trap EXIT cleanup
#
# After running:
#   http://localhost:8443/setup    — onboarding wizard
#   http://localhost:8443/         — login page (after setup)
#
# Cleanup:
#   bash scripts/cleanup-test-env.sh
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_DIR="/tmp/setjoin-test"
KEEP_RUNNING=false

for arg in "$@"; do
  case "$arg" in
    --keep-running) KEEP_RUNNING=true ;;
  esac
done

# ── Secrets ───────────────────────────────────────────────────────────────
JWT_SECRET="$(openssl rand -hex 32)"
DB_ENCRYPTION_KEY="$(openssl rand -hex 16)"
INTERNAL_API_KEY="$(openssl rand -hex 32)"
S3_ACCESS_KEY="testaccesskey"
S3_SECRET_KEY="testsecretkey"

# ── Database ──────────────────────────────────────────────────────────────
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"
DB_NAME="mailserver_test"
DB_DSN="postgres://${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable"

PG_OPTS="-h $DB_HOST -p $DB_PORT -U $DB_USER"

echo "==> Setting up test environment in $TEST_DIR"
echo ""

# ── 1. Create test directory ────────────────────────────────────────────
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR/certs"
mkdir -p "$TEST_DIR/seaweedfs/master"
mkdir -p "$TEST_DIR/seaweedfs/filer"
mkdir -p "$TEST_DIR/seaweedfs/volume"

# ── 2. Generate self-signed TLS certificate ─────────────────────────────
echo "  Generating self-signed TLS cert (valid 7 days)..."
openssl req -x509 -newkey rsa:2048 \
  -keyout "$TEST_DIR/certs/key.pem" \
  -out "$TEST_DIR/certs/cert.pem" \
  -days 7 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  2>/dev/null
echo "  TLS cert: OK"

# ── 3. Build binaries ───────────────────────────────────────────────────
echo "  Building authserver..."
(cd "$ROOT/authserver" && go build -o "$TEST_DIR/authserverd" ./cmd/authserverd) 2>&1 | tail -1
echo "  Building mailserver gateway..."
(cd "$ROOT/mailserver" && go build -o "$TEST_DIR/mailserverd" ./cmd/mailserverd) 2>&1 | tail -1

# ── 4. Fresh database ───────────────────────────────────────────────────
echo "  Dropping old test database (if exists)..."
psql $PG_OPTS -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME WITH (FORCE);" 2>/dev/null || true
echo "  Creating fresh database: $DB_NAME"
psql $PG_OPTS -d postgres -c "CREATE DATABASE $DB_NAME OWNER $DB_USER TEMPLATE template0;"

# ── 5. Load the baseline (ARCH-007 collapse) ─────────────────────────────
# Post-collapse the schema is ONE baseline (combined mailserver+authserver schema
# + seed data + the schema_migrations baseline row), not a replayed migration
# chain. The pre-collapse dual-source tree is archived under sql/_archive/.
echo "  Loading combined baseline (V001__baseline.sql)..."
(cd "$ROOT/mailserver/sql/dbschema" && psql $PG_OPTS -d "$DB_NAME" -v ON_ERROR_STOP=1 -f V001__baseline.sql >/dev/null)
echo "  Baseline: OK"

# ── 6. Load reducers ──────────────────────────────────────────────────────────────────────────────────────────────────────
echo "  Loading PL/pgSQL reducers..."
DB_NAME="$DB_NAME" DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" \
  bash "$ROOT/scripts/reload-reducers.sh" 2>&1 | tail -3
echo "  Reducers: OK"

# ── 7. Write config.yaml ────────────────────────────────────────────────
cat > "$TEST_DIR/config.yaml" <<YAML
# SetJoin test environment config — generated $(date -u +"%Y-%m-%dT%H:%M:%SZ")

hostname: localhost

listen:
  addr: ":8443"

# ── TLS (disabled for local testing — use h2c instead) ──
# To enable TLS, uncomment and run with sudo (port :443 is privileged):
# tls:
#   cert: "$TEST_DIR/certs/cert.pem"
#   key: "$TEST_DIR/certs/key.pem"

# ── Database ──
db:
  dsn: "$DB_DSN"
  direct_dsn: "$DB_DSN"
  max_conns: 10
  encryption_key: "$DB_ENCRYPTION_KEY"

# ── JWT ──
jwt:
  secret: "$JWT_SECRET"
  expiry: 1h
  issuer: mailserver

# ── Object Storage (SeaweedFS) ──
s3:
  endpoint: "127.0.0.1:8888"
  access_key: "$S3_ACCESS_KEY"
  secret_key: "$S3_SECRET_KEY"
  bucket: mailblobs
  secure: false

# ── Auth server ──
authserver:
  url: "http://127.0.0.1:8443"

internal:
  api_key: "$INTERNAL_API_KEY"

# ── WebAuthn (localhost dev) ──
webauthn:
  rp_id: localhost
  rp_name: "SetJoin Test"
  rp_origin: "http://localhost:8443"

# ── Feature toggles (minimal for onboarding) ──
kerberos:
  enabled: false
saml:
  enabled: false
oidc:
  enabled: false
oidc_provider:
  enabled: false
ad_sync:
  enabled: false
jit:
  enabled: false

# ── Threat detection (disabled for local testing) ──
threat_feed:
  enabled: false
geo_block:
  enabled: false
spray_detect:
  enabled: false
captcha:
  enabled: false
tarpit:
  enabled: false

# ── VAPID (not needed for onboarding) ──
vapid:
  private_key: ""
  subject: ""

# ── Crypto ──
crypto:
  algorithm_profile: standard

# ── Logging ──
log:
  level: debug
  format: text

# ── Network binding (disable SMTP/IMAP for onboarding test) ──
smtp:
  inbound_addr: ""
  submission_addr: ""
imap:
  addr: ""
YAML
echo "  config.yaml written ($(wc -c < "$TEST_DIR/config.yaml") bytes)"

# ── 8. Start SeaweedFS ──────────────────────────────────────────────────
echo ""
echo "  Starting SeaweedFS master (port 9333)..."
weed master \
  -mdir="$TEST_DIR/seaweedfs/master" \
  -port=9333 \
  -volume.max=0 \
  >"$TEST_DIR/seaweedfs-master.log" 2>&1 &
WEED_MASTER_PID=$!
sleep 2

if ! kill -0 $WEED_MASTER_PID 2>/dev/null; then
  echo "  ERROR: SeaweedFS master failed to start"
  cat "$TEST_DIR/seaweedfs-master.log"
  exit 1
fi
echo "  SeaweedFS master: OK (pid $WEED_MASTER_PID)"

echo "  Starting SeaweedFS filer (port 8888)..."
weed filer \
  -master=127.0.0.1:9333 \
  -port=8888 \
  -dir="$TEST_DIR/seaweedfs/filer" \
  >"$TEST_DIR/seaweedfs-filer.log" 2>&1 &
WEED_FILER_PID=$!
sleep 2

if ! kill -0 $WEED_FILER_PID 2>/dev/null; then
  echo "  ERROR: SeaweedFS filer failed to start"
  cat "$TEST_DIR/seaweedfs-filer.log"
  kill $WEED_MASTER_PID 2>/dev/null || true
  exit 1
fi
echo "  SeaweedFS filer: OK (pid $WEED_FILER_PID)"

# ── 9. Start authserver ─────────────────────────────────────────────────
echo ""
echo "  Starting authserver (127.0.0.1:8443, internal only)..."
LISTEN_ADDR="127.0.0.1:8443" \
SETJOINT_CONFIG="$TEST_DIR/config.yaml" \
  "$TEST_DIR/authserverd" \
  >"$TEST_DIR/authserver.log" 2>&1 &
AUTH_PID=$!
sleep 2

if ! kill -0 $AUTH_PID 2>/dev/null; then
  echo "  ERROR: Authserver failed to start"
  echo "  Last 20 lines of log:"
  tail -20 "$TEST_DIR/authserver.log"
  kill $WEED_FILER_PID $WEED_MASTER_PID 2>/dev/null || true
  exit 1
fi
echo "  Authserver: OK (pid $AUTH_PID)"

# ── 10. Start gateway ────────────────────────────────────────────────────
echo "  Starting gateway (h2c on :8443)..."
SETJOINT_CONFIG="$TEST_DIR/config.yaml" \
  "$TEST_DIR/mailserverd" \
  >"$TEST_DIR/gateway.log" 2>&1 &
GW_PID=$!
sleep 3

if ! kill -0 $GW_PID 2>/dev/null; then
  echo "  ERROR: Gateway failed to start"
  echo "  Last 30 lines of log:"
  tail -30 "$TEST_DIR/gateway.log"
  kill $AUTH_PID $WEED_FILER_PID $WEED_MASTER_PID 2>/dev/null || true
  exit 1
fi
echo "  Gateway: OK (pid $GW_PID)"

# ── 11. Health check ────────────────────────────────────────────────────
echo ""
echo "  Checking gateway health..."
sleep 1
if curl -s http://localhost:8443/health 2>/dev/null | grep -q .; then
  echo "  Health check: OK"
else
  echo "  WARNING: Health check failed (gateway may still be starting up)"
fi

# ── Save state for cleanup ──────────────────────────────────────────────
cat > "$TEST_DIR/.pids" <<EOF
GW_PID=$GW_PID
AUTH_PID=$AUTH_PID
WEED_FILER_PID=$WEED_FILER_PID
WEED_MASTER_PID=$WEED_MASTER_PID
EOF

# ── Done ─────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Test environment ready."
echo ""
echo "  Setup page:   http://localhost:8443/setup"
echo "  Login page:   http://localhost:8443/"
echo "  Health check: http://localhost:8443/health"
echo ""
echo "  Gateway:      http://localhost:8443"
echo "  Authserver:   http://127.0.0.1:8443 (internal only)"
echo "  SeaweedFS:    http://127.0.0.1:8888 (filer S3 API)"
echo "  PostgreSQL:   ${DB_HOST}:${DB_PORT}/${DB_NAME}"
echo ""
echo "  Logs:         $TEST_DIR/gateway.log"
echo "                $TEST_DIR/authserver.log"
echo "  Config:       $TEST_DIR/config.yaml"
echo "  PIDs:         $TEST_DIR/.pids"
echo ""
echo "  Cleanup:      bash scripts/cleanup-test-env.sh"
echo "═══════════════════════════════════════════════════════════════"

# ── Cleanup trap (unless --keep-running) ─────────────────────────────────
if ! $KEEP_RUNNING; then
  cleanup() {
    echo ""
    echo "==> Shutting down test environment..."
    for pid_var in GW_PID AUTH_PID WEED_FILER_PID WEED_MASTER_PID; do
      pid="${!pid_var:-}"
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        echo "  Killed $pid_var ($pid)"
      fi
    done
    wait 2>/dev/null || true
    echo "==> Services stopped."
    echo "    Database $DB_NAME preserved. Run cleanup script to drop."
    echo "    Data in $TEST_DIR preserved."
  }
  trap cleanup EXIT INT TERM
  echo ""
  echo "  Press Ctrl+C to stop all services (database preserved)."
  echo "  Use --keep-running to disable the trap."
  wait
else
  echo ""
  echo "  Running in background. To stop:"
  echo "    bash scripts/cleanup-test-env.sh"
fi
