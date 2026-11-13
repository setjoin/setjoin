#!/usr/bin/env bash
# e2e/scripts/start-test-stack.sh
# Starts all services needed for E2E testing: a fresh mailserver_e2e DB, a
# SeaweedFS S3 backend, the authserver, and the gateway (mailserverd) serving
# a freshly built SPA. Set E2E_SKIP_WEBMAIL_BUILD=1 only when the caller has
# already produced and verified e2e/../build in the same run.
set -e

GATEWAY_PORT="${E2E_GATEWAY_PORT:-8080}"
AUTH_PORT="${E2E_AUTH_PORT:-8443}"
S3_PORT="${E2E_S3_PORT:-9000}"
SMTP_INBOUND_PORT="${E2E_SMTP_INBOUND_PORT:-1025}"
SMTP_SUBMISSION_PORT="${E2E_SMTP_SUBMISSION_PORT:-1587}"
IMAP_PORT="${E2E_IMAP_PORT:-1143}"
LIVEKIT_PORT="${E2E_LIVEKIT_PORT:-7880}"
LIVEKIT_TCP_PORT="${E2E_LIVEKIT_TCP_PORT:-7881}"
LIVEKIT_RTC_PORT_START="${E2E_LIVEKIT_RTC_PORT_START:-50000}"
LIVEKIT_RTC_PORT_END="${E2E_LIVEKIT_RTC_PORT_END:-50010}"
S3_MASTER_PORT="${E2E_S3_MASTER_PORT:-$((S3_PORT + 533))}"
S3_VOLUME_PORT="${E2E_S3_VOLUME_PORT:-$((S3_PORT + 540))}"
S3_FILER_PORT="${E2E_S3_FILER_PORT:-$((S3_PORT + 550))}"
DB_NAME="${E2E_DB_NAME:-mailserver_e2e}"
# Opt-in rehearsal seam (E2E_GATEWAY_FLIP_DIR): when set to a directory, the
# stack watches it for flip-request.json ({"websiteDir": "..."} ) after initial
# readiness and restarts ONLY the gateway against that web root, keeping the
# database/SeaweedFS/authserver session state alive so a retained-prior-artifact
# update rehearsal can observe a real artifact update inside one browser
# session. Ordinary e2e runs leave it unset and get the unchanged behavior.
FLIP_DIR="${E2E_GATEWAY_FLIP_DIR:-}"
ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
# ── L2-C9 target guard: pure checks (name allowlist, loopback host,
# constructed-DSN cross-check) BEFORE INSTANCE_DIR derivation below — the
# instance dir path embeds DB_NAME, so nothing filesystem- or network-visible
# may happen for an unvalidated target. Always-on, fail-closed: there is NO
# opt-in kill switch (the arch-r2 guard's opt-in being disabled on this lane
# IS the triage defect). The connected cluster-identity + disposable-marker
# gate runs further below, after pg_isready and before the destructive load,
# the loader's cluster-global role provisioning, and the ALTER ROLE password
# resets.
source "$ROOT/scripts/e2e-test-db-guard.sh"
e2e_validate_test_db || exit $?
INSTANCE_DIR="${TMPDIR:-/tmp}/setjoin-e2e-${DB_NAME}-${GATEWAY_PORT}"
CONTROL_SOCKET="${E2E_CONTROL_SOCKET:-$INSTANCE_DIR/control.sock}"
AUTH_BIN="${INSTANCE_DIR}/authserver"
GATEWAY_BIN="${INSTANCE_DIR}/gateway"
MAILCTL_BIN="${INSTANCE_DIR}/mailctl"
UPDATER_BIN="${INSTANCE_DIR}/setjoin-updater"
LIVEKIT_CONTAINER="setjoin-e2e-livekit-${GATEWAY_PORT}"
LIVEKIT_MODE="${E2E_MEET_LIVE:-0}"
GATEWAY_LIVEKIT_API_KEY=""
GATEWAY_LIVEKIT_API_SECRET=""
GATEWAY_LIVEKIT_URL=""
if [ "$LIVEKIT_MODE" = "1" ]; then
    GATEWAY_LIVEKIT_API_KEY="${LIVEKIT_API_KEY:-setjoin}"
    GATEWAY_LIVEKIT_API_SECRET="${LIVEKIT_API_SECRET:-e2e-livekit-secret-at-least-32-characters}"
    GATEWAY_LIVEKIT_URL="${LIVEKIT_URL:-ws://127.0.0.1:${LIVEKIT_PORT}}"
fi
# The instance dir sits at a predictable shared-/tmp path, so it is proven
# ours before anything (built binaries, control socket, logs) is written into
# it or executed from it: never a symlink, always a directory owned by the
# invoking account with no group/other write access, tightened to 0700. A
# pre-created or planted dir fails loud instead of being used.
#
# Creation is atomic-exclusive: mkdir(2) WITHOUT -p either creates the
# directory with the requested 0700 mode or fails with EEXIST — there is no
# check-then-create window in which an attacker can plant a path that is then
# silently adopted (mkdir -p accepts a planted dir or dir-symlink without
# enforcing the requested mode, which was the Astra wave12-14 med-shard2-005
# finding). On EEXIST the full hostility checks below re-run and the path is
# adopted only if it is provably ours; anything else fails loud.
if ! mkdir -m 0700 "$INSTANCE_DIR" 2>/dev/null; then
    if [ -L "$INSTANCE_DIR" ]; then
        echo "ERROR: $INSTANCE_DIR is a symlink — refusing (possible temp-dir plant)"; exit 1
    fi
    if [ ! -d "$INSTANCE_DIR" ]; then
        if [ ! -e "$INSTANCE_DIR" ]; then
            echo "ERROR: could not create $INSTANCE_DIR (mkdir failed) — check TMPDIR"; exit 1
        fi
        echo "ERROR: $INSTANCE_DIR exists and is not a directory — refusing (possible temp-dir plant)"; exit 1
    fi
    # find exits 0 regardless of matches, so test for matched output itself.
    if [ -z "$(find "$INSTANCE_DIR" -maxdepth 0 -type d -user "$(id -u)" ! -perm -0020 ! -perm -0002 2>/dev/null)" ]; then
        echo "ERROR: $INSTANCE_DIR exists but is not owned by uid $(id -u) or is group/world-writable — refusing; remove it and retry"; exit 1
    fi
    chmod 0700 "$INSTANCE_DIR"
fi

# ── Reap a prior run's children (zombie reaper) ──
# TaskStop / Ctrl-C can SIGKILL this wrapper before the EXIT trap fires, leaving
# an instance's gateway, authserver, and weed children alive on its ports.
# The next run's gateway then panics on bind and tests hit the stale instance.
# Reap only processes holding THIS instance's requested ports. Isolated stacks
# (for example onboarding beside the ordinary browser suite) must coexist.
# SIGKILL (not SIGTERM): these are ephemeral test processes AND the gateway's
# graceful shutdown outlives a fixed `sleep 1` (measured: it survives SIGTERM+1s
# and keeps holding :8080), which is exactly what made the next run panic on bind.
# After signalling, POLL each port until the OS actually releases it rather than
# guessing with a fixed sleep — and fail loud if a NON-e2e process squats the port.
if [ "$LIVEKIT_MODE" = "1" ]; then
    command -v docker >/dev/null 2>&1 || { echo "ERROR: E2E_MEET_LIVE=1 requires Docker"; exit 1; }
    docker stop "$LIVEKIT_CONTAINER" >/dev/null 2>&1 || true
fi

PORTS=("$GATEWAY_PORT" "$AUTH_PORT" "$S3_PORT" "$S3_MASTER_PORT" "$S3_VOLUME_PORT" "$S3_FILER_PORT" "$SMTP_INBOUND_PORT" "$SMTP_SUBMISSION_PORT" "$IMAP_PORT")
if [ "$LIVEKIT_MODE" = "1" ]; then
    PORTS+=("$LIVEKIT_PORT" "$LIVEKIT_TCP_PORT")
fi
for port in "${PORTS[@]}"; do
    for _ in $(seq 1 20); do
        holder=$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null | head -1)
        [ -z "$holder" ] && break
        # A reaped e2e binary that hasn't released the socket yet → keep waiting;
        # anything else on the port is a real conflict we must not silently clobber.
        cmd=$(ps -o command= -p "$holder" 2>/dev/null || true)
        case "$cmd" in
            "$GATEWAY_BIN"*|"$AUTH_BIN"*|*weed\ server\ -dir=/tmp/e2e-weed.*) kill -9 "$holder" 2>/dev/null || true ;;
            *) echo "ERROR: port :$port held by a non-e2e process (pid $holder: $cmd) — free it or stop that process"; exit 1 ;;
        esac
        sleep 0.5
    done
    if lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "ERROR: port :$port still in use after reaping — cannot start a clean stack"; exit 1
    fi
done

export PGHOST="${E2E_PGHOST:-127.0.0.1}"
export PGPORT="${E2E_PGPORT:-5432}"
export PGUSER="${E2E_PGUSER:-mail}"
export PGPASSWORD="${E2E_PGPASSWORD:-mail}"
# load-test-schema.sh uses its own DB_* names rather than libpq's PG* names.
export DB_HOST="$PGHOST" DB_PORT="$PGPORT" DB_USER="$PGUSER"

E2E_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Build before resetting the disposable DB. A stale build can otherwise make a
# source fix look ineffective while the stack and HTTP health checks stay green.
if [ "${E2E_SKIP_WEBMAIL_BUILD:-0}" = "1" ]; then
    if [ ! -f "$E2E_DIR/../build/index.html" ]; then
        echo "ERROR: E2E_SKIP_WEBMAIL_BUILD=1 but webmail/build/index.html is missing"
        exit 1
    fi
    echo "[e2e] Webmail build: caller-verified existing output"
else
    echo "[e2e] Building webmail..."
    (cd "$E2E_DIR/.." && npm run build)
    echo "[e2e] Webmail build: OK"
fi

# Loader/psql identity (schema owner) — loads baseline+migrations+reducers.
# PGPASSWORD (exported above) supplies the credential to child psql processes;
# the URI handed to psql ARGV carries no password (R-SECRET-IN-ARGV hardening:
# argv is world-readable via `ps` for the life of the invocation). The full
# credentialed DSN stays a shell/env variable for the servers below, where env
# is not argv.
DB_PSQL_URL="postgres://${PGUSER}@${PGHOST}:${PGPORT}/${DB_NAME}?sslmode=disable"
DB_DSN="postgres://${PGUSER}:${PGPASSWORD}@${PGHOST}:${PGPORT}/${DB_NAME}?sslmode=disable"
# RUNTIME identities (native-RLS, permanent since the 2026-07-03 flip): the
# gateway/authserver connect as the NON-OWNER app role so FORCE'd policies are
# live in every test run — the production credential shape. provision-roles.sql
# (loader step 4) creates the roles; the ALTER ROLE below gives them local dev
# passwords (production operators set real secrets per the deploy runbook).
APP_DSN="postgres://setjoin_app:e2e-app@${PGHOST}:${PGPORT}/${DB_NAME}?sslmode=disable"
WORKER_DSN="postgres://setjoin_worker:e2e-worker@${PGHOST}:${PGPORT}/${DB_NAME}?sslmode=disable"
OWNER_DSN="$DB_DSN"   # dev cluster: mail owns the tables (owner identity)
# A fixed key so authserver + gateway share encryption-at-rest within a run.
# authserver requires EXACTLY 32 chars; gateway requires >=32 — so use exactly 32.
# Scope containment (R-SECRET-SCOPE-CONTAINMENT): the disposable stack adopts
# ONLY E2E_-prefixed overrides. A production-named DB_ENCRYPTION_KEY /
# S3_ACCESS_KEY / S3_SECRET_KEY in the operator's environment must never be
# silently imported into this stack (and its bootstrap/log files).
ENC_KEY="${E2E_DB_ENCRYPTION_KEY:-e2e-encryption-key-32-characters}"
WEED_DIR="$(mktemp -d /tmp/e2e-weed.XXXXXX)"
WEED_PID=""
AUTH_PID=""
GW_PID=""
LIVEKIT_STARTED=0

# Install cleanup before starting the first child. LiveKit/Docker or binary
# build failures must not strand SeaweedFS and poison the next isolated run.
cleanup() {
    echo "[e2e] Shutting down services..."
    if [ "$LIVEKIT_STARTED" = "1" ]; then
        docker stop "$LIVEKIT_CONTAINER" >/dev/null 2>&1 || true
    fi
    for pid in "$GW_PID" "$AUTH_PID" "$WEED_PID"; do
        [ -z "$pid" ] || kill "$pid" 2>/dev/null || true
    done
    for _ in $(seq 1 20); do
        alive=0
        for pid in "$GW_PID" "$AUTH_PID" "$WEED_PID"; do
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then alive=1; fi
        done
        [ "$alive" = "0" ] && break
        sleep 0.25
    done
    for pid in "$GW_PID" "$AUTH_PID" "$WEED_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    for pid in "$GW_PID" "$AUTH_PID" "$WEED_PID"; do
        [ -z "$pid" ] || wait "$pid" 2>/dev/null || true
    done
    rm -rf "$WEED_DIR" 2>/dev/null || true
    echo "[e2e] Done."
}
trap cleanup EXIT

# ── PostgreSQL check (must be running already) ──
if ! pg_isready -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" >/dev/null 2>&1; then
    echo "ERROR: PostgreSQL not reachable at ${PGHOST}:${PGPORT}"; exit 1
fi
echo "[e2e] PostgreSQL: OK"

# ── L2-C9 connected gate: cluster identity FIRST (system_identifier re-read
# from the connected cluster and matched against the endpoint-keyed ownership
# marker, so a replaced cluster at a known endpoint is refused), then the
# additive disposable-DB marker. MUST precede the destructive load below
# (which also provisions cluster-global roles via provision-roles.sql) and
# the cluster-global ALTER ROLE password resets — the self-test source pin
# enforces this ordering.
e2e_validate_test_db_cluster || exit $?

# ── Fresh schema into the dedicated e2e DB (baseline + forward migrations + reducers) ──
DBLOAD_LOG="${INSTANCE_DIR}/dbload.log"
echo "[e2e] Loading schema into ${DB_NAME} ..."
DB_NAME="$DB_NAME" bash "$ROOT/scripts/load-test-schema.sh" >"$DBLOAD_LOG" 2>&1 \
    || { echo "[e2e] schema load FAILED"; tail -20 "$DBLOAD_LOG"; exit 1; }
echo "[e2e] Schema: OK (v$(psql -d "$DB_NAME" -tAc 'SELECT MAX(version) FROM schema_migrations' | tr -d ' '))"

# Create the current and next monthly partitions before fixtures insert any
# current-month message_tags rows. If seed data lands in the DEFAULT partition
# first, PostgreSQL correctly refuses to attach the overlapping named
# partition; the gateway still works, but /health remains WARN for the entire
# run and the E2E stack no longer matches a fresh-install startup.
psql "$DB_PSQL_URL" -X -v ON_ERROR_STOP=1 -q -c 'SELECT create_monthly_partitions(1)'
echo "[e2e] Monthly partitions: OK (current + next)"

# Runtime-role dev passwords (cluster-global roles; re-asserted every run).
# Statement goes over stdin (not -c ARGV) so the literal dev passwords are not
# world-readable in `ps` for the life of the psql invocation.
psql "$DB_PSQL_URL" -X -q <<'SQL'
ALTER ROLE setjoin_app WITH LOGIN PASSWORD 'e2e-app';
ALTER ROLE setjoin_worker WITH LOGIN PASSWORD 'e2e-worker';
SQL

# ── Seed test data (users, mailboxes, MFA-exempt flags) ──
# The onboarding lane deliberately starts from a schema with zero users. Keep
# that opt-out explicit and fail-closed; every ordinary E2E run remains seeded.
if [ "${E2E_SKIP_SEED:-0}" = "1" ]; then
    echo "[e2e] Seed: SKIPPED (explicit first-boot/onboarding mode)"
else
    echo "[e2e] Seeding test data..."
    psql -d "$DB_NAME" -v ON_ERROR_STOP=1 -f "$E2E_DIR/fixtures/seed.sql" >/dev/null
    echo "[e2e] Seed: OK"
fi
if [ "$LIVEKIT_MODE" = "1" ]; then
    psql -d "$DB_NAME" -v ON_ERROR_STOP=1 -q -c \
        "UPDATE feature_toggles SET enabled=TRUE WHERE key='feature.meet'"
    echo "[e2e] Meet feature: ON (explicit live-SFU mode)"
fi
if [ "${E2E_MAXIMAL_FEATURES:-0}" = "1" ]; then
    # Disposable-fixture mode: put every registered key into the maximally
    # enabled browser-interoperable state before either server boots. SoD stays
    # off because its dedicated reducer rejects the seeded cross-class roles.
    # Device lockdown stays off because it deliberately rejects every ordinary
    # browser without an enrolled native-shell device proof; its ON behavior is
    # covered by device-lockdown.spec.ts, while this lane exercises the other
    # features together through a usable browser session.
    registry_fixture="$ROOT/shared/toggle/testdata/registry-v226.json"
    registry_keys="$(jq -c '[.definitions[].key]' "$registry_fixture")"
    registry_digest="$(jq -r '.registryDigest' "$registry_fixture")"
    installed_digest="$(psql -d "$DB_NAME" -Atc \
        'SELECT registry_digest FROM feature_toggle_registry_state WHERE singleton')"
    if [ "$registry_digest" != "$installed_digest" ]; then
        echo "ERROR: maximal feature fixture digest does not match the installed registry" >&2
        exit 1
    fi
    psql -d "$DB_NAME" -v ON_ERROR_STOP=1 -q \
        -v registry_keys="$registry_keys" <<'SQL'
INSERT INTO feature_toggles(key, enabled, description, updated_at)
SELECT key, true, '', now()
  FROM jsonb_array_elements_text(:'registry_keys'::jsonb) AS keys(key)
ON CONFLICT (key) DO UPDATE SET enabled=EXCLUDED.enabled, updated_at=now();

UPDATE feature_toggles
   SET enabled = (key NOT IN ('dengbao.sod_mode', 'feature.device_lockdown')), updated_at = now()
 WHERE feature_registry_classify(key) = 'known';

DO $$
DECLARE
  v_known bigint;
  v_enabled bigint;
  v_unknown bigint;
  v_sod boolean;
  v_lockdown boolean;
BEGIN
  SELECT count(*), count(*) FILTER (WHERE enabled)
    INTO v_known, v_enabled
    FROM feature_toggles
   WHERE feature_registry_classify(key) = 'known';
  SELECT count(*) INTO v_unknown FROM feature_toggles
   WHERE feature_registry_classify(key) = 'unknown';
  SELECT enabled INTO STRICT v_sod FROM feature_toggles
   WHERE key = 'dengbao.sod_mode';
  SELECT enabled INTO STRICT v_lockdown FROM feature_toggles
   WHERE key = 'feature.device_lockdown';
  IF v_unknown <> 0 OR v_sod OR v_lockdown OR v_enabled <> v_known - 2 THEN
    RAISE EXCEPTION 'maximal browser feature fixture is incomplete: known=%, enabled=%, unknown=%, sod=%, lockdown=%',
      v_known, v_enabled, v_unknown, v_sod, v_lockdown;
  END IF;
END;
$$;
SQL
    feature_state="$(psql -d "$DB_NAME" -Atc \
        "SELECT count(*) FILTER (WHERE enabled)::text || '/' || count(*)::text FROM feature_toggles WHERE feature_registry_classify(key)='known'")"
    echo "[e2e] Features: ${feature_state} ON (maximal browser-interoperable state; SoD and device lockdown use dedicated lanes)"
fi
# The baseline keeps the default origin readable, while an isolated-port run
# must issue links/cookies for the browser-visible gateway selected above.
psql -d "$DB_NAME" -v ON_ERROR_STOP=1 -q -c \
    "UPDATE system_config SET value = to_jsonb('http://localhost:${GATEWAY_PORT}'::text) WHERE key = 'authserver.public_url'"

# ── Start SeaweedFS S3 (drop-in for MinIO at :9000) ──
# S3 identity config so signed requests are accepted: without it SeaweedFS runs
# anonymous and rejects every SigV4-signed PUT/GET the gateway sends (it sets
# S3_ACCESS_KEY/S3_SECRET_KEY below), 500ing real blob uploads. The keys MUST match
# the gateway's creds (any / anysecret).
S3_CONFIG="${WEED_DIR}/s3.json"
cat > "$S3_CONFIG" <<'JSON'
{ "identities": [ {
    "name": "e2e",
    "credentials": [ { "accessKey": "any", "secretKey": "anysecret" } ],
    "actions": [ "Admin", "Read", "Write", "List", "Tagging" ]
} ] }
JSON
echo "[e2e] Starting SeaweedFS S3 on :${S3_PORT}..."
weed server -dir="$WEED_DIR" -ip=127.0.0.1 -s3 -s3.port="$S3_PORT" -s3.config="$S3_CONFIG" \
    -s3.port.iceberg=0 \
    -master.port="$S3_MASTER_PORT" -volume.port="$S3_VOLUME_PORT" -filer.port="$S3_FILER_PORT" -metricsPort=0 \
    >"${INSTANCE_DIR}/weed.log" 2>&1 &
WEED_PID=$!
for i in $(seq 1 30); do
    curl -s "http://127.0.0.1:${S3_PORT}" >/dev/null 2>&1 && break
    sleep 1
done
# Pre-create the blob bucket (weed shell; harmless if the gateway also ensures it).
echo "s3.bucket.create -name mailblobs" | weed shell -master="127.0.0.1:${S3_MASTER_PORT}" >/dev/null 2>&1 || true
echo "[e2e] SeaweedFS PID: $WEED_PID"

if [ "$LIVEKIT_MODE" = "1" ]; then
    echo "[e2e] Starting LiveKit SFU on :${LIVEKIT_PORT}..."
    docker run --rm -d --name "$LIVEKIT_CONTAINER" \
        -p "127.0.0.1:${LIVEKIT_PORT}:7880" \
        -p "127.0.0.1:${LIVEKIT_TCP_PORT}:7881" \
        -p "127.0.0.1:${LIVEKIT_RTC_PORT_START}-${LIVEKIT_RTC_PORT_END}:50000-50010/udp" \
        -v "$E2E_DIR/fixtures/livekit.e2e.yaml:/livekit.yaml:ro" \
        livekit/livekit-server:v1.13.5 --config /livekit.yaml >/dev/null
    LIVEKIT_STARTED=1
    for _ in $(seq 1 60); do
        curl -fsS "http://127.0.0.1:${LIVEKIT_PORT}" >/dev/null 2>&1 && break
        docker inspect "$LIVEKIT_CONTAINER" >/dev/null 2>&1 || {
            echo "ERROR: LiveKit container exited during startup"; exit 1;
        }
        sleep 1
    done
    curl -fsS "http://127.0.0.1:${LIVEKIT_PORT}" >/dev/null 2>&1 || {
        echo "ERROR: LiveKit did not become ready"; exit 1;
    }
    echo "[e2e] LiveKit: OK"
fi

# ── Build binaries (correct module paths) ──
echo "[e2e] Building authserver..."
(cd "$ROOT/authserver" && go build -o "$AUTH_BIN" ./cmd/authserverd)
echo "[e2e] Building gateway (mailserverd)..."
(cd "$ROOT/mailserver" && go build -o "$GATEWAY_BIN" ./cmd/mailserverd)
echo "[e2e] Building mailctl (CA quickstart spec shells out to it)..."
(cd "$ROOT/mailctl" && go build -o "$MAILCTL_BIN" ./)
echo "[e2e] mailctl: $MAILCTL_BIN (point specs at it via MAILCTL_BIN)"
if [ "${E2E_MANAGED_OFFICE:-0}" = "1" ]; then
    command -v docker >/dev/null 2>&1 || { echo "ERROR: E2E_MANAGED_OFFICE=1 requires Docker"; exit 1; }
    echo "[e2e] Building updater (managed Office install spec shells out to it)..."
    (cd "$ROOT/mailserver" && go build -o "$UPDATER_BIN" ./cmd/setjoin-updater)
    echo "[e2e] updater: $UPDATER_BIN (point specs at it via SETJOIN_UPDATER_BIN)"
fi

# ── Start authserver ──
echo "[e2e] Starting authserver on :${AUTH_PORT}..."
DB_DSN="$APP_DSN" \
JWT_SECRET="test-e2e-secret-key-at-least-32-chars!!" \
DB_ENCRYPTION_KEY="$ENC_KEY" \
AUDIT_HMAC_KEY="e2e-audit-hmac-key-32-bytes-fixed" \
HOSTNAME="localhost" \
LISTEN_ADDR=":${AUTH_PORT}" \
THREAT_RATE_LIMIT_PER_MIN="${THREAT_RATE_LIMIT_PER_MIN:-100000}" \
THREAT_CAPTCHA_THRESHOLD="${THREAT_CAPTCHA_THRESHOLD:-100000}" \
THREAT_TARPIT_THRESHOLD="${THREAT_TARPIT_THRESHOLD:-100000}" \
"$AUTH_BIN" &
AUTH_PID=$!
echo "[e2e] Authserver PID: $AUTH_PID"

# ── Start gateway ──
# One launch site so the initial boot and a rehearsal flip share the exact same
# environment (identical DSNs, keys, and ports; only the web root may change).
launch_gateway() {
    S3_ENDPOINT="127.0.0.1:${S3_PORT}" \
    S3_ACCESS_KEY="${E2E_S3_ACCESS_KEY:-any}" \
    S3_SECRET_KEY="${E2E_S3_SECRET_KEY:-anysecret}" \
    S3_BUCKET="mailblobs" \
    S3_SECURE="false" \
    DB_DSN="$APP_DSN" \
    DB_DIRECT_DSN="$APP_DSN" \
    DB_WORKER_DSN="$WORKER_DSN" \
    DB_OWNER_DSN="$OWNER_DSN" \
    SETJOIN_CONTROL_SOCKET="$CONTROL_SOCKET" \
    JWT_SECRET="test-e2e-secret-key-at-least-32-chars!!" \
    DB_ENCRYPTION_KEY="$ENC_KEY" \
    AUDIT_HMAC_KEY="e2e-audit-hmac-key-32-bytes-fixed" \
    HOSTNAME="localhost" \
    LISTEN_ADDR=":${GATEWAY_PORT}" \
    SMTP_INBOUND_ADDR="127.0.0.1:${SMTP_INBOUND_PORT}" \
    SMTP_SUBMISSION_ADDR="127.0.0.1:${SMTP_SUBMISSION_PORT}" \
    IMAP_ADDR="127.0.0.1:${IMAP_PORT}" \
    AUTHSERVER_URL="http://127.0.0.1:${AUTH_PORT}" \
    AUTH_RATE_LIMIT="${AUTH_RATE_LIMIT:-100000}" \
    ADMIN_RATE_LIMIT="${ADMIN_RATE_LIMIT:-100000}" \
    BOOKING_READ_RATE_LIMIT="${BOOKING_READ_RATE_LIMIT:-100000}" \
    BOOKING_WRITE_RATE_LIMIT="${BOOKING_WRITE_RATE_LIMIT:-100000}" \
    THREAT_RATE_LIMIT_PER_MIN="${THREAT_RATE_LIMIT_PER_MIN:-100000}" \
    THREAT_CAPTCHA_THRESHOLD="${THREAT_CAPTCHA_THRESHOLD:-100000}" \
    THREAT_TARPIT_THRESHOLD="${THREAT_TARPIT_THRESHOLD:-100000}" \
    CONFIG_PATH="${TMPDIR:-/tmp}/e2e-config-$$.env" \
    WEBSITE_DIR="$GATEWAY_WEBSITE_DIR" \
    LIVEKIT_API_KEY="$GATEWAY_LIVEKIT_API_KEY" \
    LIVEKIT_API_SECRET="$GATEWAY_LIVEKIT_API_SECRET" \
    LIVEKIT_URL="$GATEWAY_LIVEKIT_URL" \
    "$GATEWAY_BIN" &
    GW_PID=$!
    echo "[e2e] Gateway PID: $GW_PID (web root: $GATEWAY_WEBSITE_DIR)"
}

echo "[e2e] Starting gateway on :${GATEWAY_PORT}..."
GATEWAY_WEBSITE_DIR="${WEBSITE_DIR:-$E2E_DIR/../build}"
launch_gateway

# ── Wait for services ──
echo "[e2e] Waiting for services to be ready..."
ready=0
for i in $(seq 1 60); do
    if curl -fsS "http://localhost:${AUTH_PORT}/health" >/dev/null 2>&1 && \
       curl -fsS "http://localhost:${GATEWAY_PORT}/health" >/dev/null 2>&1; then
        echo "[e2e] All services ready after ${i}s"
        ready=1
        break
    fi
    if ! kill -0 "$AUTH_PID" 2>/dev/null || ! kill -0 "$GW_PID" 2>/dev/null; then
        echo "ERROR: an E2E service exited before readiness" >&2
        exit 1
    fi
    sleep 1
done
if [ "$ready" -ne 1 ]; then
    echo "ERROR: E2E services did not become ready within 60 seconds" >&2
    exit 1
fi

echo "[e2e] Services running. Press Ctrl+C to stop."
watch_gateway_flips() {
    while true; do
        request="$FLIP_DIR/flip-request.json"
        if [ -f "$request" ]; then
            target="$(node -e '
                const value = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"));
                if (typeof value.websiteDir !== "string" || !value.websiteDir) process.exit(2);
                process.stdout.write(value.websiteDir);
            ' "$request" 2>/dev/null || true)"
            if [ -z "$target" ] || [ "${target#/}" = "$target" ]; then
                echo '{"error":"websiteDir must be a non-empty absolute path"}' >"$FLIP_DIR/flip-failed.json"
                echo "ERROR: invalid flip request (websiteDir must be absolute)" >&2
                exit 1
            fi
            if [ ! -f "$target/index.html" ] || [ ! -f "$target/_app/version.json" ]; then
                echo '{"error":"flip target lacks index.html or _app/version.json"}' >"$FLIP_DIR/flip-failed.json"
                echo "ERROR: flip target $target is not a complete web root" >&2
                exit 1
            fi
            echo "[e2e] Flipping gateway web root: $GATEWAY_WEBSITE_DIR -> $target"
            kill "$GW_PID" 2>/dev/null || true
            released=0
            for _ in $(seq 1 20); do
                if ! kill -0 "$GW_PID" 2>/dev/null && ! lsof -tiTCP:"$GATEWAY_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
                    released=1
                    break
                fi
                sleep 0.5
            done
            if [ "$released" -ne 1 ]; then
                kill -9 "$GW_PID" 2>/dev/null || true
                wait "$GW_PID" 2>/dev/null || true
            fi
            GATEWAY_WEBSITE_DIR="$target"
            launch_gateway
            ready=0
            for _ in $(seq 1 60); do
                if curl -fsS "http://localhost:${GATEWAY_PORT}/health" >/dev/null 2>&1; then
                    ready=1
                    break
                fi
                if ! kill -0 "$GW_PID" 2>/dev/null; then
                    echo '{"error":"gateway exited after flip"}' >"$FLIP_DIR/flip-failed.json"
                    echo "ERROR: gateway exited after flip" >&2
                    exit 1
                fi
                sleep 1
            done
            if [ "$ready" -ne 1 ]; then
                echo '{"error":"gateway not ready after flip"}' >"$FLIP_DIR/flip-failed.json"
                echo "ERROR: gateway did not become ready after flip" >&2
                exit 1
            fi
            rm -f "$request"
            node -e '
                process.stdout.write(JSON.stringify({
                    websiteDir: process.argv[1],
                    gatewayPid: Number(process.argv[2]),
                }, null, 2) + "\n");
            ' "$target" "$GW_PID" >"$FLIP_DIR/flip-done.json"
            echo "[e2e] Gateway flip complete: serving $target"
        fi
        sleep 1
    done
}
if [ -n "$FLIP_DIR" ]; then
    mkdir -p "$FLIP_DIR"
    echo "[e2e] Gateway flip control armed at $FLIP_DIR"
    watch_gateway_flips
else
    while true; do sleep 5; done
fi
