#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# scripts/e6-gateway-fixture.sh — CQ E6 gateway + corpus fixture (server lane)
#
# Disposable, run-scoped loopback Setjoin gateway stack for the E6 sustained
# 20-pair run (profile docs/verification/connectivity-e6-profile.json,
# e6-electron-macos-arm64-v1): gateway + authserver + SeaweedFS on 127.0.0.1
# ephemeral ports, and a run-scoped PostgreSQL 17 Docker container (ER5
# verification RUNBOOK recipe: generated per-run SCRAM secret, loopback-only
# port mapping, removed on exit). Seeded with the frozen corpus block:
# 2 accounts x 2,000 messages x 40 attachments, cold per pair.
#
# REUSE, not reinvention: the stack itself is started by the repo's existing
# E2E loopback stack manager (mailserver/webmail/e2e/scripts/
# start-test-stack.sh) via its documented E2E_* env surface — schema load,
# cluster guard (scripts/e2e-test-db-guard.sh), runtime roles, SeaweedFS,
# authserver, gateway and rate-limit posture all come from that script. This
# wrapper only provisions the run-scoped Postgres container, applies the E6
# corpus seed (scripts/e6-fixture/seed-corpus.sql), mints the per-member
# credentials, and owns the cleanup trap: everything is run-scoped, nothing
# survives exit.
#
# Subcommands:
#   up          boot the stack + seed the corpus, print the env block, and
#               hold the foreground; Ctrl-C / TERM tears everything down
#   reset-pair  restore the cold corpus state deterministically (run between
#               pairs, or between member runs for strict cold-server state)
#   login       re-mint per-member bearer tokens (after a reset invalidates
#               prior sessions) and print the refreshed env lines
#   status      stack health + corpus row counts (cold-state verification)
#   print-env   re-print the sourceable env block from the current run
#   down        stop the stack, remove the container and all run state
#
# Output contract (consumed by the client-pair launcher / workload driver):
# the `up`, `login` and `print-env` subcommands print a sourceable env block
# (also persisted as $STATE_DIR/e6-fixture.env, 0600) with E6_TARGET_URL,
# the gateway PID (E6_DRIVER_GATEWAY_PID), the pinned
# E6_DRIVER_CLASS_ROUTES, per-member E6_DRIVER_CLASS_BODIES_<MEMBER>,
# per-member credentials (E6_MEMBER_<MEMBER>_EMAIL/_PASSWORD/_BEARER) and
# the derivation of E6_DRIVER_AUTH_BEARER per member run — plus, per member,
# E6_MEMBER_<MEMBER>_SESSION_COOKIE: the exact Set-Cookie the login response
# carried (drift-guarded), which the client-pair launcher plants into the
# Electron window session so the pair members boot logged in. Docs/
# verification/connectivity-e6-class-routes.json owns the canonical routes;
# the fixture emits them verbatim from that file.
#
# Requirements: Docker, psql, jq, curl (with --aws-sigv4), lsof, openssl.
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STACK_SCRIPT="$ROOT/mailserver/webmail/e2e/scripts/start-test-stack.sh"
SEED_SQL="$ROOT/scripts/e6-fixture/seed-corpus.sql"
RESET_SQL="$ROOT/scripts/e6-fixture/reset-pair.sql"
ROUTES_JSON="$ROOT/docs/verification/connectivity-e6-class-routes.json"

DB_NAME="mailserver_e6_e2e" # satisfies BOTH disposable guards: e2e-test-db-guard (_e2e/_test suffix) and e2e/fixtures/seed.sql (*_e2e)
PG_IMAGE="postgres:17"
PG_CONTAINER_PREFIX="setjoin-e6-pg"
STATE_ROOT="${TMPDIR:-/tmp}"
STATE_LINK="$STATE_ROOT/setjoin-e6-fixture-current"

MEMBER_A_EMAIL="e6-a@e6.test"
MEMBER_B_EMAIL="e6-b@e6.test"
MEMBER_PASSWORD="TestPass123!" # e2e seed convention (disposable DB; hash reused from e2e/fixtures/seed.sql)

log() { printf '[e6-fixture] %s\n' "$*"; }
die() {
  printf '[e6-fixture] ERROR: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

pick_free_port() {
  local port
  for _ in $(seq 1 100); do
    port=$(((RANDOM % 20000) + 20000))
    if ! lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      printf '%s' "$port"
      return 0
    fi
  done
  die "could not find a free loopback port"
}

# Pick a base port whose start-test-stack derived offsets (+533/+540/+550)
# are also free.
pick_free_s3_base() {
  local base port delta
  for _ in $(seq 1 100); do
    base=$(((RANDOM % 18000) + 20000))
    local free=1
    for delta in 0 533 540 550; do
      port=$((base + delta))
      if lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
        free=0
        break
      fi
    done
    if [ "$free" = "1" ]; then
      printf '%s' "$base"
      return 0
    fi
  done
  die "could not find a free SeaweedFS port quad"
}

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

# ── state helpers ─────────────────────────────────────────────────────────
state_dir() {
  [ -L "$STATE_LINK" ] || die "no current fixture run (start one with: $0 up)"
  local dir
  dir="$(readlink "$STATE_LINK")"
  [ -d "$dir" ] || die "current fixture state dir $dir is missing (run: $0 down; then $0 up)"
  printf '%s' "$dir"
}

load_state() {
  STATE_DIR="$(state_dir)"
  # shellcheck source=/dev/null
  source "$STATE_DIR/run.env"
  : "${PG_CONTAINER:?}" "${PG_PORT:?}" "${GATEWAY_PORT:?}" "${DB_PASSWORD:?}"
}

container_running() {
  [ -n "$(docker ps -q --filter "name=^/${PG_CONTAINER}$" 2>/dev/null)" ]
}

# ── cleanup: nothing survives exit ────────────────────────────────────────
cleanup_run() {
  local keep_state="${1:-0}"
  log "Tearing down (stack child, SeaweedFS leftovers, Postgres container)..."
  if [ -n "${STACK_CHILD:-}" ] && kill -0 "$STACK_CHILD" 2>/dev/null; then
    kill -TERM "$STACK_CHILD" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$STACK_CHILD" 2>/dev/null || break
      sleep 0.25
    done
    kill -9 "$STACK_CHILD" 2>/dev/null || true
  fi
  # The stack child traps EXIT but not TERM, so reap its children by the
  # exact identities start-test-stack.sh itself owns (same discipline as
  # its own port reaper): the INSTANCE_DIR binaries + the e2e weed dir.
  local instance_dir="${INSTANCE_DIR:-}"
  if [ -z "$instance_dir" ] && [ -n "${GATEWAY_PORT:-}" ]; then
    instance_dir="${TMPDIR:-/tmp}/setjoin-e2e-${DB_NAME}-${GATEWAY_PORT}"
  fi
  if [ -n "$instance_dir" ]; then
    pkill -TERM -f "^$instance_dir/gateway" 2>/dev/null || true
    pkill -TERM -f "^$instance_dir/authserver" 2>/dev/null || true
    sleep 1
    pkill -KILL -f "^$instance_dir/gateway" 2>/dev/null || true
    pkill -KILL -f "^$instance_dir/authserver" 2>/dev/null || true
  fi
  # SeaweedFS backstop, scoped to THIS run's weed identity: the weed is
  # started by the stack manager as `weed server -dir=/tmp/e2e-weed.XXXXXX
  # ... -s3.port=$S3_PORT` with the run-unique port quad, so matching the
  # e2e-weed namespace AND this run's -s3.port kills only our weed — never
  # another concurrent E2E/E6 run's weed in the shared /tmp/e2e-weed.*
  # namespace. (S3_PORT empty = stack never reached weed start; skip.)
  if [ -n "${S3_PORT:-}" ]; then
    local weed_pat='weed server -dir=/tmp/e2e-weed\..*-s3\.port='"${S3_PORT}"' '
    pkill -TERM -f "$weed_pat" 2>/dev/null || true
    sleep 1
    pkill -KILL -f "$weed_pat" 2>/dev/null || true
  fi
  if [ -n "${PG_CONTAINER:-}" ] && container_running; then
    docker stop "$PG_CONTAINER" >/dev/null 2>&1 || true
    docker rm "$PG_CONTAINER" >/dev/null 2>&1 || true
  fi
  rm -f "$STATE_LINK" 2>/dev/null || true
  if [ -n "$instance_dir" ] && [ -d "$instance_dir" ]; then
    rm -rf "$instance_dir"
  fi
  if [ "$keep_state" = "0" ] && [ -n "${STATE_DIR:-}" ] && [ -d "$STATE_DIR" ]; then
    rm -rf "$STATE_DIR"
  fi
  log "Teardown complete: no fixture processes, containers or state remain."
}

# ── psql helper against the run-scoped container ──────────────────────────
psql_db() {
  PGPASSWORD="$DB_PASSWORD" psql -X -h 127.0.0.1 -p "$PG_PORT" -U mail -d "$DB_NAME" "$@"
}

# ── up ────────────────────────────────────────────────────────────────────
cmd_up() {
  for c in docker psql jq curl lsof openssl; do need_cmd "$c"; done
  [ -f "$STACK_SCRIPT" ] || die "stack manager missing: $STACK_SCRIPT"
  [ -f "$ROUTES_JSON" ] || die "canonical routes payload missing: $ROUTES_JSON"
  curl --help all 2>/dev/null | grep -q aws-sigv4 || die "curl lacks --aws-sigv4 support"

  if [ -L "$STATE_LINK" ]; then
    local prev
    prev="$(readlink "$STATE_LINK" 2>/dev/null || true)"
    if [ -n "$prev" ] && [ -f "$prev/run.env" ]; then
      # Adopt only a live prior run of THIS fixture (namespace setjoin-e6-*).
      (
        # shellcheck disable=SC1091  # runtime-generated run.env path
        source "$prev/run.env"
        if container_running; then
          die "fixture already running from $prev — stop it first: $0 down"
        fi
      ) || exit 1
    fi
    rm -f "$STATE_LINK"
  fi

  local run_id
  run_id="e6-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  RUN_ID="$run_id"
  STATE_DIR="$STATE_ROOT/setjoin-e6-fixture-$run_id"
  PG_CONTAINER="${PG_CONTAINER_PREFIX}-${run_id}"
  PG_PORT="$(pick_free_port)"
  GATEWAY_PORT="$(pick_free_port)"
  AUTH_PORT="$(pick_free_port)"
  S3_PORT="$(pick_free_s3_base)"
  SMTP_IN_PORT="$(pick_free_port)"
  SMTP_SUB_PORT="$(pick_free_port)"
  IMAP_PORT="$(pick_free_port)"
  DB_PASSWORD="$(openssl rand -hex 16)" # run-scoped SCRAM secret (RUNBOOK recipe)
  STACK_CHILD=""
  BOOT_T0=$(date +%s)

  mkdir -m 0700 "$STATE_DIR"
  ln -sfn "$STATE_DIR" "$STATE_LINK"
  INSTANCE_DIR="${TMPDIR:-/tmp}/setjoin-e2e-${DB_NAME}-${GATEWAY_PORT}"

  cat >"$STATE_DIR/run.env" <<EOF
RUN_ID='$run_id'
DB_NAME='$DB_NAME'
PG_CONTAINER='$PG_CONTAINER'
PG_PORT='$PG_PORT'
GATEWAY_PORT='$GATEWAY_PORT'
AUTH_PORT='$AUTH_PORT'
S3_PORT='$S3_PORT'
DB_PASSWORD='$DB_PASSWORD'
INSTANCE_DIR='$INSTANCE_DIR'
EOF
  chmod 0600 "$STATE_DIR/run.env"
  # shellcheck disable=SC2154
  trap 'rc=$?; cleanup_run 0; exit $rc' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  log "Run $run_id (state: $STATE_DIR)"
  log "Postgres ${PG_IMAGE} on 127.0.0.1:${PG_PORT} (run-scoped SCRAM secret; RUNBOOK recipe)"
  docker image inspect "$PG_IMAGE" >/dev/null 2>&1 || docker pull "$PG_IMAGE" >/dev/null
  docker run -d --name "$PG_CONTAINER" \
    -e POSTGRES_USER=mail -e POSTGRES_PASSWORD="$DB_PASSWORD" -e POSTGRES_DB="$DB_NAME" \
    -p "127.0.0.1:${PG_PORT}:5432" "$PG_IMAGE" >/dev/null

  local ready=0
  for _ in $(seq 1 60); do
    if docker exec "$PG_CONTAINER" pg_isready -U mail -d "$DB_NAME" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  [ "$ready" = "1" ] || {
    docker logs --tail 40 "$PG_CONTAINER" >&2 || true
    die "Postgres container did not become ready"
  }
  log "Postgres: OK"
  # RUNBOOK recipe (ER5 verification receipts): the baseline requires the
  # pgTAP extension; install it in the container before any schema load.
  log "Installing postgresql-17-pgtap in the container (RUNBOOK recipe)..."
  docker exec "$PG_CONTAINER" sh -c \
    'apt-get update -qq >/dev/null && apt-get install -y -qq postgresql-17-pgtap >/dev/null' ||
    die "pgtap extension install failed (RUNBOOK recipe step)"
  # POSTGRES_DB pre-creates the database WITHOUT the disposable marker the
  # connected guard requires; drop it so load-test-schema.sh's guarded
  # DROP/CREATE path recreates and stamps it.
  docker exec "$PG_CONTAINER" psql -U mail -d postgres -c "DROP DATABASE IF EXISTS $DB_NAME" >/dev/null

  # L2-C9 cluster bootstrap: this fixture's fresh cluster is registered by
  # the guard's EXPLICIT bootstrap (direct invocation is the sanctioned
  # path); every later reset re-validates against it.
  (cd "$ROOT" &&
    E2E_PGHOST=127.0.0.1 E2E_PGPORT="$PG_PORT" E2E_DB_NAME="$DB_NAME" \
      PGUSER=mail PGPASSWORD="$DB_PASSWORD" \
      bash scripts/e2e-test-db-guard.sh --bootstrap) ||
    die "cluster guard bootstrap failed"

  # Stack: the repo's own E2E loopback manager, unmodified, driven by its
  # E2E_* env surface. It loads the schema + runtime roles + e2e seed and
  # starts SeaweedFS, authserver and gateway on the fixture's ports.
  local skip_build=0
  [ -f "$ROOT/mailserver/webmail/build/index.html" ] && skip_build=1

  # The stack manager hardcodes LISTEN_ADDR=":${AUTH_PORT}" for the
  # authserver; the authserver's AUTHSERVERD-005 cleartext posture refuses
  # wildcard binds at startup and prescribes the remediation itself:
  # "bind 127.0.0.1 ... for a gateway-proxied deployment". The launcher
  # file is outside this unit's ownership, so the fixture installs a
  # scoped go shim for the launcher's build of the authserver ONLY: the
  # built binary is wrapped to rewrite a wildcard LISTEN_ADDR to an
  # explicit 127.0.0.1 bind — strictly narrower than the launcher asked
  # for, exactly the posture's intent, and loopback-only is this fixture's
  # own requirement anyway.
  mkdir -p "$STATE_DIR/shim"
  chmod 0700 "$STATE_DIR/shim"
  cat >"$STATE_DIR/shim/go" <<'SHIMEOF'
#!/usr/bin/env bash
# e6-fixture go shim (installed by scripts/e6-gateway-fixture.sh).
# Intercepts ONLY the authserver build of the E2E stack launcher (matched by
# its exact -o output path) and wraps the binary with the loopback
# LISTEN_ADDR rewrite. Every other invocation delegates untouched.
set -euo pipefail
real="${E6_GO_REAL:?}"
out="${E6_SHIM_AUTHSERVER_OUT:?}"
is_auth=0
prev=""
for a in "$@"; do
    [ "$prev" = "-o" ] && [ "$a" = "$out" ] && is_auth=1
    prev="$a"
done
if [ "$is_auth" != "1" ]; then
    exec "$real" "$@"
fi
"$real" "$@"
mv "$out" "$out.real"
cat > "$out" <<'WRAPEOF'
#!/usr/bin/env bash
# Generated by the e6-fixture go shim: rewrite the launcher's wildcard
# LISTEN_ADDR to the loopback bind the authserver posture prescribes.
case "${LISTEN_ADDR:-}" in
    :*) export LISTEN_ADDR="127.0.0.1${LISTEN_ADDR}" ;;
esac
exec "$(dirname "$0")/authserver.real" "$@"
WRAPEOF
chmod +x "$out"
SHIMEOF
  chmod +x "$STATE_DIR/shim/go"

  log "Starting loopback stack via start-test-stack.sh (webmail build: $([ "$skip_build" = 1 ] && echo reuse-existing || echo build-once))..."
  (cd "$ROOT" &&
    E2E_DB_NAME="$DB_NAME" E2E_PGHOST=127.0.0.1 E2E_PGPORT="$PG_PORT" \
      E2E_PGUSER=mail E2E_PGPASSWORD="$DB_PASSWORD" \
      E2E_GATEWAY_PORT="$GATEWAY_PORT" E2E_AUTH_PORT="$AUTH_PORT" \
      E2E_S3_PORT="$S3_PORT" \
      E2E_S3_MASTER_PORT=$((S3_PORT + 533)) \
      E2E_S3_VOLUME_PORT=$((S3_PORT + 540)) \
      E2E_S3_FILER_PORT=$((S3_PORT + 550)) \
      E2E_SMTP_INBOUND_PORT="$SMTP_IN_PORT" \
      E2E_SMTP_SUBMISSION_PORT="$SMTP_SUB_PORT" \
      E2E_IMAP_PORT="$IMAP_PORT" \
      E2E_SKIP_WEBMAIL_BUILD=$skip_build \
      E6_GO_REAL="$(command -v go)" \
      E6_SHIM_AUTHSERVER_OUT="$INSTANCE_DIR/authserver" \
      PATH="$STATE_DIR/shim:$PATH" \
      bash "$STACK_SCRIPT" >"$STATE_DIR/stack.log" 2>&1) &
  STACK_CHILD=$!

  ready=0
  for _ in $(seq 1 120); do
    if curl -fsS "http://127.0.0.1:${GATEWAY_PORT}/health" >/dev/null 2>&1 &&
      curl -fsS "http://127.0.0.1:${AUTH_PORT}/health" >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! kill -0 "$STACK_CHILD" 2>/dev/null; then
      echo "--- stack.log tail ---" >&2
      tail -40 "$STATE_DIR/stack.log" >&2
      die "stack exited before readiness"
    fi
    sleep 1
  done
  [ "$ready" = "1" ] || {
    echo "--- stack.log tail ---" >&2
    tail -40 "$STATE_DIR/stack.log" >&2
    die "stack did not become ready within 120s"
  }
  log "Stack ready: gateway :$GATEWAY_PORT, authserver :$AUTH_PORT, SeaweedFS :$S3_PORT ($(($(date +%s) - BOOT_T0))s)"

  # E6 corpus seed + attachment blob uploads.
  local seed_t0
  seed_t0=$(date +%s)
  psql_db -At -c "WITH att AS (SELECT a.acc, g.n, repeat(md5('e6-pair-runbook-v1:att:' || a.acc || ':' || g.n), 512) AS content FROM (VALUES ('a'), ('b')) AS a(acc) CROSS JOIN generate_series(1, 40) AS g(n)) SELECT encode(sha256(convert_to(content, 'UTF8')), 'hex') || chr(9) || replace(encode(convert_to(content, 'UTF8'), 'base64'), E'\n', '') FROM att" \
    >"$STATE_DIR/blob-manifest.tsv" || die "blob manifest export failed"
  psql_db -v ON_ERROR_STOP=1 -q -f "$SEED_SQL" || die "corpus seed failed"
  local uploaded=0
  while IFS=$'\t' read -r ref b64; do
    [ -n "$ref" ] || continue
    printf '%s' "$b64" | openssl base64 -d -A >"$STATE_DIR/.blob.tmp"
    curl -fsS --aws-sigv4 "aws:amz:us-east-1:s3" --user "any:anysecret" \
      -T "$STATE_DIR/.blob.tmp" "http://127.0.0.1:${S3_PORT}/mailblobs/${ref}" >/dev/null ||
      die "S3 upload failed for mailblobs/$ref"
    uploaded=$((uploaded + 1))
  done <"$STATE_DIR/blob-manifest.tsv"
  rm -f "$STATE_DIR/.blob.tmp"
  log "Corpus seeded + $uploaded attachment blobs uploaded ($(($(date +%s) - seed_t0))s)"

  verify_corpus

  mint_and_write_env
  print_env_block

  log "Fixture ready in $(($(date +%s) - BOOT_T0))s. Waiting (Ctrl-C tears down)."
  wait "$STACK_CHILD"
}

verify_corpus() {
  local msgs drafts atts blobs offline_toggle connectivity_toggle
  msgs="$(psql_db -tAc "SELECT count(*) FROM messages WHERE mailbox_id IN (5210000001,5210000002) AND id < 5400000000")"
  drafts="$(psql_db -tAc "SELECT count(*) FROM messages WHERE id IN (5400000001,5400000002) AND is_draft")"
  atts="$(psql_db -tAc "SELECT count(*) FROM message_attachments WHERE message_id BETWEEN 5000000000 AND 5499999999")"
  blobs="$(psql_db -tAc "SELECT count(*) FROM blobs WHERE minio_ref LIKE 'mailblobs/%'")"
  offline_toggle="$(psql_db -tAc "SELECT enabled FROM feature_toggles WHERE key='feature.offline_mail'")"
  connectivity_toggle="$(psql_db -tAc "SELECT enabled FROM feature_toggles WHERE key='feature.connectivity_aware_sync'")"
  [ "$msgs" = "4000" ] || die "corpus verification failed: messages=$msgs want 4000"
  [ "$drafts" = "2" ] || die "corpus verification failed: drafts=$drafts want 2"
  [ "$atts" = "80" ] || die "corpus verification failed: attachments=$atts want 80"
  [ "$blobs" = "80" ] || die "corpus verification failed: blobs=$blobs want 80"
  # Both rollout gates must read ON: offline_effective_policy and the Go
  # substrate surfaces gate on the PAIR (see seed-corpus.sql).
  [ "$offline_toggle" = "t" ] || die "candidate substrate verification failed: feature.offline_mail=${offline_toggle:-missing} want t (seed/reset projection)"
  [ "$connectivity_toggle" = "t" ] || die "candidate substrate verification failed: feature.connectivity_aware_sync=${connectivity_toggle:-missing} want t (seed/reset projection)"
  log "Corpus verified: 2 accounts x 2000 messages ($msgs rows), 2 queued-send drafts, $atts attachments, $blobs blobs; candidate substrate ON (feature.offline_mail=t + feature.connectivity_aware_sync=t, fixture-scoped)"
}

# ── credentials + env block ───────────────────────────────────────────────
# Member login, returning (on stdout) the ACCESS TOKEN. The authserver sets
# the SAME token both as the JSON body's access_token (the API bearer) and as
# the HttpOnly `access_token` cookie the webmail SPA rides (the gateway auth
# chain accepts both). This function is the drift guard for that invariant:
# it captures the Set-Cookie header, refuses a login that sets no cookie, and
# refuses any cookie/body divergence — the client-pair launcher plants the
# cookie into the Electron window session from exactly this value, so a
# silent upstream divergence would sign the window in as nobody (the
# white-screen failure class) instead of failing the fixture loudly.
member_bearer() {
  local email="$1"
  local hdr body body_token cookie_token
  hdr="$STATE_DIR/.login-hdr.$$"
  body="$STATE_DIR/.login-body.$$"
  curl -fsS -D "$hdr" -o "$body" -X POST "http://127.0.0.1:${GATEWAY_PORT}/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"${email}\",\"password\":\"${MEMBER_PASSWORD}\"}"
  body_token="$(jq -r '.access_token // empty' "$body")"
  cookie_token="$(tr -d '\r' <"$hdr" | sed -n 's/^[Ss]et-[Cc]ookie: access_token=\([^;]*\);.*/\1/p' | tail -1)"
  rm -f "$hdr" "$body"
  [ -n "$body_token" ] || die "login for $email carried no access_token body"
  [ -n "$cookie_token" ] || die "login for $email set no access_token cookie (session bootstrap needs it)"
  [ "$body_token" = "$cookie_token" ] ||
    die "login for $email: access_token cookie/body divergence (bearer '$body_token…' vs cookie '$cookie_token…') — refusing to mint a half-usable credential"
  printf '%s' "$body_token"
}

mint_and_write_env() {
  BEARER_A="$(member_bearer "$MEMBER_A_EMAIL")"
  BEARER_B="$(member_bearer "$MEMBER_B_EMAIL")"
  [ -n "$BEARER_A" ] && [ -n "$BEARER_B" ] || {
    tail -40 "$STATE_DIR/stack.log" >&2
    die "member login failed"
  }

  DRAFTS_TAG_A="$(psql_db -tAc "SELECT id FROM tags WHERE mailbox_id=5210000001 AND name='Drafts'")"
  DRAFTS_TAG_B="$(psql_db -tAc "SELECT id FROM tags WHERE mailbox_id=5210000002 AND name='Drafts'")"
  [ -n "$DRAFTS_TAG_A" ] && [ -n "$DRAFTS_TAG_B" ] || die "drafts tags missing (seed incomplete)"

  GATEWAY_PID="$(sed -n 's/.*Gateway PID: \([0-9][0-9]*\).*/\1/p' "$STATE_DIR/stack.log" | tail -1)"
  [ -n "$GATEWAY_PID" ] || die "could not read gateway PID from stack log"

  E6_TARGET_URL="http://127.0.0.1:${GATEWAY_PORT}"
  CLASS_ROUTES="$(jq -c '.classes | with_entries(.value = {method: .value.method, path: .value.path})' "$ROUTES_JSON")"

  BODIES_A="$(jq -cn --arg acct 5210000001 --arg drafts "$DRAFTS_TAG_A" '
        {
          "queued-send":     {using:["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail","urn:ietf:params:jmap:submission"],
                              methodCalls:[["EmailSubmission/set",{accountId:$acct,create:{e6q:{emailId:"5400000001",onSuccessUpdateEmail:{}}}},"0"]]},
          "draft-commit":    {using:["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
                              methodCalls:[["Email/set",{accountId:$acct,create:{e6d:{mailboxIds:($drafts | {(.): true}),from:[{email:"e6-a@e6.test"}],to:[{email:"e6-a@e6.test"}],subject:"E6 draft-commit probe",bodyValues:{text:{value:"E6 draft-commit probe body (fixed corpus text)."}}}}},"0"]]},
          "auth-revocation": {device_id:5220000001},
          "delivery-receipt":{messageId:"5000000001",consent:true}
        }')"
  BODIES_B="$(jq -cn --arg acct 5210000002 --arg drafts "$DRAFTS_TAG_B" '
        {
          "queued-send":     {using:["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail","urn:ietf:params:jmap:submission"],
                              methodCalls:[["EmailSubmission/set",{accountId:$acct,create:{e6q:{emailId:"5400000002",onSuccessUpdateEmail:{}}}},"0"]]},
          "draft-commit":    {using:["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],
                              methodCalls:[["Email/set",{accountId:$acct,create:{e6d:{mailboxIds:($drafts | {(.): true}),from:[{email:"e6-b@e6.test"}],to:[{email:"e6-b@e6.test"}],subject:"E6 draft-commit probe",bodyValues:{text:{value:"E6 draft-commit probe body (fixed corpus text)."}}}}},"0"]]},
          "auth-revocation": {device_id:5220000002},
          "delivery-receipt":{messageId:"5100000001",consent:true}
        }')"

  cat >"$STATE_DIR/e6-fixture.env" <<EOF
# CQ E6 fixture env — run $RUN_ID (sourceable; 0600). Base URL + per-member
# credential sets for the client-pair launcher / workload driver.
export E6_FIXTURE_BASE_URL='$E6_TARGET_URL'
export E6_TARGET_URL='$E6_TARGET_URL'
export E6_DRIVER_GATEWAY_PID='$GATEWAY_PID'
export E6_DRIVER_CLASS_ROUTES='$CLASS_ROUTES'
export E6_DRIVER_CLASS_BODIES_MEMBER_A='$BODIES_A'
export E6_DRIVER_CLASS_BODIES_MEMBER_B='$BODIES_B'
export E6_MEMBER_A_EMAIL='$MEMBER_A_EMAIL'
export E6_MEMBER_A_PASSWORD='$MEMBER_PASSWORD'
export E6_MEMBER_A_BEARER='$BEARER_A'
export E6_MEMBER_A_SESSION_COOKIE='access_token=$BEARER_A'
export E6_MEMBER_B_EMAIL='$MEMBER_B_EMAIL'
export E6_MEMBER_B_PASSWORD='$MEMBER_PASSWORD'
export E6_MEMBER_B_BEARER='$BEARER_B'
export E6_MEMBER_B_SESSION_COOKIE='access_token=$BEARER_B'
# Per member run the client-pair launcher's --driver-wrapper performs the
# derivation automatically (re-minting the member bearer via 'login' first):
#   export E6_DRIVER_AUTH_BEARER="\$E6_MEMBER_<MEMBER>_BEARER"
#   export E6_DRIVER_CLASS_BODIES="\$E6_DRIVER_CLASS_BODIES_MEMBER_<MEMBER>"
# The _SESSION_COOKIE value is EXACTLY the Set-Cookie the login response
# carried (drift-guarded in member_bearer): the launcher passes it through
# SETJOIN_E6_SESSION_COOKIE so the Electron window boots with the member's
# logged-in gateway session (the HttpOnly cookie the SPA rides).
EOF
  chmod 0600 "$STATE_DIR/e6-fixture.env"

  jq -n --arg runId "$RUN_ID" --arg baseUrl "$E6_TARGET_URL" --arg gatewayPid "$GATEWAY_PID" \
    --arg routes "$CLASS_ROUTES" --arg bearerA "$BEARER_A" --arg bearerB "$BEARER_B" \
    '{kind:"e6-fixture-run", runId:$runId, baseUrl:$baseUrl, gatewayPid:($gatewayPid|tonumber),
          classRoutes:($routes|fromjson),
          members:{a:{email:"e6-a@e6.test",bearerSet:($bearerA|length>0)},b:{email:"e6-b@e6.test",bearerSet:($bearerB|length>0)}}}' \
    >"$STATE_DIR/e6-fixture.json"
  chmod 0600 "$STATE_DIR/e6-fixture.json"
}

print_env_block() {
  cat "$STATE_DIR/e6-fixture.env"
}

# ── reset-pair / status / login / print-env / down ───────────────────────
cmd_reset_pair() {
  load_state
  container_running || die "fixture Postgres container is not running — run: $0 up"
  local t0
  t0=$(date +%s)
  psql_db -v ON_ERROR_STOP=1 -q -1 -f "$RESET_SQL" || die "reset failed"
  psql_db -v ON_ERROR_STOP=1 -q -f "$SEED_SQL" || die "re-seed failed"
  verify_corpus
  log "reset-pair complete in $(($(date +%s) - t0))s (cold state restored; prior bearer tokens revoked — re-login via: $0 login)"
}

cmd_login() {
  load_state
  container_running || die "fixture Postgres container is not running — run: $0 up"
  mint_and_write_env
  grep -E "BEARER=" "$STATE_DIR/e6-fixture.env"
  log "refreshed tokens written to $STATE_DIR/e6-fixture.env"
}

cmd_status() {
  load_state
  if container_running; then
    log "Postgres container: RUNNING ($PG_CONTAINER, 127.0.0.1:$PG_PORT)"
  else
    log "Postgres container: STOPPED"
  fi
  if curl -fsS "http://127.0.0.1:${GATEWAY_PORT}/health" >/dev/null 2>&1; then
    log "Gateway health: OK (http://127.0.0.1:$GATEWAY_PORT)"
  else
    log "Gateway health: UNREACHABLE"
  fi
  psql_db -tAc "
        SELECT 'messages=' || count(*) FROM messages WHERE mailbox_id IN (5210000001,5210000002)
        UNION ALL
        SELECT 'attachments=' || count(*) FROM message_attachments WHERE message_id BETWEEN 5000000000 AND 5499999999
        UNION ALL
        SELECT 'read_receipts=' || count(*) FROM read_receipts
        UNION ALL
        SELECT 'outbound_queue=' || count(*) FROM outbound_queue
        UNION ALL
        SELECT 'sessions=' || count(*) FROM sessions WHERE user_id IN (5200000001,5200000002);" |
    sed 's/^/[e6-fixture] /'
}

cmd_print_env() {
  load_state
  print_env_block
}

cmd_down() {
  if [ -L "$STATE_LINK" ]; then
    load_state
  fi
  cleanup_run 0
}

case "${1:-}" in
  up)
    shift
    cmd_up "$@"
    ;;
  reset-pair)
    shift
    cmd_reset_pair "$@"
    ;;
  login)
    shift
    cmd_login "$@"
    ;;
  status)
    shift
    cmd_status "$@"
    ;;
  print-env)
    shift
    cmd_print_env "$@"
    ;;
  down)
    shift
    cmd_down "$@"
    ;;
  -h | --help | help | "") usage ;;
  *) die "unknown subcommand: $1 (see $0 --help)" ;;
esac
