#!/usr/bin/env bash
# gofree-record.sh: record new oracle goldens from the frozen Go coverage binary (#339).
# Runs inside the lane container (scripts/lane-container.sh) of .github/workflows/gofree-record.yml.
#   GOFREE_REC_PACKAGE  cargo package (setjoin-gateway)      GOFREE_REC_TEST  integration test target
#   GOFREE_REC_FILTER   optional libtest case filter        GOFREE_REC_EXTRA optional NAME=value lines
#   GOFREE_RECORD_GO_BINARY / GOFREE_GO_SOURCE  frozen Go binary and its 40-hex commit
#   GOFREE_REC_UPSTREAM none|authserverd; GOFREE_AUTHSERVERD_BINARY the covered auth binary (authserverd mode)
# Goldens are created exclusively: an existing one is compared, never overwritten.
set -uo pipefail
cd "$(dirname "$0")/.."
: "${GOFREE_REC_PACKAGE:?}" "${GOFREE_REC_TEST:?}" "${GOFREE_RECORD_GO_BINARY:?}" "${GOFREE_GO_SOURCE:?}"
: "${LANE_PG_PORT:?}" "${PGPASSWORD:?}" "${LANE_ARTIFACT_DIR:?}"
[[ "$GOFREE_REC_PACKAGE$GOFREE_REC_TEST" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "bad package or test name" >&2; exit 2; }
[[ "$GOFREE_GO_SOURCE" =~ ^[0-9a-f]{40}$ ]] || { echo "GOFREE_GO_SOURCE must be a 40-hex commit" >&2; exit 2; }
[[ -z "${GOFREE_REC_FILTER:-}" || "$GOFREE_REC_FILTER" =~ ^[A-Za-z0-9_:.-]+$ ]] || { echo "bad case_filter" >&2; exit 2; }
HOST=127.0.0.1 PORT="$LANE_PG_PORT" DB="gofree_e2e_record_$(openssl rand -hex 6)" ART="$LANE_ARTIFACT_DIR"
dsn() { printf 'postgres://%s:%s@%s:%s/%s' "$1" "$2" "$HOST" "$PORT" "$DB"; }
enc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }
UP="${GOFREE_REC_UPSTREAM:-none}" AUTH_NAME="" ENVF=""
[[ "$UP" == none || "$UP" == authserverd ]] || { echo "bad go_upstream" >&2; exit 2; }
cleanup() {
  if [[ -n "$AUTH_NAME" ]]; then
    docker stop --time 10 "$AUTH_NAME" >/dev/null 2>&1; docker rm -f "$AUTH_NAME" >/dev/null 2>&1
    echo "Stopped owned auth oracle container $AUTH_NAME" >>"${GOFREE_RESOURCE_LEDGER:-/dev/null}"
  fi
  [[ -z "$ENVF" ]] || rm -f "$ENVF"
  psql -h "$HOST" -p "$PORT" -U postgres -d postgres -X -q -c "DROP DATABASE IF EXISTS \"$DB\" WITH (FORCE)" >/dev/null 2>&1
}
trap cleanup EXIT

# Extra record variables (family-specific selectors such as GOFREE_RECORD_DRAIN=all), allowlisted.
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  [[ "$line" =~ ^GOFREE_(RECORD|ORACLE|VERIFY)_[A-Z0-9_]+=[A-Za-z0-9_.,:/-]*$ && "$line" != GOFREE_RECORD_GO_BINARY=* ]] \
    || { echo "extra_env line rejected: $line" >&2; exit 2; }
  export "$line"
done <<<"${GOFREE_REC_EXTRA:-}"

echo "== schema into $DB"
DB_HOST="$HOST" DB_PORT="$PORT" DB_USER=postgres DB_NAME="$DB" bash scripts/load-test-schema.sh >"$ART/schema.log" 2>&1 \
  || { tail -40 "$ART/schema.log"; exit 1; }
APP_PW="$(openssl rand -hex 16)"
psql -h "$HOST" -p "$PORT" -U postgres -d postgres -X -q -v ON_ERROR_STOP=1 -c "ALTER ROLE setjoin_app LOGIN PASSWORD '$APP_PW'" || exit 1
SUPER="$(enc "$PGPASSWORD")"
export TEST_DB_DSN="$(dsn postgres "$SUPER")" REQUIRE_DB=1
export DB_DSN="$TEST_DB_DSN" DB_DIRECT_DSN="$TEST_DB_DSN" DB_APP_DSN="$(dsn setjoin_app "$APP_PW")"

# Owned-resource bookkeeping the harness appends to; the workflow prints it in the summary.
export GOFREE_RESOURCE_PREFIX="gofree-rec-${GITHUB_RUN_ID:-local}"
export GOFREE_RESOURCE_LEDGER="$ART/resource-ledger.txt"
: >"$GOFREE_RESOURCE_LEDGER"
export GOFREE_GO_COVERAGE_DIR="$ART/go-cover"
mkdir -p "$GOFREE_GO_COVERAGE_DIR"
if [[ "$UP" == authserverd ]]; then
  # identity-login/README.md: Go must load the same synthetic signing-key row as native replay before it
  # starts (the fixture row, secret and DB_ENCRYPTION_KEY below are public test material from keys.json).
  KEYS=server-rust/tests/conformance/identity-login/keys.json
  : "${GOFREE_AUTHSERVERD_BINARY:?}" "${GOFREE_AUTH_SRC:?}"
  read -r KID ENV_HEX JWKS JWT_SECRET_FIXTURE < <(python3 -I - "$KEYS" <<'PY'
import json, sys
f = json.load(open(sys.argv[1]))
print(f["kid"], f["envelope"], json.dumps(f["jwks"]["keys"][0]).replace(" ", ""), f["secret"])
PY
)
  psql -h "$HOST" -p "$PORT" -U postgres -d "$DB" -X -q -v ON_ERROR_STOP=1 \
    -c "DELETE FROM signing_keys" \
    -c "INSERT INTO signing_keys(kid,alg,public_jwk,private_key_enc,status) VALUES('$KID','ES256','$JWKS'::text::jsonb,decode('$ENV_HEX','hex'),'active')" || exit 1
  AUTH_PORT=47335 AUTH_NAME="gofree-rec-${GITHUB_RUN_ID:-local}-auth-oracle-$(openssl rand -hex 4)"
  ENVF="$(mktemp)"; chmod 600 "$ENVF"
  {
    echo "DB_DSN=$DB_APP_DSN"; echo "DB_WORKER_DSN=$TEST_DB_DSN"; echo "DB_OWNER_DSN=$TEST_DB_DSN"; echo "DB_DIRECT_DSN=$TEST_DB_DSN"
    echo "JWT_SECRET=$JWT_SECRET_FIXTURE"; echo "DB_ENCRYPTION_KEY=$(printf '22%.0s' $(seq 32))"
    echo "INTERNAL_API_KEY=idlogin3-internal-test-key"; echo "HOSTNAME=mail.test"
    echo "LISTEN_ADDR=127.0.0.1:$AUTH_PORT"; echo "GOCOVERDIR=/coverage"; echo "NETWORK_MODE=airgap"
    for flag in THREAT_FEED GEO_BLOCK SPRAY_DETECT CAPTCHA TARPIT; do echo "${flag}_ENABLED=false"; done
  } >"$ENVF"
  echo "Planned auth oracle container $AUTH_NAME, host network, port $AUTH_PORT; fixture DB $DB only; binary $GOFREE_AUTHSERVERD_BINARY" >>"$GOFREE_RESOURCE_LEDGER"
  docker run -d --name "$AUTH_NAME" --label "org.setjoin.task=gofree-record-auth" --network host --env-file "$ENVF" \
    -v "$GOFREE_AUTH_SRC:/src:ro" -w /src -v "$(dirname "$GOFREE_AUTHSERVERD_BINARY"):/evidence:ro" -v "$GOFREE_GO_COVERAGE_DIR:/coverage" \
    setjoin-ci-linux-tc:local-amd64 "/evidence/$(basename "$GOFREE_AUTHSERVERD_BINARY")" >/dev/null || exit 1
  rm -f "$ENVF"; ENVF=""
  ready=0
  for _ in $(seq 1 60); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$AUTH_PORT/health" || true)"
    [[ "$code" =~ ^[1-5][0-9][0-9]$ ]] && { ready=1; break; }
    docker inspect -f '{{.State.Running}}' "$AUTH_NAME" 2>/dev/null | grep -q true || break
    sleep 1
  done
  [[ "$ready" == 1 ]] || { docker logs "$AUTH_NAME" 2>&1 | tail -30 | sed -E 's/(postgres:\/\/[^:]+:)[^@]*@/\1***@/g'; echo "auth oracle did not become ready" >&2; exit 1; }
  export GOFREE_RECORD_UPSTREAM="http://127.0.0.1:$AUTH_PORT"
fi
# Mutants and fault cuts never record (the harness rejects them with a recorder set).
args=(--test-threads=1 --skip mutant --skip fault)
[[ -n "${GOFREE_REC_FILTER:-}" ]] && args=("$GOFREE_REC_FILTER" "${args[@]}")
echo "== record $GOFREE_REC_PACKAGE --test $GOFREE_REC_TEST ${GOFREE_REC_FILTER:-<all cases>}"
(cd server-rust && cargo test --locked -p "$GOFREE_REC_PACKAGE" --test "$GOFREE_REC_TEST" -- "${args[@]}") 2>&1 | tee "$ART/record.log"
exit "${PIPESTATUS[0]}"
