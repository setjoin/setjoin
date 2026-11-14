#!/usr/bin/env bash
# gofree-record.sh: record new oracle goldens from the frozen Go coverage binary (#339).
# Runs inside the lane container (scripts/lane-container.sh) of .github/workflows/gofree-record.yml.
#   GOFREE_REC_PACKAGE  cargo package (setjoin-gateway)      GOFREE_REC_TEST  integration test target
#   GOFREE_REC_FILTER   optional libtest case filter        GOFREE_REC_EXTRA optional NAME=value lines
#   GOFREE_RECORD_GO_BINARY / GOFREE_GO_SOURCE  frozen Go binary and its 40-hex commit
#   GOFREE_REC_UPSTREAM none|authserverd; GOFREE_RECORD_AUTH_PRESET off|threat|tarpit|ca (extra_env); GOFREE_AUTHSERVERD_BINARY the covered auth binary (authserverd mode)
# Goldens are created exclusively: an existing one is compared, never overwritten.
set -uo pipefail
cd "$(dirname "$0")/.."
: "${GOFREE_REC_PACKAGE:?}" "${GOFREE_REC_TEST:?}" "${GOFREE_RECORD_GO_BINARY:?}" "${GOFREE_GO_SOURCE:?}"
: "${LANE_PG_PORT:?}" "${PGPASSWORD:?}" "${LANE_ARTIFACT_DIR:?}"
[[ "$GOFREE_REC_PACKAGE$GOFREE_REC_TEST" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "bad package or test name" >&2; exit 2; }
[[ "$GOFREE_GO_SOURCE" =~ ^[0-9a-f]{40}$ ]] || { echo "GOFREE_GO_SOURCE must be a 40-hex commit" >&2; exit 2; }
[[ -z "${GOFREE_REC_FILTER:-}" || "$GOFREE_REC_FILTER" =~ ^[A-Za-z0-9_][A-Za-z0-9_:.-]*$ ]] || { echo "bad case_filter" >&2; exit 2; }
HOST=127.0.0.1 PORT="$LANE_PG_PORT" DB="gofree_e2e_record_$(openssl rand -hex 6)" ART="$LANE_ARTIFACT_DIR"
dsn() { printf 'postgres://%s:%s@%s:%s/%s' "$1" "$2" "$HOST" "$PORT" "$DB"; }
enc() { V="$1" python3 -I -c 'import os,urllib.parse;print(urllib.parse.quote(os.environ["V"],safe=""))'; }
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
  [[ "$line" != *LEARN*=* ]] || { echo "learning mode cannot be requested: $line" >&2; exit 2; }
  [[ "$line" =~ ^GOFREE_(RECORD|ORACLE|VERIFY)_[A-Z0-9_]+=[A-Za-z0-9_.,:/-]*$ && "$line" != GOFREE_RECORD_GO_BINARY=* && "$line" != GOFREE_RECORD_UPSTREAM=* ]] \
    || { echo "extra_env line rejected: $line" >&2; exit 2; }
  export "$line"
done <<<"${GOFREE_REC_EXTRA:-}"

# Go threat-env preset for authserverd mode (default off = the historical five *_ENABLED=false).
PRESET="${GOFREE_RECORD_AUTH_PRESET:-off}"
[[ "$PRESET" =~ ^(off|threat|tarpit|ca)$ ]] || { echo "bad GOFREE_RECORD_AUTH_PRESET: $PRESET" >&2; exit 2; }
[[ "$PRESET" == off || "$UP" == authserverd ]] || { echo "GOFREE_RECORD_AUTH_PRESET=$PRESET needs go_upstream=authserverd" >&2; exit 2; }

echo "== schema into $DB"
DB_HOST="$HOST" DB_PORT="$PORT" DB_USER=postgres DB_NAME="$DB" bash scripts/load-test-schema.sh >"$ART/schema.log" 2>&1 \
  || { tail -40 "$ART/schema.log"; exit 1; }
APP_PW="$(openssl rand -hex 16)"
echo "::add-mask::$APP_PW"
# the secret travels on stdin, never in argv
printf "ALTER ROLE setjoin_app LOGIN PASSWORD '%s'\n" "$APP_PW" | psql -h "$HOST" -p "$PORT" -U postgres -d postgres -X -q -v ON_ERROR_STOP=1 || exit 1
SUPER="$(enc "$PGPASSWORD")"
export TEST_DB_DSN="$(dsn postgres "$SUPER")" REQUIRE_DB=1
export DB_DSN="$TEST_DB_DSN" DB_DIRECT_DSN="$TEST_DB_DSN" DB_APP_DSN="$(dsn setjoin_app "$APP_PW")"

# Owned-resource bookkeeping the harness appends to; the workflow prints it in the summary.
export GOFREE_RESOURCE_PREFIX="gofree-rec-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
export GOFREE_ORACLE_CONTAINER_PREFIX="$GOFREE_RESOURCE_PREFIX"
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
  printf "DELETE FROM signing_keys;\nINSERT INTO signing_keys(kid,alg,public_jwk,private_key_enc,status) VALUES('%s','ES256','%s'::text::jsonb,decode('%s','hex'),'active');\n" "$KID" "$JWKS" "$ENV_HEX" \
    | psql -h "$HOST" -p "$PORT" -U postgres -d "$DB" -X -q -v ON_ERROR_STOP=1 || exit 1
  AUTH_PORT=47335 AUTH_NAME="gofree-rec-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-auth-oracle-$(openssl rand -hex 4)"
  ENVF="$(mktemp)"; chmod 600 "$ENVF"
  {
    echo "DB_DSN=$DB_APP_DSN"; echo "DB_WORKER_DSN=$TEST_DB_DSN"; echo "DB_OWNER_DSN=$TEST_DB_DSN"; echo "DB_DIRECT_DSN=$TEST_DB_DSN"
    echo "JWT_SECRET=$JWT_SECRET_FIXTURE"; echo "DB_ENCRYPTION_KEY=$(printf '22%.0s' $(seq 32))"
    echo "INTERNAL_API_KEY=idlogin3-internal-test-key"; echo "HOSTNAME=mail.test"
    echo "LISTEN_ADDR=127.0.0.1:$AUTH_PORT"; echo "GOCOVERDIR=/coverage"; echo "NETWORK_MODE=airgap"
    case "$PRESET" in
      off|ca)  # ca = off; the oracle seeds the CA database toggles itself
        for flag in THREAT_FEED GEO_BLOCK SPRAY_DETECT CAPTCHA TARPIT; do echo "${flag}_ENABLED=false"; done ;;
      threat|tarpit)
        # Go env names: authserver/internal/config/config.go (*_ENABLED bools, CAPTCHA_SECRET, GEOIP_DB_PATH,
        # THREAT_RATE_LIMIT_PER_MIN, THREAT_CAPTCHA_*, THREAT_TARPIT_*, THREAT_SPRAY_*); GEO_BLOCK_COUNTRIES and
        # TRUSTED_PROXY_IP are read by shared code (clientip.go, threat).
        for flag in THREAT_FEED GEO_BLOCK SPRAY_DETECT CAPTCHA TARPIT; do echo "${flag}_ENABLED=true"; done
        # CAPTCHA_SECRET is a public FIXTURE string (never a real secret); the GeoIP DB is the repo's us.mmdb fixture.
        echo "CAPTCHA_SECRET=gofree-record-fixture-captcha-secret-not-a-secret"
        echo "GEO_BLOCK_COUNTRIES=US"; echo "GEOIP_DB_PATH=server-rust/tests/conformance/authzgates/us.mmdb"
        echo "TRUSTED_PROXY_IP=127.0.0.1"
        echo "THREAT_RATE_LIMIT_PER_MIN=3"; echo "THREAT_CAPTCHA_THRESHOLD=3"; echo "THREAT_CAPTCHA_WINDOW_MINS=5"
        echo "THREAT_SPRAY_MAX_USERS=3"; echo "THREAT_SPRAY_WINDOW_SECS=300"; echo "THREAT_SPRAY_LOCKOUT_MINS=5"
        if [[ "$PRESET" == tarpit ]]; then echo "CAPTCHA_ENABLED=false"; echo "THREAT_TARPIT_THRESHOLD=2"; fi ;;
    esac
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
args=(--test-threads=1 --nocapture --skip mutant --skip fault)
[[ -n "${GOFREE_REC_FILTER:-}" ]] && args=("$GOFREE_REC_FILTER" "${args[@]}")
echo "== record $GOFREE_REC_PACKAGE --test $GOFREE_REC_TEST ${GOFREE_REC_FILTER:-<all cases>}"
(cd server-rust && cargo test --locked -p "$GOFREE_REC_PACKAGE" --test "$GOFREE_REC_TEST" -- "${args[@]}") 2>&1 | tee "$ART/record.log"
cargo_rc="${PIPESTATUS[0]}" tee_rc="${PIPESTATUS[1]}"
[[ "$cargo_rc" == 0 ]] || { echo "cargo test failed ($cargo_rc)" >&2; exit "$cargo_rc"; }
[[ "$tee_rc" == 0 ]] || { echo "tee failed ($tee_rc)" >&2; exit "$tee_rc"; }
# evidence that a golden was recorded or compared (not merely that some test passed)
replayed="$(grep -cE 'GOLDEN-(REPLAY|RECORDED|WORKER)' "$ART/record.log" || true)"
created="$(git ls-files --others --exclude-standard server-rust | wc -l)"
[[ $((replayed + created)) -ge 1 ]] || { echo "no golden was recorded or compared (0 GOLDEN- lines, 0 new files)" >&2; exit 1; }
echo "evidence: $replayed golden lines, $created new files"
# evidence that at least one test actually executed (an over-narrow filter runs 0 and would pass silently)
grep -Eq 'test result: ok\. [1-9][0-9]* passed' "$ART/record.log" || { echo "no test executed: check package, test and case_filter" >&2; exit 1; }
