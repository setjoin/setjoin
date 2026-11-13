#!/usr/bin/env bash
# Run inside the test image, or pass a wrapper that executes its target binary.
set -euo pipefail

if [[ $# != 1 || ! -x "$1" ]]; then
  echo 'usage: smoke-rust-floor.sh <gateway-executable>' >&2
  exit 2
fi
gateway=$1
expected=${SMOKE_EXPECTED_VERSION:?set SMOKE_EXPECTED_VERSION to the gateway package version}
[[ "$expected" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][[:alnum:].-]+)?$ ]] || {
  echo 'invalid SMOKE_EXPECTED_VERSION' >&2
  exit 2
}
if ! version=$(timeout 30 env -i PATH="$PATH" "$gateway" --version) ||
    [[ "$version" != "setjoin-gateway $expected" ]]; then
  echo "invalid gateway version: ${version:-<no output>}" >&2
  exit 1
fi
echo "$version"

attempts=${SMOKE_ATTEMPTS:-60}
[[ "$attempts" =~ ^[1-9][0-9]*$ ]] || { echo 'invalid SMOKE_ATTEMPTS' >&2; exit 2; }
port=${SMOKE_PORT:-18090}
[[ "$port" =~ ^[0-9]+$ ]] && ((port > 0 && port < 65536)) || { echo 'invalid SMOKE_PORT' >&2; exit 2; }
log=$(mktemp "${TMPDIR:-/tmp}/setjoin-floor-smoke.XXXXXX")
pid=
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -f "$log"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
(
  exec -a "${SMOKE_PROCESS_NAME:-setjoin-floor-gateway}" env -i PATH="$PATH" \
    GATEWAY_LISTEN="127.0.0.1:$port" GATEWAY_AUTH_UPSTREAM=http://127.0.0.1:9 "$gateway"
) >"$log" 2>&1 &
pid=$!
for ((i=0; i<attempts; i++)); do
  sleep 1
  if ! kill -0 "$pid" 2>/dev/null; then
    echo 'gateway exited before health check' >&2
    cat "$log" >&2
    exit 1
  fi
  # The startup message confirms that this process bound the port, so an
  # unrelated listener cannot satisfy the probe after a bind failure.
  if grep -Fq "listening on 127.0.0.1:$port," "$log"; then
    response=$(curl --noproxy '*' --max-time 2 -fsS -w '%{http_code}' "http://127.0.0.1:$port/_gateway/healthz" 2>/dev/null || true)
    if [[ "$response" == $'ok\n200' ]] && kill -0 "$pid" 2>/dev/null; then
      echo 'gateway health: ok'
      exit 0
    fi
  fi
done
echo 'gateway health check failed' >&2
cat "$log" >&2
exit 1
