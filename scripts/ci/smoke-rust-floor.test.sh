#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/setjoin-floor-smoke-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
export SMOKE_EXPECTED_VERSION=0.0.0

# A binary that claims success but emits the wrong version must be rejected.
cat > "$tmp/gateway" <<'EOF'
#!/usr/bin/env bash
echo 'incorrect version'
EOF
chmod +x "$tmp/gateway"
if bash "$root/scripts/ci/smoke-rust-floor.sh" "$tmp/gateway" >"$tmp/log" 2>&1; then
  echo 'incorrect version passed smoke' >&2
  exit 1
fi
grep -q 'invalid gateway version' "$tmp/log"

# A plausible version from a different build must not pass either.
cat > "$tmp/gateway" <<'EOF'
#!/usr/bin/env bash
echo 'setjoin-server 99.99.99'
EOF
if SMOKE_EXPECTED_VERSION=0.0.0 bash "$root/scripts/ci/smoke-rust-floor.sh" "$tmp/gateway" >"$tmp/log" 2>&1; then
  echo 'mismatched version passed smoke' >&2
  exit 1
fi
grep -q 'invalid gateway version' "$tmp/log"

# A legacy binary banner must also be rejected after the rename to setjoin-server.
cat > "$tmp/gateway" <<'EOF'
#!/usr/bin/env bash
echo 'setjoin-gateway 0.0.0'
EOF
if SMOKE_EXPECTED_VERSION=0.0.0 bash "$root/scripts/ci/smoke-rust-floor.sh" "$tmp/gateway" >"$tmp/log" 2>&1; then
  echo 'legacy setjoin-gateway banner passed smoke' >&2
  exit 1
fi
grep -q 'invalid gateway version' "$tmp/log"

# A gateway that prints a valid version but immediately exits is unhealthy.
cat > "$tmp/gateway" <<'EOF'
#!/usr/bin/env bash
if [[ ${1:-} == --version ]]; then echo 'setjoin-server 0.0.0'; exit 0; fi
exit 1
EOF
if SMOKE_ATTEMPTS=1 bash "$root/scripts/ci/smoke-rust-floor.sh" "$tmp/gateway" >"$tmp/log" 2>&1; then
  echo 'exited gateway passed smoke' >&2
  exit 1
fi
grep -q 'gateway exited before health check' "$tmp/log"

# A process that stays up without serving health is also rejected (and must receive GATEWAY_RUST_AUTH_UPSTREAM).
cat > "$tmp/gateway" <<'EOF'
#!/usr/bin/env bash
if [[ ${1:-} == --version ]]; then echo 'setjoin-server 0.0.0'; exit 0; fi
[[ "${GATEWAY_RUST_AUTH_UPSTREAM:-}" == "http://127.0.0.1:9" ]] || { echo "missing GATEWAY_RUST_AUTH_UPSTREAM" >&2; exit 1; }
echo "setjoin-server: listening on ${GATEWAY_LISTEN}, Go upstream unset" >&2
exec sleep 30
EOF
if SMOKE_PORT=38721 SMOKE_ATTEMPTS=1 bash "$root/scripts/ci/smoke-rust-floor.sh" "$tmp/gateway" >"$tmp/log" 2>&1; then
  echo 'unresponsive gateway passed smoke' >&2
  exit 1
fi
grep -q 'gateway health check failed' "$tmp/log"

echo 'rust floor smoke failure cases passed'
