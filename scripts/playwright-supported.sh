#!/usr/bin/env bash
# Run a host-side Playwright command against a version-matched browser server
# on a supported Ubuntu runtime when the Linux host itself is unsupported.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEBMAIL="$ROOT/mailserver/webmail"
RUNTIME="${PLAYWRIGHT_BROWSER_RUNTIME:-auto}"
CONNECT_ENDPOINT="${PLAYWRIGHT_CONNECT_WS_ENDPOINT:-}"
FLAVOR="${PLAYWRIGHT_IMAGE_FLAVOR:-noble}"
PORT="${PLAYWRIGHT_SERVER_PORT:-$((30000 + ($$ % 20000)))}"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/playwright-supported.sh --check
  bash scripts/playwright-supported.sh -- <host Playwright command> [args...]

PLAYWRIGHT_BROWSER_RUNTIME:
  auto       Use a supported host runtime or an explicit loopback endpoint.
  host       Always use the host browser runtime.
  connect    Use PLAYWRIGHT_CONNECT_WS_ENDPOINT on a supported browser host.
  container  Diagnostic only: use the version-matched official image.

PLAYWRIGHT_IMAGE_FLAVOR must be noble or jammy.
PLAYWRIGHT_SERVER_PORT must be a free loopback TCP port from 1024 through 65535.
The wrapper accepts only a loopback WebSocket endpoint. Its diagnostic container
also binds loopback and is removed on every exit. Test code, psql helpers, and
artifacts stay on the host. Containers share the host kernel; they are not a
release-gate workaround for a browser crash caused by an unsupported kernel.
EOF
}

case "$RUNTIME" in
  auto|host|connect|container) ;;
  *) echo "playwright-supported: runtime must be auto, host, connect, or container" >&2; exit 2 ;;
esac
case "$FLAVOR" in
  noble|jammy) ;;
  *) echo "playwright-supported: image flavor must be noble or jammy" >&2; exit 2 ;;
esac
case "$PORT" in
  ''|*[!0-9]*) echo "playwright-supported: server port must be a decimal integer" >&2; exit 2 ;;
esac
if [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
  echo "playwright-supported: server port must be between 1024 and 65535" >&2
  exit 2
fi

VERSION="$(cd "$WEBMAIL" && node -e '
  const value = require("./node_modules/@playwright/test/package.json").version;
  if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(value)) process.exit(2);
  process.stdout.write(value);
')"
IMAGE="mcr.microsoft.com/playwright:v${VERSION}-${FLAVOR}"

host_is_supported() {
  [ "$(uname -s)" != "Linux" ] && return 0
  [ -r /etc/os-release ] || return 1
  # Playwright's official Linux images currently publish Ubuntu 22.04 and 24.04.
  # Other Linux hosts fail closed in auto mode because a container shares the
  # host kernel; use a loopback tunnel to a separate supported browser host.
  (
    # shellcheck source=/etc/os-release
    . /etc/os-release
    [ "${ID:-}" = "ubuntu" ] &&
      { [ "${VERSION_ID:-}" = "22.04" ] || [ "${VERSION_ID:-}" = "24.04" ]; }
  )
}

if [ "$RUNTIME" = "auto" ]; then
  if [ -n "$CONNECT_ENDPOINT" ]; then
    RUNTIME="connect"
  elif host_is_supported; then
    RUNTIME="host"
  else
    RUNTIME="unsupported"
  fi
fi

ENGINE=""
if [ "$RUNTIME" = "container" ]; then
  if command -v docker >/dev/null 2>&1; then
    ENGINE="docker"
  elif command -v podman >/dev/null 2>&1; then
    ENGINE="podman"
  else
    echo "playwright-supported: container runtime requires docker or podman" >&2
    exit 1
  fi
fi

if [ "$RUNTIME" = "connect" ]; then
  if [ -z "$CONNECT_ENDPOINT" ]; then
    echo "playwright-supported: connect mode requires PLAYWRIGHT_CONNECT_WS_ENDPOINT" >&2
    exit 2
  fi
  PLAYWRIGHT_ENDPOINT_VALUE="$CONNECT_ENDPOINT" node -e '
    const value = process.env.PLAYWRIGHT_ENDPOINT_VALUE;
    let url;
    try { url = new URL(value); } catch { process.exit(2); }
    if (!["ws:", "wss:"].includes(url.protocol) ||
        !["127.0.0.1", "localhost", "::1"].includes(url.hostname) ||
        !url.port || url.username || url.password || url.hash) process.exit(2);
  ' || {
    echo "playwright-supported: endpoint must be loopback ws(s) with an explicit port and no credentials/fragment" >&2
    exit 2
  }
fi

if [ "${1:-}" = "--check" ]; then
  printf 'runtime=%s\nversion=%s\nimage=%s\nengine=%s\n' \
    "$RUNTIME" "$VERSION" "$IMAGE" "${ENGINE:-none}"
  exit 0
fi
if [ "${1:-}" != "--" ]; then
  usage >&2
  exit 2
fi
shift
if [ "$#" -eq 0 ]; then
  echo "playwright-supported: missing host command after --" >&2
  exit 2
fi

if [ "$RUNTIME" = "host" ]; then
  exec "$@"
fi
if [ "$RUNTIME" = "connect" ]; then
  PW_TEST_CONNECT_WS_ENDPOINT="$CONNECT_ENDPOINT" exec "$@"
fi
if [ "$RUNTIME" = "unsupported" ]; then
  echo "playwright-supported: this Linux host is outside the supported browser matrix" >&2
  echo "run the tests on Ubuntu 22.04/24.04, macOS, or a supported browser host" >&2
  echo "reachable through a loopback SSH tunnel via PLAYWRIGHT_CONNECT_WS_ENDPOINT" >&2
  exit 1
fi

if [ "$ENGINE" = "docker" ]; then
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    docker pull "$IMAGE"
  fi
else
  if ! podman image exists "$IMAGE"; then
    podman pull "$IMAGE"
  fi
fi

NAME="setjoin-playwright-${$}"
cleanup() {
  "$ENGINE" rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

"$ENGINE" run --detach --rm --init --ipc=host --network=host \
  --name "$NAME" --user pwuser \
  --volume "$WEBMAIL:/work/webmail:ro" \
  "$IMAGE" node /work/webmail/node_modules/playwright/cli.js \
  run-server --port "$PORT" --host 127.0.0.1 \
  >/dev/null

READY=0
for _ in $(seq 1 120); do
  if PW_SERVER_PORT="$PORT" node -e '
    const net = require("node:net");
    const socket = net.connect(Number(process.env.PW_SERVER_PORT), "127.0.0.1");
    socket.setTimeout(250);
    socket.once("connect", () => { socket.destroy(); process.exit(0); });
    socket.once("timeout", () => { socket.destroy(); process.exit(1); });
    socket.once("error", () => process.exit(1));
  ' >/dev/null 2>&1; then
    READY=1
    break
  fi
  if ! "$ENGINE" inspect "$NAME" >/dev/null 2>&1; then
    echo "playwright-supported: browser server exited before readiness" >&2
    "$ENGINE" logs "$NAME" >&2 || true
    exit 1
  fi
  sleep 0.25
done
if [ "$READY" -ne 1 ]; then
  echo "playwright-supported: browser server was not ready within 30 seconds" >&2
  "$ENGINE" logs "$NAME" >&2 || true
  exit 1
fi

echo "playwright-supported: browser=$IMAGE endpoint=loopback runtime=$ENGINE"
PW_TEST_CONNECT_WS_ENDPOINT="ws://127.0.0.1:${PORT}/" "$@"
