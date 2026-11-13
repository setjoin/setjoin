#!/usr/bin/env bash
# Installer proof for the Rust front door (#264, ARCH-027 deployment shape).
#
#   bash test-install-front-door.sh [built-setjoin-gateway]
#
# Proves, against the REAL compiled unit catalog, the REAL renderers and the
# REAL install.sh/upgrade.sh text:
#   1. unit names are unchanged: every pre-#264 unit keeps its name and
#      destination; the front door is one added unit (setjoin-gateway) plus
#      its socket;
#   2. the gateway is rendered, enabled and started by default (front door ON)
#      through the same render_runtime_units + setjoinctl path as every unit,
#      after the Go gateway it proxies to;
#   3. the ARCH-027 shape: the gateway serves plaintext HTTP on a
#      systemd-owned loopback socket for the existing TLS terminator, holds no
#      capabilities, and forwards to Go's internal plain listener
#      (HTTP_MODE=proxy, Go trusting exactly the gateway's address);
#   4. *.prev rollback covers the Go and Rust binaries (test-upgrade-rollback.sh)
#      and the immutable layout adopts and quarantines the gateway too.
# With a built gateway it also runs the rendered configuration: the gateway
# answers its health probe and forwards to a stand-in Go upstream with the
# client identity headers it owns. With root and systemd (REQUIRE_SYSTEMD=1
# makes it mandatory) the rendered socket+service run under a disposable
# gofree-t13-* name with only the account and paths substituted.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
INSTALL="$ROOT/mailserver/deploy/scripts/install.sh"
UPGRADE="$ROOT/mailserver/deploy/scripts/upgrade.sh"
GATEWAY_BIN="${1:-${GATEWAY_BIN:-}}"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/gofree-t13-front-door.XXXXXX")"
pids=()
cleanup() {
  local pid
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
  echo "install front door: $*" >&2
  if [ -n "${name:-}" ]; then journalctl -u "$name.service" -u "$name.socket" -n 20 --no-pager >&2 || true; fi
  exit 1
}
require_text() { # require_text <desc> <pattern> <file>
  grep -Fq -- "$2" "$3" || fail "missing ($1): $2 in $3"
}

# ── 1. Unchanged unit names ──────────────────────────────────────────────────
# shellcheck source=../generated/unit-catalog.sh
source "$ROOT/mailserver/deploy/generated/unit-catalog.sh"
for unit in setjoin-valkey setjoin-sfu setjoin-egress setjoin-funasr setjoin-asr-bot setjoin-auth setjoin setjoin-updater; do
  [ "${SETJOIN_UNIT_DESTINATION[$unit]:-}" = "/etc/systemd/system/$unit.service" ] ||
    fail "pre-#264 unit $unit lost its name or destination"
done
[ "${#SETJOIN_ALL_UNITS[@]}" = 9 ] || fail "unit inventory is ${#SETJOIN_ALL_UNITS[@]} units, want the 8 unchanged + setjoin-gateway"
[ "${SETJOIN_UNIT_DESTINATION["setjoin-gateway"]:-}" = /etc/systemd/system/setjoin-gateway.service ] ||
  fail "setjoin-gateway is not in the compiled catalog"
[ "${SETJOIN_UNIT_REQUIRED["setjoin-gateway"]}" = true ] || fail "front door is not a required (default ON) unit"
case " ${SETJOIN_DEFAULT_ENABLE[*]} " in *" setjoin-gateway "*) ;; *) fail "front door is not enabled by default" ;; esac
order=" ${SETJOIN_REQUIRED_START_ORDER[*]} "
case "$order" in *" setjoin setjoin-gateway "*) ;; *) fail "front door must start right after the Go gateway it proxies: $order" ;; esac
stop=" ${SETJOIN_STOP_ORDER[*]} "
case "$stop" in *" setjoin-gateway setjoin "*) ;; *) fail "front door must stop before the Go gateway: $stop" ;; esac

# ── 2. Rendered through the real installer path ──────────────────────────────
FX="$tmp/fx"
mkdir -p "$FX/units"
sed "s#/etc/systemd/system#$FX/units#g" "$ROOT/mailserver/deploy/generated/unit-catalog.sh" >"$tmp/catalog.sh"
{
  echo 'set -euo pipefail'
  echo 'die() { printf "ERROR: %s\n" "$1" >&2; exit 1; }'
  echo 'info() { printf "    %s\n" "$1"; }'
  echo "ROOT='$ROOT'"
  echo 'source "$ROOT/mailserver/deploy/scripts/lib-livekit.sh"'
  echo "source '$tmp/catalog.sh'"
  sed -n '/^render_runtime_units() {/,/^}$/p' "$INSTALL"
} >"$tmp/harness.sh"
grep -q '^render_runtime_units() {' "$tmp/harness.sh" || fail "could not extract render_runtime_units from install.sh"

cat >>"$tmp/harness.sh" <<HARNESS
INSTALL_DIR='$FX/opt'
RUNTIME_DIR='$FX/opt/current'
DATA_DIR='$FX/var'
CONFIG_ENV='$FX/etc/config.env'
AUTH_ENV='$FX/etc/auth.env'
GATEWAY_ENV='$FX/etc/gateway.env'
DB_CREDENTIALS_FILE='$FX/etc/db-credentials.d/db-credentials.env'
UPDATER_DATA_DIR='$FX/updater'
UPDATER_DSN_FILE='$FX/u/dsn'
UPDATER_EXECUTION_CONFIG='$FX/u/execution.json'
UPDATER_OWNER_DSN_FILE='$FX/u/owner'
UPDATER_RECOVERY_ACCESS_FILE='$FX/u/ra'
UPDATER_RECOVERY_SECRET_FILE='$FX/u/rs'
UPDATER_RECOVERY_HMAC_FILE='$FX/u/rh'
UPDATER_PROBE_CREDENTIAL_FILE='$FX/u/probe'
UPDATER_APP_WORKER_DSN_FILE='$FX/u/aw'
OFFICE_APP_MANIFEST='$FX/u/office.json'
OFFICE_APP_STATE_DIR='$FX/u/office'
CONTAINER_BIN=/bin/echo
AUTHSERVER_URL=http://127.0.0.1:8443
mkdir -p '$FX/etc'
render_runtime_units
render_gateway_env '$FX/etc/gateway.env'
HARNESS
bash "$tmp/harness.sh" || fail "render_runtime_units/render_gateway_env failed"

for unit in "${SETJOIN_REQUIRED_START_ORDER[@]}"; do
  [ -s "$FX/units/$unit.service" ] || fail "required unit $unit was not rendered"
done
svc="$FX/units/setjoin-gateway.service"
sock="$FX/units/setjoin-gateway.socket"
[ -s "$sock" ] || fail "the front-door socket was not rendered beside its service"
require_text 'runs the active release' "ExecStart=$FX/opt/current/setjoin-gateway" "$svc"
require_text 'reads its own env overrides' "EnvironmentFile=$FX/etc/gateway.env" "$svc"
! grep -Eq '^EnvironmentFile=.*(config.env|db-credentials.env)$' "$svc" || fail "gateway received the broad secret files"
require_text 'dedicated federation credentials' "EnvironmentFile=-$FX/etc/federation.env" "$svc"
require_text 'socket activated' 'Requires=setjoin-gateway.socket' "$svc"
require_text 'enable pulls the socket' 'Also=setjoin-gateway.socket' "$svc"
require_text 'unprivileged account' 'User=setjoin' "$svc"
require_text 'empty bounding set' 'CapabilityBoundingSet=' "$svc"
grep -Eq '^CapabilityBoundingSet=$' "$svc" || fail "gateway bounding set is not empty"
grep -Eq '^AmbientCapabilities=$' "$svc" || fail "gateway ambient set is not empty"
! grep -q 'CAP_' "$svc" || fail "gateway unit names a capability"
require_text 'starts after Go' 'After=network.target setjoin-gateway.socket setjoin.service setjoin-auth.service' "$svc"
require_text 'loopback plaintext listener' 'ListenStream=127.0.0.1:8090' "$sock"
require_text 'one shared listener' 'Accept=no' "$sock"
for unit_file in "$svc" "$sock"; do
  require_text 'inactive until a release carries the binary' "ConditionPathExists=$FX/opt/current/setjoin-gateway" "$unit_file"
  ! grep -q '{{' "$unit_file" || fail "unresolved placeholder in $unit_file"
done
if command -v systemd-analyze >/dev/null 2>&1; then
  # Units reference fixture paths; verify syntax only (no man-page lookups).
  out="$(systemd-analyze verify --man=no "$svc" "$sock" 2>&1 || true)"
  if grep -Ei 'unknown (key|section)|failed to parse|invalid' <<<"$out" | grep -v 'Command .* is not executable' | grep -q .; then
    fail "systemd-analyze rejected the rendered front door: $out"
  fi
fi

gw_env="$FX/etc/gateway.env"
require_text 'Go internal plain listener as upstream' 'GATEWAY_UPSTREAM=http://127.0.0.1:80' "$gw_env"
require_text 'direct authserver upstream' 'GATEWAY_AUTH_UPSTREAM=http://127.0.0.1:8443' "$gw_env"
require_text 'trusts only the local TLS terminator' 'GATEWAY_TRUSTED_PROXIES=127.0.0.1' "$gw_env"
require_text 'front door ON' 'GATEWAY_ENABLED=true' "$gw_env"
# A non-loopback upstream would expose Go's plain listener beyond the host.
if (
  source "$ROOT/mailserver/deploy/scripts/lib-livekit.sh"
  AUTHSERVER_URL=http://127.0.0.1:8443 \
    GATEWAY_UPSTREAM=http://10.0.0.5:80 render_gateway_env "$tmp/bad.env"
) 2>/dev/null; then
  fail "render_gateway_env accepted a non-loopback Go upstream"
fi
[ ! -e "$tmp/bad.env" ] || fail "a refused gateway env was left on disk"

# install.sh: Go serves its internal plain listener and trusts the gateway;
# the binary joins the flat cohort the immutable layout adopts.
require_text 'Go plain listener for the gateway' 'HTTP_MODE=proxy' "$INSTALL"
require_text 'Go trusts exactly the gateway address' 'TRUSTED_PROXY_IP=127.0.0.1' "$INSTALL"
require_text 'gateway env renders in the config step' 'render_gateway_env "$GATEWAY_ENV"' "$INSTALL"
require_text 'gateway binary joins the flat cohort' 'install -m 0755 "$GATEWAY_SOURCE" "$INSTALL_DIR/setjoin-gateway"' "$INSTALL"
require_text 'renderer input assigned before the entry migration' 'GATEWAY_ENV="$CONFIG_DIR/gateway.env"' "$INSTALL"
require_text 'install health-checks the front door' '/_gateway/healthz' "$INSTALL"
[ "$(grep -n 'GATEWAY_ENV="$CONFIG_DIR/gateway.env"' "$INSTALL" | head -1 | cut -d: -f1)" -lt \
  "$(grep -n 'prepare_credential_migration "$CONFIG_DIR"' "$INSTALL" | head -1 | cut -d: -f1)" ] ||
  fail "GATEWAY_ENV must be assigned before the entry migration re-renders units"

# Default start: the installer enables SETJOIN_DEFAULT_ENABLE and runs
# setjoinctl restart; drive the real lifecycle script over the rendered units.
require_text 'installer enables the default set' 'systemctl enable "${SETJOIN_DEFAULT_ENABLE[@]}"' "$INSTALL"
require_text 'installer starts through setjoinctl' '/usr/local/sbin/setjoinctl restart' "$INSTALL"
mkdir -p "$tmp/bin"
cat >"$tmp/bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FRONT_DOOR_LOG"
MOCK
chmod 0755 "$tmp/bin/systemctl"
printf '{"version":1,"enabled":false}\n' >"$tmp/execution.json"
SETJOINCTL_ALLOW_NON_ROOT=1 FRONT_DOOR_LOG="$tmp/systemctl.log" SYSTEMCTL_BIN="$tmp/bin/systemctl" \
  SYSTEMD_DIR="$FX/units" SETJOIN_UNIT_CATALOG="$ROOT/mailserver/deploy/generated/unit-catalog.sh" \
  UPDATER_EXECUTION_CONFIG="$tmp/execution.json" \
  bash "$ROOT/mailserver/deploy/scripts/setjoin-lifecycle.sh" restart >/dev/null
grep -qx 'start setjoin-gateway' "$tmp/systemctl.log" || fail "setjoinctl restart did not start the front door"
[ "$(grep -n '^start setjoin$' "$tmp/systemctl.log" | cut -d: -f1)" -lt \
  "$(grep -n '^start setjoin-gateway$' "$tmp/systemctl.log" | cut -d: -f1)" ] || fail "front door started before Go"

# ── 4. *.prev rollback covers Go and Rust ────────────────────────────────────
bash "$ROOT/mailserver/deploy/scripts/test-upgrade-rollback.sh" >/dev/null ||
  fail "flat *.prev rollback (Go + Rust) failed"
bash "$ROOT/mailserver/deploy/scripts/test-federation-upgrade.sh" >/dev/null ||
  fail "native federation upgrade/whole-release rollback failed"
require_text 'upgrade keeps the previous Rust binary' 'setjoin-gateway.prev' "$UPGRADE"

# ── Executable front door with the rendered configuration ────────────────────
if [ -z "$GATEWAY_BIN" ]; then
  echo "install front door: PASS (static/render/lifecycle/rollback; no gateway binary given, executable arms not run)"
  exit 0
fi
[ -x "$GATEWAY_BIN" ] || fail "gateway binary is not executable: $GATEWAY_BIN"
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
go_port="$(port)"
cat >"$tmp/gofree-t13-upstream.py" <<'PY'
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path, "xff": self.headers.get("X-Forwarded-For"),
                           "proto": self.headers.get("X-Forwarded-Proto")}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
python3 -I "$tmp/gofree-t13-upstream.py" "$go_port" &
pids+=("$!")
for _ in $(seq 1 100); do
  (exec 3<>"/dev/tcp/127.0.0.1/$go_port") 2>/dev/null && break
  sleep 0.1
done

run_front_door() { # run_front_door <address> — exercise a listening front door
  local address="$1" body
  for _ in $(seq 1 100); do
    curl -sf "http://$address/_gateway/healthz" >/dev/null 2>&1 && break
    sleep 0.1
  done
  [ "$(curl -sf "http://$address/_gateway/healthz")" = ok ] || fail "front door at $address did not answer its health probe"
  # The local TLS terminator (trusted) reports the client; a spoofed chain
  # entry is ignored and https survives because the peer is trusted.
  body="$(curl -sS -f -H 'X-Forwarded-For: 6.6.6.6, 203.0.113.9' -H 'X-Forwarded-Proto: https' "http://$address/health?probe=1" 2>&1)" ||
    fail "front door did not forward to Go: $body $(cat "$tmp/gateway.log" 2>/dev/null)"
  python3 -I -c 'import json,sys; d=json.loads(sys.argv[1]); assert d=={"path":"/health?probe=1","xff":"203.0.113.9","proto":"https"}, d' "$body" ||
    fail "forwarded request lost its path or identity headers: $body"
}

# Direct run with the rendered env (only the upstream port differs: the
# stand-in Go is not on :80).
gw_port="$(port)"
(
  set -a
  # shellcheck disable=SC1090
  source "$gw_env"
  set +a
  export GATEWAY_UPSTREAM="http://127.0.0.1:$go_port" GATEWAY_LISTEN="127.0.0.1:$gw_port"
  export LLVM_PROFILE_FILE="$tmp/gofree-t13-%p.profraw"
  exec "$GATEWAY_BIN"
) >"$tmp/gateway.log" 2>&1 &
pids+=("$!")
run_front_door "127.0.0.1:$gw_port"
echo "install front door: rendered configuration serves and forwards (direct run)"

if [ "$(id -u)" != 0 ] || ! systemctl show --property=Version --value >/dev/null 2>&1; then
  [ "${REQUIRE_SYSTEMD:-0}" != 1 ] || fail "REQUIRE_SYSTEMD=1 but root/systemd is unavailable"
  echo "install front door: PASS (systemd arm NOT run: needs root and a systemd manager)"
  exit 0
fi

# Real systemd: the rendered units under a disposable name. Only the account
# (nobody: no setjoin user here), binary path and env path are substituted.
name="gofree-t13-front-door-$$"
sd="/run/systemd/system"
# Not below /tmp: the rendered unit has PrivateTmp=true.
bin_dir="$(mktemp -d /run/gofree-t13-front-door-bin.XXXXXX)"
chmod 0755 "$bin_dir"
install -m 0755 "$GATEWAY_BIN" "$bin_dir/setjoin-gateway"
sd_port="$(port)"
sed -e "s#^GATEWAY_UPSTREAM=.*#GATEWAY_UPSTREAM=http://127.0.0.1:$go_port#" "$gw_env" >"$bin_dir/gateway.env"
chmod 0644 "$bin_dir/gateway.env"
echo 'LLVM_PROFILE_FILE=/tmp/gofree-t13-%p.profraw' >>"$bin_dir/gateway.env"
echo "Owned resources: $bin_dir, $sd/$name.socket, $sd/$name.service (removed on exit)"
systemd_cleanup() {
  systemctl stop "$name.socket" "$name.service" >/dev/null 2>&1 || true
  rm -f "$sd/$name.socket" "$sd/$name.service"
  systemctl daemon-reload || true
  systemctl reset-failed "$name.service" "$name.socket" >/dev/null 2>&1 || true
  rm -rf "$bin_dir"
  cleanup
}
trap systemd_cleanup EXIT
sed -e "s#$FX/opt/current/setjoin-gateway#$bin_dir/setjoin-gateway#g" \
  -e "s#$FX/etc/gateway.env#$bin_dir/gateway.env#g" \
  -e 's#^User=setjoin$#User=nobody#' -e 's#^Group=setjoin$#Group=nogroup#' \
  -e "s#setjoin-gateway.socket#$name.socket#g" \
  -e '/^After=/s# setjoin.service setjoin-auth.service##' -e '/^Wants=/d' \
  "$svc" >"$sd/$name.service"
getent group nogroup >/dev/null || sed -i 's#^Group=nogroup$#Group=nobody#' "$sd/$name.service"
sed -e "s#$FX/opt/current/setjoin-gateway#$bin_dir/setjoin-gateway#g" \
  -e "s#^ListenStream=.*#ListenStream=127.0.0.1:$sd_port#" \
  -e "/^\[Socket\]/a Service=$name.service" \
  "$sock" >"$sd/$name.socket"
systemctl daemon-reload
systemctl start "$name.socket"
run_front_door "127.0.0.1:$sd_port"
pid="$(systemctl show "$name.service" -p MainPID --value)"
[ "${pid:-0}" -gt 0 ] || fail "socket activation did not start the rendered service"
for field in CapInh CapPrm CapEff CapBnd CapAmb; do
  value="$(awk -v f="$field:" '$1==f {print $2}' "/proc/$pid/status")"
  [ "$((16#$value))" = 0 ] || fail "rendered service holds $field=$value"
done
[ "$(awk '$1=="Uid:" {print $2}' "/proc/$pid/status")" != 0 ] || fail "rendered service runs as root"
echo "install front door: PASS (rendered socket+service under systemd: activation, empty capabilities, forwarding)"
