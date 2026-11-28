#!/usr/bin/env bash
# Fixed-scope lifecycle controller for a single-node Setjoin installation.
# It deliberately has no caller-supplied unit or path arguments.
set -euo pipefail

SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-systemctl}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
UPDATER_EXECUTION_CONFIG="${UPDATER_EXECUTION_CONFIG:-/etc/setjoin-updater/execution.json}"
CATALOG_SH="${SETJOIN_UNIT_CATALOG:-/usr/local/lib/setjoin/unit-catalog.sh}"
[ -r "$CATALOG_SH" ] || {
  printf 'setjoinctl: fixed unit catalog is missing: %s\n' "$CATALOG_SH" >&2
  exit 1
}
# shellcheck source=../generated/unit-catalog.sh
source "$CATALOG_SH"

die() {
  printf 'setjoinctl: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: setjoinctl <start|stop|restart|status|uninstall> [options]

Options for stop, restart, and uninstall:
  --allow-updater-stop      confirm that no upgrade is active before stopping

Required for uninstall:
  --confirm-preserve-data   remove only Setjoin systemd unit registrations;
                            preserve config, mail data, recovery sets, releases,
                            PostgreSQL, and object storage

The command accepts no service names or filesystem paths.
EOF
}

require_root() {
  [ "${SETJOINCTL_ALLOW_NON_ROOT:-0}" = "1" ] || [ "$(id -u)" = "0" ] ||
    die "must run as root"
  command -v "$SYSTEMCTL_BIN" >/dev/null 2>&1 || die "required service-manager binary is unavailable"
}

unit_file() {
  printf '%s/%s.service\n' "$SYSTEMD_DIR" "$1"
}

unit_installed() {
  [ -f "$(unit_file "$1")" ]
}

# Active topology resolution (#544): detect split (setjoin-auth + setjoin-gateway)
# vs unified (setjoind), failing closed on mixed or missing core units.
ACTIVE_TOPOLOGY=""
ACTIVE_REQUIRED_START_ORDER=()
ACTIVE_STOP_ORDER=()
ACTIVE_ALL_UNITS=()
declare -A ACTIVE_UNIT_REQUIRED=()

ALL_SERVER_SOCKETS=(
  setjoin-gateway.socket setjoin-federation.socket setjoin-https.socket setjoin-acme.socket
  setjoin-imap.socket setjoin-imaps.socket setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket
)

resolve_topology() {
  local has_unified=0 has_split=0 unit
  if unit_installed setjoind; then has_unified=1; fi
  if unit_installed setjoin-gateway || unit_installed setjoin-auth; then has_split=1; fi
  if [ "$has_unified" = 1 ] && [ "$has_split" = 1 ]; then
    die "mixed unit topology: setjoind.service coexists with setjoin-gateway.service or setjoin-auth.service"
  fi
  ACTIVE_REQUIRED_START_ORDER=()
  ACTIVE_STOP_ORDER=()
  ACTIVE_ALL_UNITS=()
  ACTIVE_UNIT_REQUIRED=()
  if [ "$has_unified" = 1 ]; then
    ACTIVE_TOPOLOGY="unified"
    for unit in "${SETJOIN_REQUIRED_START_ORDER[@]}"; do
      case "$unit" in
        setjoin-auth) ACTIVE_REQUIRED_START_ORDER+=(setjoind) ;;
        setjoin-gateway) ;;
        *) ACTIVE_REQUIRED_START_ORDER+=("$unit") ;;
      esac
    done
    for unit in "${SETJOIN_STOP_ORDER[@]}"; do
      case "$unit" in
        setjoin-gateway) ACTIVE_STOP_ORDER+=(setjoind) ;;
        setjoin-auth) ;;
        *) ACTIVE_STOP_ORDER+=("$unit") ;;
      esac
    done
    for unit in "${SETJOIN_ALL_UNITS[@]}"; do
      case "$unit" in
        setjoin-auth)
          ACTIVE_ALL_UNITS+=(setjoind)
          ACTIVE_UNIT_REQUIRED[setjoind]="true"
          ;;
        setjoin-gateway) ;;
        *)
          ACTIVE_ALL_UNITS+=("$unit")
          ACTIVE_UNIT_REQUIRED["$unit"]="${SETJOIN_UNIT_REQUIRED[$unit]}"
          ;;
      esac
    done
  else
    ACTIVE_TOPOLOGY="split"
    ACTIVE_REQUIRED_START_ORDER=("${SETJOIN_REQUIRED_START_ORDER[@]}")
    ACTIVE_STOP_ORDER=("${SETJOIN_STOP_ORDER[@]}")
    ACTIVE_ALL_UNITS=("${SETJOIN_ALL_UNITS[@]}")
    for unit in "${SETJOIN_ALL_UNITS[@]}"; do
      ACTIVE_UNIT_REQUIRED["$unit"]="${SETJOIN_UNIT_REQUIRED[$unit]}"
    done
  fi
}

require_base_units() {
  local unit
  for unit in "${ACTIVE_REQUIRED_START_ORDER[@]}"; do
    unit_installed "$unit" || die "required unit $(unit_file "$unit") is missing"
  done
}

updater_execution_enabled() {
  [ -f "$UPDATER_EXECUTION_CONFIG" ] &&
    grep -Eq '"enabled"[[:space:]]*:[[:space:]]*true([[:space:],}]|$)' "$UPDATER_EXECUTION_CONFIG"
}

require_updater_stop_confirmation() {
  local confirmed="$1"
  if updater_execution_enabled && [ "$confirmed" != "1" ]; then
    die "transactional upgrade execution is enabled; verify no upgrade is active, then retry with --allow-updater-stop"
  fi
}

start_or_restart() {
  local verb="$1" unit
  resolve_topology
  require_base_units
  for unit in "${ACTIVE_ALL_UNITS[@]}"; do
    if [ "${ACTIVE_UNIT_REQUIRED[$unit]}" = "true" ] || unit_installed "$unit"; then
      "$SYSTEMCTL_BIN" "$verb" "$unit"
    fi
  done
}

stop_all() {
  local unit socket
  resolve_topology
  for unit in "${ACTIVE_STOP_ORDER[@]}"; do
    if unit_installed "$unit"; then
      # Keep listeners open across restart so new connections queue. A full
      # stop/uninstall must close all sockets first to prevent reactivation.
      if [ "${1:-}" != restart ] && { [ "$unit" = setjoin-gateway ] || [ "$unit" = setjoind ]; }; then
        for socket in "${ALL_SERVER_SOCKETS[@]}"; do
          if [ -f "$SYSTEMD_DIR/$socket" ]; then "$SYSTEMCTL_BIN" stop "$socket"; fi
        done
      elif [ "${1:-}" != restart ] && [ -f "$SYSTEMD_DIR/$unit.socket" ]; then
        "$SYSTEMCTL_BIN" stop "$unit.socket"
      fi
      "$SYSTEMCTL_BIN" stop "$unit"
    fi
  done
}

status_all() {
  local unit failed=0
  resolve_topology
  if [ "$ACTIVE_TOPOLOGY" = "split" ] && ! unit_installed setjoin-gateway && ! unit_installed setjoin-auth; then
    die "no core Setjoin units installed in $SYSTEMD_DIR"
  fi
  for unit in "${ACTIVE_ALL_UNITS[@]}"; do
    if unit_installed "$unit"; then
      "$SYSTEMCTL_BIN" is-active "$unit" || failed=1
    fi
  done
  return "$failed"
}

uninstall_units() {
  local unit path socket
  stop_all
  for unit in "${ACTIVE_ALL_UNITS[@]}"; do
    if unit_installed "$unit"; then
      "$SYSTEMCTL_BIN" disable "$unit" >/dev/null 2>&1 || true
      if [ "$unit" = setjoin-gateway ] || [ "$unit" = setjoind ]; then
        for socket in "${ALL_SERVER_SOCKETS[@]}"; do
          if [ -f "$SYSTEMD_DIR/$socket" ]; then
            "$SYSTEMCTL_BIN" disable "$socket" >/dev/null 2>&1 || true
            rm -f -- "$SYSTEMD_DIR/$socket"
          fi
        done
      fi
      path="$(unit_file "$unit")"
      rm -f -- "$path"
      if [ -f "${path%.service}.socket" ]; then
        "$SYSTEMCTL_BIN" disable "$unit.socket" >/dev/null 2>&1 || true
        rm -f -- "${path%.service}.socket"
      fi
    fi
  done
  "$SYSTEMCTL_BIN" daemon-reload
  "$SYSTEMCTL_BIN" reset-failed >/dev/null 2>&1 || true
  cat <<'EOF'
Setjoin service registrations were removed.
Preserved: /etc/setjoin, /etc/setjoin-updater, /var/lib/setjoin,
/var/lib/setjoin-updater, /opt/setjoin, PostgreSQL, and object storage.
Data purge is intentionally not implemented by this command.
EOF
}

main() {
  [ "$#" -ge 1 ] || {
    usage >&2
    exit 2
  }
  local command="$1" allow_updater_stop=0 confirm_preserve_data=0
  shift
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --allow-updater-stop) allow_updater_stop=1 ;;
      --confirm-preserve-data) confirm_preserve_data=1 ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        usage >&2
        die "unsupported option: $1"
        ;;
    esac
    shift
  done

  require_root
  case "$command" in
    start)
      [ "$allow_updater_stop" = "0" ] && [ "$confirm_preserve_data" = "0" ] ||
        die "start accepts no options"
      start_or_restart start
      ;;
    stop)
      [ "$confirm_preserve_data" = "0" ] || die "--confirm-preserve-data is only valid with uninstall"
      require_updater_stop_confirmation "$allow_updater_stop"
      stop_all
      ;;
    restart)
      [ "$confirm_preserve_data" = "0" ] || die "--confirm-preserve-data is only valid with uninstall"
      require_updater_stop_confirmation "$allow_updater_stop"
      stop_all restart
      start_or_restart start
      ;;
    status)
      [ "$allow_updater_stop" = "0" ] && [ "$confirm_preserve_data" = "0" ] ||
        die "status accepts no options"
      status_all
      ;;
    uninstall)
      [ "$confirm_preserve_data" = "1" ] ||
        die "uninstall requires --confirm-preserve-data"
      require_updater_stop_confirmation "$allow_updater_stop"
      uninstall_units
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
