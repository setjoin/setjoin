#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SCRIPT="$ROOT/mailserver/deploy/scripts/setjoin-lifecycle.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/systemd" "$tmp/etc" "$tmp/data"
log="$tmp/systemctl.log"

cat > "$tmp/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$SETJOINCTL_TEST_LOG"
case "${1:-}" in
  is-active) printf 'active\n' ;;
esac
EOF
chmod 0755 "$tmp/bin/systemctl"

base=(setjoin-valkey setjoin-sfu setjoin-egress setjoin-auth setjoin-gateway setjoin-updater)
optional=(setjoin-funasr setjoin-asr-bot)
for unit in "${base[@]}" "${optional[@]}"; do
  : > "$tmp/systemd/$unit.service"
done
: > "$tmp/systemd/setjoin-gateway.socket"
: > "$tmp/systemd/setjoin-federation.socket"
: > "$tmp/systemd/setjoin-https.socket"
: > "$tmp/systemd/setjoin-imap.socket"
: > "$tmp/systemd/setjoin-imaps.socket"
printf '{"version":1,"enabled":false}\n' > "$tmp/etc/execution.json"

run_lifecycle() {
  SETJOINCTL_ALLOW_NON_ROOT=1 \
    SETJOINCTL_TEST_LOG="$log" \
    SYSTEMCTL_BIN="$tmp/bin/systemctl" \
    SYSTEMD_DIR="$tmp/systemd" \
    SETJOIN_UNIT_CATALOG="$ROOT/mailserver/deploy/generated/unit-catalog.sh" \
    UPDATER_EXECUTION_CONFIG="$tmp/etc/execution.json" \
    bash "$SCRIPT" "$@"
}

run_lifecycle start
expected_start=$'start setjoin-valkey\nstart setjoin-sfu\nstart setjoin-egress\nstart setjoin-funasr\nstart setjoin-asr-bot\nstart setjoin-auth\nstart setjoin-gateway\nstart setjoin-updater'
[ "$(cat "$log")" = "$expected_start" ] || {
  echo "unexpected start order" >&2; cat "$log" >&2; exit 1;
}

: > "$log"
run_lifecycle restart
expected_stop=$'stop setjoin-updater\nstop setjoin-gateway\nstop setjoin-auth\nstop setjoin-asr-bot\nstop setjoin-funasr\nstop setjoin-egress\nstop setjoin-sfu\nstop setjoin-valkey'
[ "$(sed -n '1,8p' "$log")" = "$expected_stop" ] || {
  echo "unexpected stop order" >&2; cat "$log" >&2; exit 1;
}
[ "$(sed -n '9,16p' "$log")" = "$expected_start" ] || {
  echo "unexpected restart order" >&2; cat "$log" >&2; exit 1;
}

printf '{"version":1,"enabled":true}\n' > "$tmp/etc/execution.json"
if run_lifecycle stop >/dev/null 2>&1; then
  echo "enabled updater execution allowed an unconfirmed stop" >&2
  exit 1
fi
run_lifecycle stop --allow-updater-stop >/dev/null

# A stopped front door must not be reactivated by its still-listening socket.
: > "$log"
run_lifecycle stop --allow-updater-stop >/dev/null
for socket in setjoin-https.socket setjoin-imap.socket setjoin-imaps.socket; do
  grep -qx "stop $socket" "$log" || { echo "stop retained $socket" >&2; exit 1; }
  [ "$(grep -n "^stop $socket$" "$log" | cut -d: -f1)" -lt "$(grep -n '^stop setjoin-gateway$' "$log" | cut -d: -f1)" ] || exit 1
done
grep -qx 'stop setjoin-federation.socket' "$log" || { echo 'stop retained federation socket' >&2; exit 1; }
grep -qx 'stop setjoin-gateway.socket' "$log" || {
  echo "stop retained the activating front-door socket" >&2; exit 1;
}
[ "$(grep -n '^stop setjoin-gateway.socket$' "$log" | cut -d: -f1)" -lt \
  "$(grep -n '^stop setjoin-gateway$' "$log" | cut -d: -f1)" ] || {
  echo "front-door socket stopped after its service" >&2; exit 1;
}

if run_lifecycle uninstall --allow-updater-stop >/dev/null 2>&1; then
  echo "uninstall without preserve-data confirmation succeeded" >&2
  exit 1
fi
preserved="$tmp/data/mail-object"
: > "$preserved"
run_lifecycle uninstall --allow-updater-stop --confirm-preserve-data >/dev/null
[ -f "$preserved" ] || { echo "uninstall removed preserved data" >&2; exit 1; }
[ ! -e "$tmp/systemd/setjoin-federation.socket" ] || { echo "uninstall retained federation socket" >&2; exit 1; }
[ ! -e "$tmp/systemd/setjoin-gateway.socket" ] || { echo "uninstall retained the front-door socket" >&2; exit 1; }
for socket in setjoin-https.socket setjoin-imap.socket setjoin-imaps.socket; do
  [ ! -e "$tmp/systemd/$socket" ] || { echo "uninstall retained $socket" >&2; exit 1; }
done
for unit in "${base[@]}" "${optional[@]}"; do
  [ ! -e "$tmp/systemd/$unit.service" ] || {
    echo "uninstall retained unit $unit" >&2; exit 1;
  }
done

if run_lifecycle start >/dev/null 2>&1; then
  echo "start accepted a missing required unit" >&2
  exit 1
fi

# Unified setjoind topology (#544): start/stop/restart/uninstall + mixed refusal.
uni_base=(setjoin-valkey setjoin-sfu setjoin-egress setjoind setjoin-updater)
for unit in "${uni_base[@]}"; do
  : >"$tmp/systemd/$unit.service"
done
for sock in setjoin-gateway.socket setjoin-federation.socket setjoin-https.socket \
  setjoin-imap.socket setjoin-imaps.socket \
  setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
  : >"$tmp/systemd/$sock"
done

# Mixed topology (setjoind.service + setjoin-gateway.service) MUST fail closed.
: >"$tmp/systemd/setjoin-gateway.service"
if run_lifecycle start >/dev/null 2>&1; then
  echo "mixed topology was accepted by setjoinctl start" >&2
  exit 1
fi
rm -f "$tmp/systemd/setjoin-gateway.service"

: >"$log"
run_lifecycle start
expected_uni_start=$'start setjoin-valkey\nstart setjoin-sfu\nstart setjoin-egress\nstart setjoind\nstart setjoin-updater'
[ "$(cat "$log")" = "$expected_uni_start" ] || {
  echo "unexpected unified start order" >&2
  cat "$log" >&2
  exit 1
}

: >"$log"
run_lifecycle stop --allow-updater-stop >/dev/null
for sock in setjoin-gateway.socket setjoin-federation.socket setjoin-https.socket \
  setjoin-imap.socket setjoin-imaps.socket \
  setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
  grep -qx "stop $sock" "$log" || {
    echo "unified stop retained $sock" >&2
    exit 1
  }
  [ "$(grep -n "^stop $sock$" "$log" | cut -d: -f1)" -lt "$(grep -n '^stop setjoind$' "$log" | cut -d: -f1)" ] || {
    echo "unified stop closed $sock after setjoind" >&2
    exit 1
  }
done

run_lifecycle uninstall --allow-updater-stop --confirm-preserve-data >/dev/null
for sock in setjoin-gateway.socket setjoin-federation.socket setjoin-https.socket \
  setjoin-imap.socket setjoin-imaps.socket \
  setjoin-smtp.socket setjoin-smtps.socket setjoin-submission.socket; do
  [ ! -e "$tmp/systemd/$sock" ] || {
    echo "unified uninstall retained $sock" >&2
    exit 1
  }
done
[ ! -e "$tmp/systemd/setjoind.service" ] || {
  echo "unified uninstall retained setjoind.service" >&2
  exit 1
}

echo "setjoin lifecycle: PASS"
