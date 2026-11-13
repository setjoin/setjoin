#!/usr/bin/env bash
# Resumable host-side observer for the V175 OIDC authentication shadow rail.
# It runs a real RP -> OP authorization-code/TOTP flow every four hours until
# the database itself proves >=7 matches spanning >=24 hours.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_PREFIX="${RUN_PREFIX:-}"
ACTION="${1:-status}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-14400}"
A=""
C=""
EVIDENCE_DIR=""
PRIVATE_DIR=""
FLOW="$ROOT/scripts/unified-deployment-d4-oidc-flow.sh"

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

validate() {
  case "$RUN_PREFIX" in
    (*[!a-z0-9-]*|'') die "RUN_PREFIX must contain only lowercase a-z, 0-9, or hyphen" ;;
  esac
  case "$ACTION" in
    (once|observe|run-loop|status|verify-window|stop) ;;
    (*) die "usage: $0 once|observe|status|verify-window|stop" ;;
  esac
  [[ "$INTERVAL_SECONDS" =~ ^[1-9][0-9]*$ ]] ||
    die "INTERVAL_SECONDS must be a positive integer"
  [ "$INTERVAL_SECONDS" -ge 900 ] ||
    die "INTERVAL_SECONDS must be at least 900; compressed clocks are not accepted"
  [ "$INTERVAL_SECONDS" -le 14400 ] ||
    die "INTERVAL_SECONDS must be at most 14400 so seven observations span no more than 24 hours"
  A="${RUN_PREFIX}-a"
  C="${RUN_PREFIX}-c"
  EVIDENCE_DIR="$ROOT/test-results/deployment-readiness/$RUN_PREFIX/d4/oidc"
  PRIVATE_DIR="$EVIDENCE_DIR/private"
  install -d -m 0700 "$EVIDENCE_DIR" "$PRIVATE_DIR"
  [ -x "$FLOW" ] || die "OIDC flow helper is missing or not executable: $FLOW"
  for name in "$A" "$C"; do
    [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = true ] ||
      die "required retained container is not running: $name"
  done
  [ -s "$PRIVATE_DIR/admin-email" ] || die "missing private test admin email file"
  [ -s "$PRIVATE_DIR/admin-password" ] || die "missing private test admin password file"
}

reset_test_idp_admin() {
  local user_id count password
  count="$(docker exec -u postgres "$C" psql -d mailserver -Atc "
    SELECT count(*)
      FROM users u
      JOIN admin_role_assignments a ON a.user_id=u.id
      JOIN admin_role_groups g ON g.id=a.role_group_id
     WHERE g.name='Super Admin'
       AND (a.expires_at IS NULL OR a.expires_at>now())")"
  [ "$count" = 1 ] || die "test IdP must have exactly one active Super Admin"
  user_id="$(docker exec -u postgres "$C" psql -d mailserver -Atc "
    SELECT u.id
      FROM users u
      JOIN admin_role_assignments a ON a.user_id=u.id
      JOIN admin_role_groups g ON g.id=a.role_group_id
     WHERE g.name='Super Admin'
       AND (a.expires_at IS NULL OR a.expires_at>now())")"
  password="$(<"$PRIVATE_DIR/admin-password")"
  docker exec -i -u postgres "$C" psql -d mailserver \
    -v ON_ERROR_STOP=1 -v "password=$password" -v "user_id=$user_id" <<'SQL' >/dev/null
UPDATE users
   SET password_hash=crypt(:'password',gen_salt('bf')),
       must_change_password=false,
       totp_enabled=false,
       totp_enabled_at=NULL,
       totp_secret_enc=NULL,
       mfa_exempt=false,
       enabled=true,
       updated_at=now()
 WHERE id=:'user_id'::bigint;
SET row_security=off;
DELETE FROM auth_lockouts;
DELETE FROM rate_limit_counters;
DELETE FROM auth_attempts;
SQL
}

gate_json() {
  docker exec -u postgres "$A" psql -d mailserver -Atc "
    SELECT identity_upgrade_shadow(source_key)::text
      FROM identity_sources
     WHERE kind='oidc'
     ORDER BY id"
}

source_ready() {
  [ "$(docker exec -u postgres "$A" psql -d mailserver -Atc "
    SELECT count(*)
      FROM identity_sources
     WHERE kind='oidc'
       AND state='active'
       AND read_mode='shadow'")" = 1 ]
}

run_once() {
  source_ready ||
    die "expected exactly one active shadow-mode OIDC source before changing the test account"
  reset_test_idp_admin
  docker exec \
    -e "TEST_ADMIN_EMAIL=$(<"$PRIVATE_DIR/admin-email")" \
    -e "TEST_ADMIN_PASSWORD=$(<"$PRIVATE_DIR/admin-password")" \
    "$A" /mnt/repo-src/scripts/unified-deployment-d4-oidc-flow.sh
  gate_json
}

observe_loop() {
  while :; do
    if ! source_ready; then
      printf 'stopped_at=%s reason=oidc_source_not_active_shadow\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        >>"$EVIDENCE_DIR/auth-observation.log"
      exit 0
    fi
    {
      printf 'observed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      run_once
    } >>"$EVIDENCE_DIR/auth-observation.log" 2>>"$EVIDENCE_DIR/auth-observer.stderr"
    if gate_json | python3 -c \
      'import json,sys; rows=[json.loads(x) for x in sys.stdin if x.strip()]; raise SystemExit(0 if len(rows)==1 and rows[0].get("eligible") is True else 1)'; then
      printf 'eligible_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        >>"$EVIDENCE_DIR/auth-observation.log"
      exit 0
    fi
    sleep "$INTERVAL_SECONDS"
  done
}

observer_alive() {
  local pid_file="$EVIDENCE_DIR/auth-observer.pid"
  local pid recorded_start current_start
  [ -s "$pid_file" ] || return 1
  read -r pid recorded_start <"$pid_file"
  [[ "$pid" =~ ^[1-9][0-9]*$ && "$recorded_start" =~ ^[1-9][0-9]*$ ]] ||
    return 1
  kill -0 "$pid" 2>/dev/null || return 1
  [ -r "/proc/$pid/stat" ] || return 1
  current_start="$(awk '{print $22}' "/proc/$pid/stat")"
  [ "$current_start" = "$recorded_start" ]
}

start_observer() {
  local pid_file="$EVIDENCE_DIR/auth-observer.pid"
  local pid start_ticks
  if observer_alive; then
    echo "auth_observer=running"
    return
  fi
  nohup "$0" run-loop \
    >"$EVIDENCE_DIR/auth-observer.stdout" \
    2>>"$EVIDENCE_DIR/auth-observer.stderr" &
  pid="$!"
  for _ in {1..20}; do
    [ -r "/proc/$pid/stat" ] && break
    sleep 0.05
  done
  [ -r "/proc/$pid/stat" ] || die "auth observer exited before its identity could be recorded"
  start_ticks="$(awk '{print $22}' "/proc/$pid/stat")"
  printf '%s %s\n' "$pid" "$start_ticks" >"$pid_file"
  chmod 0600 "$pid_file"
  printf 'auth_observer=started\npid=%s\n' "$pid"
}

stop_observer() {
  local pid_file="$EVIDENCE_DIR/auth-observer.pid"
  local pid
  if observer_alive; then
    read -r pid _ <"$pid_file"
    kill "$pid" 2>/dev/null || true
  fi
  rm -f "$pid_file"
  echo "auth_observer=stopped"
}

validate
case "$ACTION" in
  (once) run_once ;;
  (observe) start_observer ;;
  (run-loop) observe_loop ;;
  (status)
    gate_json
    if observer_alive; then
      echo "auth_observer=running"
    else
      echo "auth_observer=stopped"
    fi
    ;;
  (verify-window)
    result="$(gate_json)"
    printf '%s\n' "$result"
    printf '%s\n' "$result" | python3 -c \
      'import json,sys; rows=[json.loads(x) for x in sys.stdin if x.strip()]; raise SystemExit(0 if len(rows)==1 and rows[0].get("eligible") is True else 1)' ||
      die "real OIDC authentication observation is not yet eligible"
    echo "D4_AUTH_WINDOW_PASS"
    ;;
  (stop) stop_observer ;;
esac
