#!/usr/bin/env bash
# D6 composition soak setup/status/cleanup for retained A/B/C stacks.
# Keeps Guest + Identity model canary + Federation live together on A while
# the real 24-hour Identity observer runs. All test state is prefix-scoped.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_PREFIX="${RUN_PREFIX:-}"
TEST_SUBNET="${TEST_SUBNET:-172.30.240.0/24}"
ACTION="${1:-prepare}"
A=""
B=""
C=""
EVIDENCE_DIR=""

die() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

validate() {
  case "$RUN_PREFIX" in
    (*[!a-z0-9-]*|'') die "RUN_PREFIX is required and must contain only lowercase a-z, 0-9, or hyphen" ;;
  esac
  case "$TEST_SUBNET" in
    (*.*.*".0/24") ;;
    (*) die "TEST_SUBNET must be an IPv4 /24 ending in .0/24" ;;
  esac
  case "$ACTION" in
    (prepare|status|cleanup) ;;
    (*) die "usage: $0 prepare|status|cleanup" ;;
  esac
  A="${RUN_PREFIX}-a"
  B="${RUN_PREFIX}-b"
  C="${RUN_PREFIX}-c"
  EVIDENCE_DIR="$ROOT/test-results/deployment-readiness/$RUN_PREFIX/d6"
  install -d -m 0700 "$EVIDENCE_DIR"
  for container in "$A" "$B" "$C"; do
    [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" = "true" ] ||
      die "required retained container is not running: $container"
  done
}

psql_env() {
  local container="$1" sql="$2"
  docker exec -i "$container" bash -s -- "$sql" <<'INNER'
set -Eeuo pipefail
sql="$1"
source /etc/setjoin/config.env
psql "$DB_DIRECT_OWNER_DSN" -X -v ON_ERROR_STOP=1 -tAc "$sql"
INNER
}

prepare_action() {
  [ -s "$ROOT/test-results/deployment-readiness/$RUN_PREFIX/d3/browser.txt" ] ||
    die "D6 requires the completed Guest browser journey"
  [ -s "$ROOT/test-results/deployment-readiness/$RUN_PREFIX/d4/initial-sync.txt" ] ||
    die "D6 requires the active Identity canary"
  [ -s "$ROOT/test-results/deployment-readiness/$RUN_PREFIX/d5/rotation.txt" ] ||
    die "D6 requires the completed Federation journey and rotation"

  local guest_id channel_id body="${RUN_PREFIX}-d6-guest-collaboration"
  guest_id="$(psql_env "$A" "
    SELECT g.user_id FROM guest_accounts g
      JOIN users u ON u.id=g.user_id
     WHERE g.status='active' AND u.enabled
     ORDER BY g.user_id DESC LIMIT 1
  ")"
  [[ "$guest_id" =~ ^[1-9][0-9]*$ ]] || die "no active Guest fixture is available"

  psql_env "$A" "
    UPDATE feature_toggles SET enabled=true,updated_at=now()
     WHERE key='feature.guest_accounts';
  " >/dev/null
  [ "$(psql_env "$B" \
    "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")" = "f" ] ||
    die "Guest unexpectedly enabled on B"
  [ "$(psql_env "$C" \
    "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'")" = "f" ] ||
    die "Guest unexpectedly enabled on C"

  channel_id="$(psql_env "$A" "
    SELECT id FROM chat_channels WHERE name='${RUN_PREFIX}-d6-guest-channel'
    UNION ALL
    SELECT chat_channel_create(91000,'${RUN_PREFIX}-d6-guest-channel')
     WHERE NOT EXISTS (
       SELECT 1 FROM chat_channels WHERE name='${RUN_PREFIX}-d6-guest-channel'
     )
    LIMIT 1
  ")"
  psql_env "$A" "SELECT chat_member_add(91000,$channel_id,$guest_id)" >/dev/null
  if [ "$(psql_env "$A" \
    "SELECT count(*) FROM chat_messages WHERE channel_id=$channel_id AND body='$body'")" = "0" ]; then
    psql_env "$A" "SELECT chat_message_send($guest_id,$channel_id,'$body')" >/dev/null
  fi
  [ "$(psql_env "$A" "
    SELECT count(*) FROM chat_messages
     WHERE channel_id=$channel_id AND body='$body' AND author_id=$guest_id
  ")" = "1" ] || die "Guest collaboration message did not land exactly once"

  # A Guest-bearing channel must never become a federated room. Catch the
  # exact reducer code inside the database so a generic failure cannot pass.
  psql_env "$A" "
    DO \$block\$
    BEGIN
      PERFORM federation_room_create(91000,$channel_id,'org-a.test');
      RAISE EXCEPTION 'guest federation refusal missing';
    EXCEPTION
      WHEN SQLSTATE 'BZ216' THEN NULL;
    END
    \$block\$;
  " >/dev/null

  [ "$(psql_env "$A" \
    "SELECT count(*) FROM mailboxes WHERE user_id=$guest_id")" = "0" ] ||
    die "Guest acquired a mailbox during composition"
  [ "$(psql_env "$A" \
    "SELECT count(*) FROM user_identity_links WHERE user_id=$guest_id")" = "0" ] ||
    die "Guest entered normalized identity links during composition"
  [ "$(psql_env "$A" \
    "SELECT count(*) FROM user_lifecycle_authorities WHERE user_id=$guest_id")" = "0" ] ||
    die "Guest entered person lifecycle authority during composition"
  [ "$(psql_env "$A" "
    SELECT count(*) FROM feature_toggles
     WHERE key IN ('feature.guest_accounts','feature.identity_model_v2','feature.federation')
       AND enabled
  ")" = "3" ] || die "Guest, Identity model and Federation are not jointly enabled on A"

  {
    printf 'composition_features=guest+identity_model_v2+federation\n'
    printf 'guest_user_id=%s\n' "$guest_id"
    printf 'guest_collaboration_channel=%s\n' "$channel_id"
    printf 'guest_chat_message=PASS\n'
    printf 'guest_federation_refusal=BZ216\n'
    printf 'guest_mailboxes=0\n'
    printf 'guest_identity_links=0\n'
    printf 'guest_lifecycle_authorities=0\n'
    printf 'b_c_guest_toggle=OFF_OFF\n'
    printf 'composition_soak=RUNNING\n'
  } | tee "$EVIDENCE_DIR/prepare.txt"
  printf 'D6_PREPARE_PASS\n'
}

status_action() {
  psql_env "$A" "
    SELECT jsonb_build_object(
      'toggles',(SELECT jsonb_object_agg(key,enabled ORDER BY key)
                   FROM feature_toggles
                  WHERE key IN (
                    'feature.guest_accounts',
                    'feature.identity_model_v2',
                    'feature.identity_normalized_reads',
                    'feature.identity_transitions',
                    'feature.federation'
                  )),
      'guestIdentityLinks',(SELECT count(*) FROM user_identity_links l
                              JOIN guest_accounts g ON g.user_id=l.user_id),
      'guestLifecycleAuthorities',(
        SELECT count(*) FROM user_lifecycle_authorities a
          JOIN guest_accounts g ON g.user_id=a.user_id),
      'federationOutstanding',(
        SELECT count(*) FROM federation_outbox WHERE acked_at IS NULL)
    )
  "
}

cleanup_action() {
  psql_env "$A" "
    UPDATE feature_toggles SET enabled=false,updated_at=now()
     WHERE key='feature.guest_accounts';
  " >/dev/null
  printf 'd6_guest_toggle_restored_off=PASS\n'
}

validate
case "$ACTION" in
  (prepare) prepare_action ;;
  (status) status_action ;;
  (cleanup) cleanup_action ;;
esac
