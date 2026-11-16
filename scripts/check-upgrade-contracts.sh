#!/usr/bin/env bash
# Transactional-updater route, CLI, documentation, recovery, and OFF-gate guard.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUIDE="${UPGRADE_GUIDE:-$ROOT/docs/guides/UPGRADE.md}"
RECOVERY_GUIDE="${UPGRADE_RECOVERY_GUIDE:-$ROOT/docs/guides/UPGRADE_RECOVERY.md}"
RESTORE_GUIDE="${RESTORE_REHEARSAL_GUIDE:-$ROOT/docs/guides/RESTORE_REHEARSAL.md}"
REHEARSAL="$ROOT/scripts/transactional-updater-rehearsal.sh"
CONTINUITY_REHEARSAL="$ROOT/scripts/transactional-upgrade-rehearsal.sh"
REWIND_REHEARSAL="$ROOT/scripts/transactional-continuity-rewind.sh"
MOBILE_PROBE="$ROOT/clients/desktop/src-tauri/src/bridge_js.rs"
MOBILE_HARNESS="$ROOT/clients/desktop/scripts/mobile-e2e.sh"
CONTINUITY_VERIFICATION="${CONTINUITY_VERIFICATION:-$ROOT/docs/verification/2026-08-02-transactional-continuity-u5-u8.md}"
REHEARSAL_CHARACTERIZATION="${REHEARSAL_CHARACTERIZATION:-$ROOT/docs/audit/architecture-r2-rehearsal-characterization.md}"

check_guide() {
  local guide="$1"
  local failed=0
  local required=(
    "database-only emergency dump"
    "does not capture SeaweedFS/S3 mail or"
    "not a unified point-in-time recovery set or restore proof"
    "mailctl backup create --pre-upgrade"
    "mailctl backup verify --pre-upgrade"
    "Exit \`0\` with \`status=verified\` is the install gate"
    "RESTORE_REHEARSAL.md"
    "managed-layout Admin Portal is the release-first authorization and observation"
    "root-owned execution config all permit it"
    "installations seed those gates OFF"
    "retired System-page binary-path handler"
    "sudo /opt/setjoin/deploy/scripts/upgrade.sh /tmp/mailserverd /tmp/mailctl"
  )

  for phrase in "${required[@]}"; do
    if ! grep -Fq "$phrase" "$guide"; then
      echo "[upgrade-contract] $guide is missing required wording: $phrase" >&2
      failed=1
    fi
  done
  return "$failed"
}

check_restore_guide() {
  local guide="$1"
  local failed=0
  local required=(
    "newly created PostgreSQL **cluster**"
    "system_identifier"
    "production endpoints remain unreachable/absent"
    "POST /api/admin/system/upgrades/restore-proofs"
    "successful backup never implies a successful restore"
    "mailctl backup verify --pre-upgrade"
  )
  for phrase in "${required[@]}"; do
    if ! grep -Fq "$phrase" "$guide"; then
      echo "[upgrade-contract] $guide is missing required wording: $phrase" >&2
      failed=1
    fi
  done
  return "$failed"
}

check_recovery_guide() {
  local guide="$1"
  local failed=0
  local required=(
    "Never restore PostgreSQL"
    "recovery_required"
    "Application recovery is a separate, destructive incident"
    "snapshots are optional"
    "/var/lib/setjoin-updater/journal/events.jsonl"
    "/opt/setjoin/current/share/docs/UPGRADE_RECOVERY.md"
    "/usr/libexec/setjoin-recovery activate-previous"
    "upgrade_intent_recover"
  )
  for phrase in "${required[@]}"; do
    if ! grep -Fq "$phrase" "$guide"; then
      echo "[upgrade-contract] $guide is missing required wording: $phrase" >&2
      failed=1
    fi
  done
  return "$failed"
}

check_rehearsal_u8_eligibility() {
  local gate row status open=""
  for gate in \
    "Physical iOS device" \
    "Physical Android device" \
    "First-use operator timing drill"; do
    row="$(grep -E "^\| $gate \| (OPEN|CLOSED) \|" "$CONTINUITY_VERIFICATION" || true)"
    if [ -z "$row" ]; then
      open="${open}${open:+, }$gate (missing)"
      continue
    fi
    status="$(printf '%s\n' "$row" | awk -F'|' '{gsub(/^ +| +$/, "", $3); print $3}')"
    if [ "$status" != "CLOSED" ]; then
      open="${open}${open:+, }$gate ($status)"
    fi
  done
  if [ -n "$open" ]; then
    echo "rehearsal_u8_hold_open: $open" >&2
    return 1
  fi
  echo "rehearsal_u8_hold_closed: physical iOS, physical Android, and independent-operator timing evidence are CLOSED"
}

check_rehearsal_characterization() {
  local phrase failed=0
  for phrase in \
    '## Duplication and authority matrix' \
    'Prefix validation' \
    'Resource naming' \
    'Subnet and port allocation' \
    'Remote execution/copy' \
    'Evidence roots' \
    'Resume markers' \
    'Receipt encoding' \
    'Cleanup' \
    'Secrets/redaction' \
    'scripts/unified-deployment-readiness.sh' \
    'scripts/transactional-updater-rehearsal.sh' \
    'scripts/transactional-upgrade-rehearsal.sh' \
    'scripts/transactional-continuity-rewind.sh' \
    'No generic SSH/SCP or arbitrary-command abstraction'; do
    if ! grep -Fq "$phrase" "$REHEARSAL_CHARACTERIZATION"; then
      echo "[upgrade-contract] rehearsal characterization is missing: $phrase" >&2
      failed=1
    fi
  done
  return "$failed"
}

if [ "${1:-}" = "--rehearsal-extraction-eligible" ]; then
  [ "$#" -eq 1 ] || { echo "usage: scripts/check-upgrade-contracts.sh [--self-test|--rehearsal-extraction-eligible]" >&2; exit 2; }
  check_rehearsal_u8_eligibility
  exit
fi

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  printf '%s\n' '# deliberately incomplete upgrade guide' > "$tmp/UPGRADE.md"
  printf '%s\n' '# deliberately incomplete recovery guide' > "$tmp/UPGRADE_RECOVERY.md"
  printf '%s\n' '# deliberately incomplete restore guide' > "$tmp/RESTORE_REHEARSAL.md"
  printf '%s\n' '# deliberately incomplete rehearsal characterization' > "$tmp/REHEARSAL.md"
  if check_guide "$tmp/UPGRADE.md" >/dev/null 2>&1; then
    echo "upgrade contract self-test failed: incomplete guide passed" >&2
    exit 1
  fi
  if check_recovery_guide "$tmp/UPGRADE_RECOVERY.md" >/dev/null 2>&1; then
    echo "upgrade contract self-test failed: incomplete recovery guide passed" >&2
    exit 1
  fi
  if check_restore_guide "$tmp/RESTORE_REHEARSAL.md" >/dev/null 2>&1; then
    echo "upgrade contract self-test failed: incomplete restore guide passed" >&2
    exit 1
  fi
  original_characterization="$REHEARSAL_CHARACTERIZATION"
  REHEARSAL_CHARACTERIZATION="$tmp/REHEARSAL.md"
  if check_rehearsal_characterization >/dev/null 2>&1; then
    echo "upgrade contract self-test failed: incomplete rehearsal characterization passed" >&2
    exit 1
  fi
  REHEARSAL_CHARACTERIZATION="$original_characterization"
  printf '%s\n' \
    '| Physical iOS device | OPEN | fixture |' \
    '| Physical Android device | OPEN | fixture |' \
    '| First-use operator timing drill | OPEN | fixture |' > "$tmp/u8-open.md"
  CONTINUITY_VERIFICATION="$tmp/u8-open.md"
  hold_output="$(check_rehearsal_u8_eligibility 2>&1 || true)"
  for gate in "Physical iOS device" "Physical Android device" "First-use operator timing drill"; do
    grep -Fq "$gate (OPEN)" <<<"$hold_output" || {
      echo "upgrade contract self-test failed: open hold omitted $gate" >&2
      exit 1
    }
  done
  printf '%s\n' \
    '| Physical iOS device | CLOSED | fixture |' \
    '| Physical Android device | CLOSED | fixture |' \
    '| First-use operator timing drill | CLOSED | fixture |' > "$tmp/u8-closed.md"
  CONTINUITY_VERIFICATION="$tmp/u8-closed.md"
  check_rehearsal_u8_eligibility >/dev/null || {
    echo "upgrade contract self-test failed: closed U8 fixture remained held" >&2
    exit 1
  }
  printf '%s\n' '| Physical iOS device | CLOSED | fixture |' > "$tmp/u8-missing.md"
  CONTINUITY_VERIFICATION="$tmp/u8-missing.md"
  if check_rehearsal_u8_eligibility >/dev/null 2>&1; then
    echo "upgrade contract self-test failed: missing U8 rows passed" >&2
    exit 1
  fi
  echo "E_UPGRADE_CONTRACT_DRIFT problem=planted_incomplete_contract cause=required_U8_or_recovery_evidence_missing value=self-test-fixture fix='restore every named contract row and recovery instruction' rerun='bash scripts/check-upgrade-contracts.sh'" >&2
  echo "upgrade contract self-test passed"
  exit 0
fi

if [ "$#" -ne 0 ]; then
  echo "usage: scripts/check-upgrade-contracts.sh [--self-test|--rehearsal-extraction-eligible]" >&2
  exit 2
fi

check_guide "$GUIDE"
check_recovery_guide "$RECOVERY_GUIDE"
check_restore_guide "$RESTORE_GUIDE"
check_rehearsal_characterization

routes=(
  "/admin/system/upgrades"
  "/admin/system/upgrades/preview"
  "/admin/system/upgrades/challenges"
  "/admin/system/upgrades/challenges/complete"
  "/admin/system/upgrades/intents"
  "/admin/system/upgrades/intents/{id}"
  "/admin/system/upgrades/intents/{id}/cancel"
  "/admin/system/upgrades/intents/{id}/diagnostics"
  "/admin/system/upgrades/recovery-context"
  "/admin/system/upgrades/recovery-sets"
  "/admin/system/upgrades/restore-proofs"
  "/admin/system/recovery/incidents"
  "/admin/system/recovery/signals"
  "/recovery/incidents"
  "/recovery/uploads"
)
for route in "${routes[@]}"; do
  grep -Fq "$route" "$ROOT/mailserver/cmd/mailserverd/main.go" || {
    echo "[upgrade-contract] route registry missing $route" >&2; exit 1;
  }
  grep -Fq "/api$route:" "$ROOT/mailserver/api/openapi.yaml" || {
    echo "[upgrade-contract] OpenAPI missing /api$route" >&2; exit 1;
  }
done

for client_route in \
  /admin/system/upgrades \
  /admin/system/upgrades/preview \
  /admin/system/upgrades/challenges \
  /admin/system/upgrades/challenges/complete \
  /admin/system/upgrades/intents; do
  grep -Fq "$client_route" "$ROOT/mailserver/webmail/src/lib/admin/client.ts" || {
    echo "[upgrade-contract] typed web client missing $client_route" >&2; exit 1;
  }
done

backup_help="$(cd "$ROOT/mailctl" && go run . backup -h)"
upgrade_help="$(cd "$ROOT/mailctl" && go run . upgrade -h)"
for token in "create --pre-upgrade" "verify --pre-upgrade"; do
  grep -Fq "$token" <<<"$backup_help" || {
    echo "[upgrade-contract] mailctl backup --help missing $token" >&2; exit 1;
  }
done
for token in status watch cancel history diagnostics; do
  grep -Eq "(^|[ |])$token([ |<]|$)" <<<"$upgrade_help" || {
    echo "[upgrade-contract] mailctl upgrade --help missing $token" >&2; exit 1;
  }
done
if grep -Eq 'upgrade (check|apply|rollback)|binary[_ -]?path' <<<"$upgrade_help"; then
  echo "[upgrade-contract] retired caller-owned upgrade mutation returned to CLI help" >&2
  exit 1
fi
grep -Fq 'DB_DIRECT_OWNER_DSN="$DB_DIRECT_DSN"' \
  "$ROOT/mailserver/deploy/scripts/install.sh" || {
  echo "[upgrade-contract] installer does not initialize the updater owner DSN before rendering its credential" >&2
  exit 1
}
for installer_contract in \
  '_INSTALL_UMASK="$(umask)"' \
  'umask "$_INSTALL_UMASK"' \
  'chown root:root "$INSTALL_DIR"' \
  'chmod 0755 "$INSTALL_DIR/releases"'; do
  grep -Fq "$installer_contract" "$ROOT/mailserver/deploy/scripts/install.sh" || {
    echo "[upgrade-contract] installer omits immutable runtime traversal contract: $installer_contract" >&2
    exit 1
  }
done
if grep -Eq "'feature\.transactional_upgrades_(catalog|execution)',[[:space:]]*true" \
  "$ROOT/mailserver/sql/dbschema/V178__transactional_upgrade_control.sql"; then
  echo "[upgrade-contract] transactional-upgrade rollout flag is seeded ON" >&2
  exit 1
fi
if grep -Eq "'feature\.client_recovery_(receipts|cache|ingest)',[[:space:]]*true" \
  "$ROOT/mailserver/sql/dbschema/V178__transactional_upgrade_control.sql"; then
  echo "[upgrade-contract] client-assisted recovery rollout flag is seeded ON" >&2
  exit 1
fi
verification="$ROOT/docs/verification/2026-08-01-transactional-updater-u3-u4-local.md"
for gate in \
  "Ubuntu same-set isolated restore" \
  "Ubuntu updater switch and rollback" \
  "Browser dangerous-state matrix" \
  "Final independent review"; do
  grep -Eq "^\\| $gate \\| (OPEN|CLOSED) \\|" "$verification" || {
    echo "[upgrade-contract] structured U3/U4 gate is missing: $gate" >&2; exit 1;
  }
done
bash "$REHEARSAL" self-test >/dev/null
RUN_PREFIX=continuity-contract bash "$CONTINUITY_REHEARSAL" self-test >/dev/null
RUN_PREFIX=rewind-contract bash "$REWIND_REHEARSAL" self-test >/dev/null
for contract in \
  'full)' \
  'rewind)' \
  'physical_device_gate=OPEN' \
  'scripts/unified-deployment-readiness.sh" cleanup'; do
  grep -Fq "$contract" "$CONTINUITY_REHEARSAL" || {
    echo "[upgrade-contract] U5-U8 rehearsal is missing: $contract" >&2; exit 1;
  }
done
for contract in \
  'portable_complete_machine_rewind=PASS' \
  'database_config_object_index_updater_release_continuity=RESTORED' \
  'adversarial_receipt=REJECTED' \
  'terminal_client_recovery_flags=OFF' \
  'clamav-daemon clamav-freshclam clamdscan' \
  'command -v clamdscan' \
  'ListenStream=127.0.0.1:3310' \
  "c.relpersistence='u'" \
  '--exclude-table-data=public.health_history' \
  '--exclude-table-data=public.threat_feed_blocks' \
  'baseline-threat-feed.sha256' \
  'REWIND_ATTEMPT' \
  'restored-minio-offline.sha256' \
  'egress-podman-storage.tar' \
  'machine-rootfs.tar' \
  'tar --one-file-system --xattrs --acls --numeric-owner' \
  'setjoin-ga-smoke-base:v6' \
  '--change '\''ENTRYPOINT ["/sbin/init"]'\''' \
  '--change '\''CMD []'\''' \
  '/usr/bin/podman system reset --force' \
  'restored Egress image identity differs from baseline' \
  'digest-less Egress cache does not contain exactly one image identity' \
  'docker image rm -f "$SNAPSHOT_IMAGE"' \
  'docker volume rm -f "$SNAPSHOT_VOLUME"'; do
  grep -Fq -- "$contract" "$REWIND_REHEARSAL" || {
    echo "[upgrade-contract] portable rewind rehearsal is missing: $contract" >&2; exit 1;
  }
done
grep -Fq 'find "$SNAPSHOT_DIR" -type f -delete' "$REWIND_REHEARSAL" || {
  echo "[upgrade-contract] portable rewind cleanup retains private client evidence" >&2; exit 1;
}
for contract in \
  "phase: 'restart-required'" \
  'recoveryBlob.resume:' \
  'recoveryBlob.restart-read' \
  "phase: 'complete'"; do
  grep -Fq "$contract" "$MOBILE_PROBE" || {
    echo "[upgrade-contract] mobile recovery probe is missing: $contract" >&2; exit 1;
  }
done
for contract in \
  'restart-phase.json' \
  'simctl terminate' \
  'am force-stop' \
  'restart_resume: PASS'; do
  grep -Fq "$contract" "$MOBILE_HARNESS" || {
    echo "[upgrade-contract] mobile restart/resume harness is missing: $contract" >&2; exit 1;
  }
done
masked_cleanup='bash "$ROOT/scripts/transactional-updater-rehearsal.sh" cleanup'
masked_cleanup="$masked_cleanup || true"
if grep -F "$masked_cleanup" "$CONTINUITY_REHEARSAL" >/dev/null; then
  echo "[upgrade-contract] U5-U8 cleanup masks updater cleanup failure" >&2
  exit 1
fi
for contract in \
  'backup create --pre-upgrade' \
  'backup verify --pre-upgrade' \
  'unified-deployment-d2.sh" restore-current' \
  'BACKUP_PROVIDER=s3' \
  'systemctl restart setjoin' \
  'go build -o "$source_runtime/mailserverd" ./cmd/mailserverd' \
  'feature.transactional_upgrades_execution' \
  'wait_for_state "$rollback_id" rolled_back' \
  'terminal_off'; do
  grep -Fq "$contract" "$REHEARSAL" || {
    echo "[upgrade-contract] updater rehearsal is missing: $contract" >&2; exit 1;
  }
done
grep -Fq -- '--reason '\''verify disposable U3 application recovery point'\'' --json \' "$REHEARSAL" || {
  echo "[upgrade-contract] recovery verification flags are not placed before the positional set ID" >&2
  exit 1
}
if sed -n '/docker exec -i "$A" bash -s -- "$release_id" "$source_version"/,/^INNER$/p' "$REHEARSAL" |
    grep -Fq 'jq '; then
  echo "[upgrade-contract] release seeding depends on jq inside the minimal Ubuntu target" >&2
  exit 1
fi
bash "$ROOT/mailserver/deploy/scripts/test-updater-render.sh" >/dev/null
bash "$ROOT/mailserver/deploy/scripts/test-setjoin-lifecycle.sh" >/dev/null
bash "$ROOT/mailserver/deploy/scripts/test-upgrade-rollback.sh" >/dev/null
bash "$ROOT/mailserver/deploy/scripts/test-install-front-door.sh" >/dev/null
bash "$ROOT/mailserver/deploy/scripts/test-imap-sockets.sh" >/dev/null
for lifecycle_contract in \
  'install -o root -g root -m 0755' \
  '/usr/local/sbin/setjoinctl restart'; do
  grep -Fq "$lifecycle_contract" "$ROOT/mailserver/deploy/scripts/install.sh" || {
    echo "[upgrade-contract] installer does not use the fixed lifecycle controller: $lifecycle_contract" >&2
    exit 1
  }
done
grep -Fq 'Data purge is intentionally not implemented by this command.' \
  "$ROOT/mailserver/deploy/scripts/setjoin-lifecycle.sh" || {
  echo "[upgrade-contract] lifecycle uninstall no longer fails closed around customer data" >&2
  exit 1
}
continuity_verification="$CONTINUITY_VERIFICATION"
for gate in \
  "Physical iOS device" \
  "Physical Android device" \
  "U8 full-program gate"; do
  grep -Eq "^\\| $gate \\| (OPEN|CLOSED) \\|" "$continuity_verification" || {
    echo "[upgrade-contract] structured U5/U8 gate is missing: $gate" >&2; exit 1;
  }
done
if grep -Eq '^\| Physical (iOS|Android) device \| OPEN \|' "$continuity_verification"; then
  grep -Eq "'feature\.client_recovery_(cache|ingest)',[[:space:]]*false" \
    "$ROOT/mailserver/sql/dbschema/V178__transactional_upgrade_control.sql" || {
      echo "[upgrade-contract] physical-device gate is OPEN but continuity flags are not pinned OFF" >&2; exit 1;
    }
fi
check_rehearsal_u8_eligibility || true
grep -Fq 'ExecStart={{RUNTIME_DIR}}/mailserverd' "$ROOT/mailserver/deploy/mailserver.service.template" || {
  echo "[upgrade-contract] gateway unit does not execute immutable current" >&2; exit 1;
}
grep -Fq 'ExecStart={{RUNTIME_DIR}}/setjoin-auth' "$ROOT/mailserver/deploy/authserver.service.template" || {
  echo "[upgrade-contract] auth unit does not execute the Rust setjoin-auth in immutable current" >&2; exit 1;
}
grep -Fq 'ExecStart={{RUNTIME_DIR}}/authserverd' "$ROOT/mailserver/deploy/setjoin-authserverd.service.template" || {
  echo "[upgrade-contract] transitional authserverd unit does not execute immutable current" >&2; exit 1;
}
grep -Fq 'PartOf=setjoin-auth.service' "$ROOT/mailserver/deploy/setjoin-authserverd.service.template" || {
  echo "[upgrade-contract] transitional authserverd must follow setjoin-auth's lifecycle" >&2; exit 1;
}
! grep -Eq '^EnvironmentFile=\{\{DB_CREDENTIALS_FILE\}\}' "$ROOT/mailserver/deploy/authserver.service.template" || {
  echo "[upgrade-contract] the Rust auth unit must not load the privileged credential file" >&2; exit 1;
}
! grep -Eq 'auth/login' "$ROOT/mailserver/deploy/authserver.service.template" || {
  echo "[upgrade-contract] auth readiness must not send credential requests (captcha/tarpit lockout)" >&2; exit 1;
}
grep -Fq 'release must contain exactly one recovery guide artifact' "$ROOT/shared/release/manifest.go" || {
  echo "[upgrade-contract] release schema does not require the recovery guide" >&2; exit 1;
}
grep -Fq 'adopt-current-layout' "$ROOT/mailserver/deploy/scripts/install.sh" || {
  echo "[upgrade-contract] installer does not adopt the immutable layout" >&2; exit 1;
}
grep -Fq 'install_release_roots' "$ROOT/mailserver/deploy/scripts/install.sh" || {
  echo "[upgrade-contract] installer does not deliver release trust roots before adoption" >&2; exit 1;
}
grep -Fq 'positional artifact-copy upgrades are disabled' "$ROOT/mailserver/deploy/scripts/upgrade.sh" || {
  echo "[upgrade-contract] adopted layout can still enter legacy artifact copy" >&2; exit 1;
}
grep -Fq 'go-module-catalog.mjs" artifacts' "$ROOT/scripts/build.sh" || {
  echo "[upgrade-contract] build front door does not consume the fixed module catalog" >&2; exit 1;
}
node "$ROOT/scripts/go-module-catalog.mjs" artifacts | awk -F '\t' \
  '$1 == "mailserver" && $6 == "./cmd/setjoin-recovery" && $7 == "setjoin-recovery" { found=1 } END { exit !found }' || {
  echo "[upgrade-contract] fixed recovery helper is absent from the build capability catalog" >&2; exit 1;
}
for unit_template in \
  "$ROOT/mailserver/deploy/mailserver.service.template" \
  "$ROOT/mailserver/deploy/authserver.service.template" \
  "$ROOT/mailserver/deploy/setjoin-authserverd.service.template"; do
  # Exposure means an ACTIVE unit line carrying a privileged DSN (an
  # Environment= assignment or a rendered/interpolated credential) — not a
  # comment naming the variables. The DEPLOY-004 split (b07736bdd) documents
  # its root-owned 0600 DB_CREDENTIALS_FILE design in template comments;
  # owner/worker DSN values reach the unit only through that EnvironmentFile,
  # which is the isolation this contract exists to enforce.
  if grep -Ev '^[[:space:]]*#' "$unit_template" | \
      grep -Eq 'DB_OWNER_DSN|DB_UPDATER_DSN|UPDATER_DSN'; then
    echo "[upgrade-contract] gateway/auth unit exposes owner or updater DSN: $unit_template" >&2
    exit 1
  fi
done
echo "upgrade contracts: U-1 through deterministic U7 plus U8 OFF/hardware gates, routes, lifecycle, guides, immutable layout, and units passed"
