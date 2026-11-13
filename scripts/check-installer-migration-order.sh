#!/usr/bin/env bash
# Guard the single-node upgrade ordering that a real V149 -> V177 rehearsal
# exposed: the matching mailctl must apply pending migrations before current
# reducers are loaded. It also keeps mailctl in the build/install artifact set,
# so a clean or partially-built checkout cannot silently reuse a stale binary.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INSTALLER="${INSTALLER_MIGRATION_ORDER_FILE:-$ROOT/mailserver/deploy/scripts/install.sh}"

run_check() {
  local file="$1" migration_line reducer_line group_line user_line continuity_chown_line failed=0
  if [ ! -f "$file" ]; then
    echo "installer-migration-order: missing installer: $file" >&2
    return 1
  fi

  migration_line="$(grep -nF '"$ROOT/mailctl/mailctl" schema apply --yes' "$file" | head -1 | cut -d: -f1 || true)"
  reducer_line="$(grep -nF 'bash "$ROOT/scripts/reload-reducers.sh"' "$file" | head -1 | cut -d: -f1 || true)"
  if [ -z "$migration_line" ] || [ -z "$reducer_line" ] || [ "$migration_line" -ge "$reducer_line" ]; then
    echo "installer-migration-order: matching mailctl must apply pending migrations before reducer reload" >&2
    failed=1
  fi
  grep -Fq '[ ! -x "$ROOT/mailctl/mailctl" ]' "$file" || {
    echo "installer-migration-order: build preflight does not require the matching mailctl" >&2
    failed=1
  }
  grep -Fq 'install -m 0755 "$ROOT/mailctl/mailctl"' "$file" || {
    echo "installer-migration-order: install artifacts omit mailctl" >&2
    failed=1
  }
  group_line="$(grep -nF 'getent group setjoin >/dev/null 2>&1 || groupadd -r setjoin' "$file" | head -1 | cut -d: -f1 || true)"
  user_line="$(grep -nF 'id -u setjoin >/dev/null 2>&1 || useradd -r -g setjoin' "$file" | head -1 | cut -d: -f1 || true)"
  continuity_chown_line="$(grep -nF 'chown root:setjoin "$CONTINUITY_SIGNING_KEY_FILE"' "$file" | head -1 | cut -d: -f1 || true)"
  if [ -z "$group_line" ] || [ -z "$user_line" ] || [ -z "$continuity_chown_line" ] ||
     [ "$group_line" -ge "$continuity_chown_line" ] || [ "$user_line" -ge "$continuity_chown_line" ]; then
    echo "installer-migration-order: explicit setjoin group and user must exist before continuity-key ownership" >&2
    failed=1
  fi
  [ "$failed" -eq 0 ]
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  cat >"$tmp/bad.sh" <<'EOF'
[ ! -x "$ROOT/mailctl/mailctl" ]
getent group setjoin >/dev/null 2>&1 || groupadd -r setjoin
id -u setjoin >/dev/null 2>&1 || useradd -r -g setjoin
chown root:setjoin "$CONTINUITY_SIGNING_KEY_FILE"
bash "$ROOT/scripts/reload-reducers.sh"
"$ROOT/mailctl/mailctl" schema apply --yes
install -m 0755 "$ROOT/mailctl/mailctl" "$INSTALL_DIR/mailctl"
EOF
  if run_check "$tmp/bad.sh" >/dev/null 2>&1; then
    echo "installer-migration-order self-test: accepted reducers before migrations" >&2
    exit 1
  fi
  cat >"$tmp/bad-identity.sh" <<'EOF'
[ ! -x "$ROOT/mailctl/mailctl" ]
"$ROOT/mailctl/mailctl" schema apply --yes
bash "$ROOT/scripts/reload-reducers.sh"
chown root:setjoin "$CONTINUITY_SIGNING_KEY_FILE"
getent group setjoin >/dev/null 2>&1 || groupadd -r setjoin
id -u setjoin >/dev/null 2>&1 || useradd -r -g setjoin
install -m 0755 "$ROOT/mailctl/mailctl" "$INSTALL_DIR/mailctl"
EOF
  if run_check "$tmp/bad-identity.sh" >/dev/null 2>&1; then
    echo "installer-migration-order self-test: accepted continuity-key ownership before runtime identity" >&2
    exit 1
  fi
  cat >"$tmp/good.sh" <<'EOF'
[ ! -x "$ROOT/mailctl/mailctl" ]
getent group setjoin >/dev/null 2>&1 || groupadd -r setjoin
id -u setjoin >/dev/null 2>&1 || useradd -r -g setjoin
chown root:setjoin "$CONTINUITY_SIGNING_KEY_FILE"
"$ROOT/mailctl/mailctl" schema apply --yes
bash "$ROOT/scripts/reload-reducers.sh"
install -m 0755 "$ROOT/mailctl/mailctl" "$INSTALL_DIR/mailctl"
EOF
  run_check "$tmp/good.sh"
  echo "installer-migration-order self-test: PASS"
  exit 0
fi

if [ "$#" -ne 0 ]; then
  echo "usage: check-installer-migration-order.sh [--self-test]" >&2
  exit 2
fi

run_check "$INSTALLER"
echo "installer-migration-order: PASS"
