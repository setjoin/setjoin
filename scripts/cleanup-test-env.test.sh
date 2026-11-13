#!/usr/bin/env bash
# SEC-TEMP-HYGIENE: cleanup-test-env.sh treats /tmp state as hostile data.
# Negative arms: a planted .pids is never sourced (no shell execution as the
# invoking account) and rm -rf never touches attacker-chosen trees; positive
# arm: a well-formed .pids still drives the kill path and the owned dir is
# removed. The database arm is always --keep-db so tests never touch a live
# mailserver_test, and SETJOIN_TEST_ENV_DIR keeps every arm sandboxed.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

CLEANUP="$ROOT/scripts/cleanup-test-env.sh"
[[ -f "$CLEANUP" ]] || {
  echo 'E_SEC_CLEANUP target script missing' >&2
  exit 1
}
grep -Fq 'SETJOIN_TEST_ENV_DIR:-/tmp/setjoin-test' "$CLEANUP" || {
  echo 'E_SEC_CLEANUP default TEST_DIR changed' >&2
  exit 1
}

sandbox="$(mktemp -d)"
trap 'rm -rf "$sandbox"' EXIT
env_dir="$sandbox/env"

run_cleanup() {
  SETJOIN_TEST_ENV_DIR="$env_dir" bash "$CLEANUP" --keep-db
}

# ── Arm 1: world-writable .pids with hostile content is refused, nothing executes ──
mkdir -p "$env_dir" "$sandbox/canary-victim"
echo victim >"$sandbox/canary-victim/data"
cat >"$env_dir/.pids" <<EOF
touch $sandbox/pwned-1
TEST_DIR=$sandbox/canary-victim
GW_PID=1; rm -rf $sandbox/canary-victim
EOF
chmod 0666 "$env_dir/.pids"
out="$(run_cleanup 2>&1)" || {
  echo "E_SEC_CLEANUP hostile .pids made cleanup fail: $out" >&2
  exit 1
}
grep -q 'not owned by uid\|group/world-writable' <<<"$out" || {
  echo "E_SEC_CLEANUP world-writable .pids not refused loudly: $out" >&2
  exit 1
}
[[ ! -e "$sandbox/pwned-1" ]] || {
  echo 'E_SEC_CLEANUP hostile .pids was sourced/executed' >&2
  exit 1
}
[[ -f "$sandbox/canary-victim/data" ]] || {
  echo 'E_SEC_CLEANUP attacker-chosen tree was rm -rf-ed' >&2
  exit 1
}

# ── Arm 2: valid owner/mode but non-conforming grammar is refused ──
mkdir -p "$env_dir"
cat >"$env_dir/.pids" <<EOF
GW_PID=999; touch $sandbox/pwned-2
EVIL=\$(touch $sandbox/pwned-2)
EOF
chmod 0644 "$env_dir/.pids"
out="$(run_cleanup 2>&1)" || {
  echo "E_SEC_CLEANUP grammar-hostile .pids made cleanup fail: $out" >&2
  exit 1
}
grep -q 'expected KEY=<pid> lines only' <<<"$out" || {
  echo "E_SEC_CLEANUP non-conforming .pids grammar not refused: $out" >&2
  exit 1
}
[[ ! -e "$sandbox/pwned-2" ]] || {
  echo 'E_SEC_CLEANUP .pids content was evaluated' >&2
  exit 1
}

# ── Arm 3: symlinked .pids is refused before any read ──
mkdir -p "$env_dir"
cat >"$sandbox/outside-pids" <<EOF
AUTH_PID=\$(touch $sandbox/pwned-3)
EOF
chmod 0644 "$sandbox/outside-pids"
ln -s "$sandbox/outside-pids" "$env_dir/.pids"
out="$(run_cleanup 2>&1)" || {
  echo "E_SEC_CLEANUP symlinked .pids made cleanup fail: $out" >&2
  exit 1
}
grep -q 'symlinked' <<<"$out" || {
  echo "E_SEC_CLEANUP symlinked .pids not refused: $out" >&2
  exit 1
}
[[ ! -e "$sandbox/pwned-3" ]] || {
  echo 'E_SEC_CLEANUP symlink target was sourced' >&2
  exit 1
}
rm -rf "$env_dir" "$sandbox/outside-pids"

# ── Arm 4: well-formed .pids drives the kill path; owned dir is removed ──
mkdir -p "$env_dir"
cat >"$env_dir/mailserverd" <<'EOF'
#!/bin/sh
sleep 300
EOF
chmod 0755 "$env_dir/mailserverd"
"$env_dir/mailserverd" &
fake_pid=$!
printf 'GW_PID=%s\n' "$fake_pid" >"$env_dir/.pids"
chmod 0644 "$env_dir/.pids"
out="$(run_cleanup 2>&1)" || {
  echo "E_SEC_CLEANUP valid .pids made cleanup fail: $out" >&2
  exit 1
}
if kill -0 "$fake_pid" 2>/dev/null; then
  echo 'E_SEC_CLEANUP recorded PID was not killed on the happy path' >&2
  exit 1
fi
grep -q "Killed GW_PID ($fake_pid)" <<<"$out" || {
  echo "E_SEC_CLEANUP happy-path kill not reported: $out" >&2
  exit 1
}
grep -q "Removed $env_dir" <<<"$out" || {
  echo "E_SEC_CLEANUP owned dir not removed: $out" >&2
  exit 1
}
[[ ! -e "$env_dir" ]] || {
  echo 'E_SEC_CLEANUP owned dir still present' >&2
  exit 1
}
wait "$fake_pid" 2>/dev/null || true

# ── Arm 5: absent state takes the confined kill-by-name fallback harmlessly ──
out="$(run_cleanup 2>&1)" || {
  echo "E_SEC_CLEANUP fallback path failed: $out" >&2
  exit 1
}
grep -q "Nothing to remove at $env_dir" <<<"$out" || {
  echo "E_SEC_CLEANUP absent dir not handled: $out" >&2
  exit 1
}

# ── Arm 6 (root only): a foreign-owned TEST_DIR is never rm -rf-ed ──
if [[ "$(id -u)" == "0" ]]; then
  mkdir -p "$env_dir"
  echo planted >"$env_dir/planted"
  chown -R nobody "$env_dir"
  out="$(run_cleanup 2>&1)" || {
    echo "E_SEC_CLEANUP foreign-owned dir made cleanup fail: $out" >&2
    exit 1
  }
  grep -q "not owned by uid 0" <<<"$out" || {
    echo "E_SEC_CLEANUP foreign-owned dir not refused: $out" >&2
    exit 1
  }
  [[ -f "$env_dir/planted" ]] || {
    echo 'E_SEC_CLEANUP foreign-owned dir was removed' >&2
    exit 1
  }
fi

echo 'security cleanup-test-env: PASS (hostile/symlink/grammar .pids refused without execution, rm -rf confined, happy path intact)'
