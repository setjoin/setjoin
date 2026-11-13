#!/usr/bin/env bash
# CONTRACT: worker-launch-inventory
# Verifies the AST-derived launch golden, reviewed semantics matrix, and the
# semantics-neutral launchWorker lifecycle behavior.
source "$(dirname "$0")/_base.sh"

usage() {
  echo "usage: check-worker-launch-inventory.sh [--self-test|--help]"
}

run_tests() {
  (
    cd "$ROOT"
    go test ./mailserver/cmd/mailserverd \
      -run 'TestLaunchWorker|TestWorkerLaunchInventory|TestWorkerSemantics' \
      -count=1
  )
}

case "${1:-}" in
  --help) usage ;;
  --self-test)
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    awk '/10\. Graceful shutdown/ { print "\tgo plantedWorker.Run(ctx)" } { print }' \
      "$ROOT/mailserver/cmd/mailserverd/main.go" > "$tmp/main.go"
    set +e
    output="$(
      cd "$ROOT"
      WORKER_LAUNCH_MAIN="$tmp/main.go" go test ./mailserver/cmd/mailserverd \
        -run '^TestWorkerLaunchInventoryGolden$' -count=1 2>&1
    )"
    rc=$?
    set -e
    if [[ "$rc" -eq 0 ]] || ! grep -Fq 'direct|plantedWorker.Run' <<<"$output"; then
      echo "check-worker-launch-inventory self-test: planted direct launch was not rejected" >&2
      echo "$output" >&2
      exit 1
    fi
    echo "E_WORKER_LAUNCH_DRIFT problem=planted_direct_launch cause=launch_bypasses_launchWorker value=plantedWorker.Run fix='route the worker through launchWorker with reviewed semantics' rerun='bash scripts/check-worker-launch-inventory.sh'" >&2
    echo "check-worker-launch-inventory self-test: PASS"
    ;;
  "")
    run_tests
    echo "check-worker-launch-inventory: PASS"
    ;;
  *) usage >&2; exit 2 ;;
esac
