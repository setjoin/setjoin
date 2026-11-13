#!/usr/bin/env bash
# CONTRACT: architecture-r2-route-inventory
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MERGED_OUTPUT="${ROUTE_INVENTORY_MERGED_OUTPUT:-$ROOT/test-results/mailserver/route-inventory.json}"

usage() {
  cat <<'EOF'
Usage: bash scripts/check-route-inventory.sh [--self-test|--help]

Replays the six gateway registrars plus Drive, Chat, Meet, and SCIM package
registrars, atomically merges their runtime-derived route evidence, and checks
OpenAPI coverage and visibility. No database, listener, or network is used.
EOF
}

validate_artifact_set() {
  local evidence_dir="$1"
  local expected=(chat.json drive.json gateway.json meet.json scim.json)
  local actual=()
  shopt -s nullglob dotglob
  local entry
  for entry in "$evidence_dir"/*; do
    [[ -f "$entry" ]] || {
      echo "E_ROUTE_ARTIFACT_SET: unexpected non-file entry $entry" >&2
      return 1
    }
    actual+=("$(basename "$entry")")
  done
  shopt -u nullglob dotglob
  if [[ "${#actual[@]}" -ne "${#expected[@]}" ]]; then
    echo "E_ROUTE_ARTIFACT_SET: got ${#actual[@]} artifacts, want ${#expected[@]}" >&2
    printf '  actual: %s\n' "${actual[*]:-(none)}" >&2
    printf '  expected: %s\n' "${expected[*]}" >&2
    return 1
  fi
  local sorted
  sorted="$(printf '%s\n' "${actual[@]}" | LC_ALL=C sort)"
  if [[ "$sorted" != "$(printf '%s\n' "${expected[@]}")" ]]; then
    echo "E_ROUTE_ARTIFACT_SET: missing, duplicate, or wrongly prefixed owner artifact" >&2
    printf '  actual: %s\n' "$sorted" >&2
    printf '  expected: %s\n' "$(printf '%s\n' "${expected[@]}")" >&2
    return 1
  fi
}

emit_artifacts() {
  local evidence_dir="$1" run_id="$2"
  mkdir -p "$evidence_dir"
  chmod 700 "$evidence_dir"
  (
    cd "$ROOT/mailserver"
    ROUTE_INVENTORY_OUTPUT_DIR="$evidence_dir" ROUTE_INVENTORY_RUN_ID="$run_id" \
      go test ./cmd/mailserverd -run '^(TestRouteInventoryGolden|TestRouteInventoryEmit)$' -count=1
    ROUTE_INVENTORY_OUTPUT_DIR="$evidence_dir" ROUTE_INVENTORY_RUN_ID="$run_id" \
      go test ./internal/drive ./internal/chat ./internal/meet ./internal/scim \
        -run '^TestRouteInventoryEmit$' -count=1
  )
  validate_artifact_set "$evidence_dir"
}

merge_artifacts() {
  local evidence_dir="$1" output="$2"
  (
    cd "$ROOT/mailserver"
    ROUTE_INVENTORY_INPUT_DIR="$evidence_dir" ROUTE_INVENTORY_MERGED_OUTPUT="$output" \
      go test ./cmd/mailserverd -run '^TestRouteInventoryMerge$' -count=1
  )
}

run_guard() {
  local evidence_dir run_id
  evidence_dir="$(mktemp -d "${TMPDIR:-/tmp}/setjoin-route-inventory.XXXXXX")"
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM}"
  trap 'rm -rf "$evidence_dir"' RETURN
  emit_artifacts "$evidence_dir" "$run_id"
  merge_artifacts "$evidence_dir" "$MERGED_OUTPUT"
  ROUTE_INVENTORY_FILE="$MERGED_OUTPUT" bash "$ROOT/scripts/check-openapi-coverage.sh"
  ROUTE_INVENTORY_FILE="$MERGED_OUTPUT" bash "$ROOT/scripts/check-openapi-visibility.sh"
  local count
  count="$(node "$ROOT/scripts/route-inventory-json.mjs" routes "$MERGED_OUTPUT" | grep -c . | tr -d ' ')"
  echo "route-inventory: PASS ($count exact operations; gateway + Drive + Chat + Meet + SCIM)"
}

self_test() {
  local tmp evidence run_id merged
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/setjoin-route-inventory-selftest.XXXXXX")"
  trap 'rm -rf "$tmp"' RETURN
  evidence="$tmp/evidence"
  merged="$tmp/merged.json"
  run_id="selftest-$$-${RANDOM}"
  emit_artifacts "$evidence" "$run_id" >/dev/null
  merge_artifacts "$evidence" "$merged" >/dev/null

  mkdir "$tmp/missing"
  cp "$evidence"/chat.json "$evidence"/drive.json "$evidence"/gateway.json "$evidence"/scim.json "$tmp/missing/"
  if validate_artifact_set "$tmp/missing" >/dev/null 2>&1; then
    echo "route-inventory self-test: missing owner artifact was accepted" >&2
    return 1
  fi

  mkdir "$tmp/duplicate"
  cp "$evidence"/*.json "$tmp/duplicate/"
  cp "$evidence"/drive.json "$tmp/duplicate/drive-copy.json"
  if validate_artifact_set "$tmp/duplicate" >/dev/null 2>&1; then
    echo "route-inventory self-test: duplicate/wrong-prefix artifact was accepted" >&2
    return 1
  fi

  mkdir "$tmp/stale"
  cp "$evidence"/*.json "$tmp/stale/"
  sed -E 's/"run_id": "[^"]+"/"run_id": "stale-run"/' "$evidence/drive.json" > "$tmp/stale/drive.json"
  if merge_artifacts "$tmp/stale" "$tmp/stale-merged.json" >/dev/null 2>&1; then
    echo "route-inventory self-test: stale owner artifact was accepted" >&2
    return 1
  fi

  cp "$merged" "$tmp/planted.json"
  node -e '
    const fs = require("fs");
    const file = process.argv[1];
    const artifact = JSON.parse(fs.readFileSync(file, "utf8"));
    artifact.operations.push({
      method: "GET", path: "/drive/__route_inventory_selftest__",
      pattern: "GET /drive/__route_inventory_selftest__", owner: "drive",
      mount: "/drive/", middleware: "requireAuth", visibility: "public",
      satisfying_masks: ["00000"]
    });
    fs.writeFileSync(file, JSON.stringify(artifact));
  ' "$tmp/planted.json"
  local diagnostic="$tmp/diagnostic.txt"
  if ROUTE_INVENTORY_FILE="$tmp/planted.json" bash "$ROOT/scripts/check-openapi-coverage.sh" >"$diagnostic" 2>&1; then
    echo "route-inventory self-test: planted private route was accepted" >&2
    return 1
  fi
  if ! grep -q 'E_ROUTE_UNDOCUMENTED' "$diagnostic"; then
    echo "route-inventory self-test: planted failure omitted E_ROUTE_UNDOCUMENTED" >&2
    return 1
  fi
  cat "$diagnostic" >&2
  echo "route-inventory self-test: PASS (missing, duplicate, stale, and undocumented private route rejected)"
}

case "${1:-}" in
  "") run_guard ;;
  --self-test) self_test ;;
  --help) usage ;;
  *) usage >&2; exit 2 ;;
esac
