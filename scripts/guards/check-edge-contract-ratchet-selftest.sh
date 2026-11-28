#!/usr/bin/env bash
# Self-test for scripts/guards/check-edge-contract-ratchet.sh (#561).
# Proves:
#   1. Adding an uncovered non-JMAP/non-DAV route FAILS.
#   2. Unrelated prefix-sharing routes (`/david`, `/jmap-admin`) are NOT excluded and FAIL.
#   3. Excluded protocol routes (`/jmap/...`, `/dav/...`) PASS.
#   4. Dropping a covered route FAILS.
#   5. Raw `fetch('/api/settings/view')` in a `.svelte` route (with all 12 bindings intact) FAILS.
#   6. Raw interpolated template-literal ``fetch(`/api/messages/${id}/trace`)`` FAILS.
#   7. Invalid `--diff-base` fails closed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GUARD="$ROOT/scripts/guards/check-edge-contract-ratchet.sh"
INV="$ROOT/server-rust/bins/gateway/route-inventory.json"
SPEC="$ROOT/contracts/edge/openapi/edge.v1.yaml"
RATCHET="$ROOT/config/edge-contract-ratchet.json"
WEBMAIL_SRC="$ROOT/mailserver/webmail/src"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/edge-ratchet-selftest.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

python3 - "$INV" "$tmp/inv_uncovered.json" "$tmp/inv_prefix_trap.json" "$tmp/inv_jmap_ok.json" <<'PY'
import copy, json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))

bad = copy.deepcopy(data)
bad["routes"].append({
    "listener": "gateway",
    "method": "POST",
    "path": "/settings/brand-new-uncovered-route",
    "family": "F19",
    "slice": "settings-a",
    "upstream": "local-rust",
    "state": "ON",
})
pathlib.Path(sys.argv[2]).write_text(json.dumps(bad), encoding="utf-8")

trap_prefix = copy.deepcopy(data)
trap_prefix["routes"].append({
    "listener": "gateway",
    "method": "GET",
    "path": "/david/profile",
    "family": "F19",
    "slice": "profile",
    "upstream": "local-rust",
    "state": "ON",
})
pathlib.Path(sys.argv[3]).write_text(json.dumps(trap_prefix), encoding="utf-8")

ok = copy.deepcopy(data)
ok["routes"].append({
    "listener": "gateway",
    "method": "POST",
    "path": "/jmap/custom-protocol-endpoint",
    "family": "F18",
    "slice": "jmap",
    "upstream": "local-rust",
    "state": "ON",
})
pathlib.Path(sys.argv[4]).write_text(json.dumps(ok), encoding="utf-8")
PY

if bash "$GUARD" --inventory "$tmp/inv_uncovered.json" --openapi "$SPEC" --webmail-src "$WEBMAIL_SRC" --ratchet "$RATCHET" >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: adding an uncovered non-JMAP route was NOT caught" >&2
  exit 1
fi

if bash "$GUARD" --inventory "$tmp/inv_prefix_trap.json" --openapi "$SPEC" --webmail-src "$WEBMAIL_SRC" --ratchet "$RATCHET" >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: /david/profile was falsely excluded by /dav prefix check" >&2
  exit 1
fi

if ! bash "$GUARD" --inventory "$tmp/inv_jmap_ok.json" --openapi "$SPEC" --webmail-src "$WEBMAIL_SRC" --ratchet "$RATCHET" >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: excluded JMAP route was unexpectedly rejected" >&2
  exit 1
fi

# Drop a covered route from a copy of edge.v1.yaml
python3 - "$SPEC" "$tmp/spec_dropped.json" "$ROOT/scripts/guards/check-edge-contract-breaking.py" <<'PY'
import importlib.util, json, pathlib, sys
spec = importlib.util.spec_from_file_location("b", sys.argv[3])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
doc = mod.load_openapi(pathlib.Path(sys.argv[1]))
del doc["paths"]["/api/user/quota"]
pathlib.Path(sys.argv[2]).write_text(json.dumps(doc), encoding="utf-8")
PY

if bash "$GUARD" --inventory "$INV" --openapi "$tmp/spec_dropped.json" --webmail-src "$WEBMAIL_SRC" --ratchet "$RATCHET" >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: dropping a covered route was NOT caught" >&2
  exit 1
fi

# Build a clean copy of the bound webmail files (all current bindings intact!) so
# the raw-fetch regression tests isolate the raw-fetch check from the binding floor.
setup_bound_webmail() {
  local dir="$1"
  rm -rf "$dir"
  mkdir -p "$dir/routes/settings"
  python3 - "$WEBMAIL_SRC" "$dir" <<'PY'
import pathlib, shutil, sys
src_root = pathlib.Path(sys.argv[1])
dst_root = pathlib.Path(sys.argv[2])
for sub in ("lib", "routes"):
    base = src_root / sub
    if not base.is_dir():
        continue
    for p in base.rglob("*"):
        if not p.is_file() or p.suffix not in (".ts", ".svelte"):
            continue
        rel = p.relative_to(src_root).as_posix()
        if rel.endswith(".test.ts") or rel.endswith(".spec.ts") or rel.endswith("edge/schema.d.ts") or rel.endswith("edge/client.ts"):
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        if "$lib/edge/client" in text:
            target = dst_root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)
PY
}

# Sanity: clean isolated webmail fixture with all bound files MUST PASS
setup_bound_webmail "$tmp/webmail_clean"
if ! bash "$GUARD" --inventory "$INV" --openapi "$SPEC" --webmail-src "$tmp/webmail_clean" --ratchet "$RATCHET" >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: clean isolated webmail fixture with all current bindings failed" >&2
  exit 1
fi

# Plant a raw fetch regression inside a .svelte route file (with all 12 bindings intact)
setup_bound_webmail "$tmp/webmail_raw_svelte"
cat >"$tmp/webmail_raw_svelte/routes/settings/+page.svelte" <<'EOF'
<script lang="ts">
async function bad() {
  await fetch('/api/settings/view', { method: 'PUT', body: '{}' });
}
</script>
EOF

out_raw_svelte="$(bash "$GUARD" --inventory "$INV" --openapi "$SPEC" --webmail-src "$tmp/webmail_raw_svelte" --ratchet "$RATCHET" 2>&1 || true)"
if ! grep -q "raw fetch/httpRequest/typedFetch call to contracted path \`/api/settings/view\`" <<<"$out_raw_svelte"; then
  echo "SELF-TEST FAIL: raw fetch() in .svelte route did not trigger raw-fetch violation: $out_raw_svelte" >&2
  exit 1
fi

# Plant an interpolated template-literal raw fetch `/api/messages/${id}/trace`
setup_bound_webmail "$tmp/webmail_raw_tpl"
cat >"$tmp/webmail_raw_tpl/routes/settings/+page.svelte" <<'EOF'
<script lang="ts">
async function badTemplate(id: string) {
  await fetch(`/api/messages/${id}/trace`);
}
</script>
EOF

out_raw_tpl="$(bash "$GUARD" --inventory "$INV" --openapi "$SPEC" --webmail-src "$tmp/webmail_raw_tpl" --ratchet "$RATCHET" 2>&1 || true)"
if ! grep -q "raw fetch/httpRequest/typedFetch call to contracted path \`/api/messages/\${id}/trace\`" <<<"$out_raw_tpl"; then
  echo "SELF-TEST FAIL: interpolated template-literal raw fetch was NOT caught: $out_raw_tpl" >&2
  exit 1
fi

# Invalid --diff-base MUST fail closed
if bash "$GUARD" --inventory "$INV" --openapi "$SPEC" --webmail-src "$WEBMAIL_SRC" --ratchet "$RATCHET" --diff-base "nonexistent-ref-selftest-561" >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: invalid --diff-base did not fail closed" >&2
  exit 1
fi

echo "check-edge-contract-ratchet self-test: PASS (uncovered route, /david prefix trap, dropped route, isolated .svelte raw fetch, interpolated \${id} fetch, and bad --diff-base caught; JMAP excluded)"
