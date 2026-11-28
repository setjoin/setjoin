#!/usr/bin/env bash
# EdgeContract drift check (#561).
# Recompiles TypeSpec -> OpenAPI 3.1 -> TypeScript schema -> Rust plain serde
# DTOs into a temp directory and asserts byte-identical match against committed
# artifacts:
#   - contracts/edge/openapi/edge.v1.yaml
#   - mailserver/webmail/src/lib/edge/schema.d.ts
#   - server-rust/crates/edge-contract/src/generated.rs
#
# Set EDGE_CONTRACT_REQUIRE_TOOLS=1 (as in CI) to require full tsp/node
# regeneration; without node_modules installed, falls back to static structural
# parity validation across all three committed artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EDGE_DIR="${EDGE_CONTRACT_DIR:-$ROOT/contracts/edge}"
COMMITTED_OPENAPI="${EDGE_COMMITTED_OPENAPI:-$EDGE_DIR/openapi/edge.v1.yaml}"
COMMITTED_TS="${EDGE_COMMITTED_TS:-$ROOT/mailserver/webmail/src/lib/edge/schema.d.ts}"
COMMITTED_RS="${EDGE_COMMITTED_RS:-$ROOT/server-rust/crates/edge-contract/src/generated.rs}"

for f in "$COMMITTED_OPENAPI" "$COMMITTED_TS" "$COMMITTED_RS"; do
  if [ ! -f "$f" ]; then
    echo "EDGE-CONTRACT-DRIFT-FAIL: missing committed artifact $f" >&2
    exit 1
  fi
done

# Prefer user-local node under $HOME if present and not already on PATH.
if ! command -v node >/dev/null 2>&1 && [ -n "${HOME:-}" ] && [ -x "${HOME}/.local/node/bin/node" ]; then
  export PATH="${HOME}/.local/node/bin:$PATH"
fi

if command -v node >/dev/null 2>&1 && [ -x "$EDGE_DIR/node_modules/.bin/tsp" ] && [ -x "$EDGE_DIR/node_modules/.bin/openapi-typescript" ]; then
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/edge-contract-drift.XXXXXX")"
  trap 'rm -rf "$tmp"' EXIT

  (
    cd "$EDGE_DIR"
    ./node_modules/.bin/tsp compile main.tsp \
      --option "@typespec/openapi3.emitter-output-dir=$tmp/openapi" \
      --option "@typespec/openapi3.output-file=edge.v1.yaml" >/dev/null
    ./node_modules/.bin/openapi-typescript "$tmp/openapi/edge.v1.yaml" -o "$tmp/schema.d.ts" >/dev/null 2>&1
    node scripts/gen-rust-dtos.mjs "$tmp/openapi/edge.v1.yaml" "$tmp/generated.rs" >/dev/null
  )

  fail=0
  if ! diff -u "$COMMITTED_OPENAPI" "$tmp/openapi/edge.v1.yaml"; then
    echo "EDGE-CONTRACT-DRIFT-FAIL: contracts/edge/openapi/edge.v1.yaml drifted from TypeSpec sources (run npm run build in contracts/edge/)" >&2
    fail=1
  fi
  if ! diff -u "$COMMITTED_TS" "$tmp/schema.d.ts"; then
    echo "EDGE-CONTRACT-DRIFT-FAIL: mailserver/webmail/src/lib/edge/schema.d.ts drifted from OpenAPI 3.1 baseline (run npm run build in contracts/edge/)" >&2
    fail=1
  fi
  if ! diff -u "$COMMITTED_RS" "$tmp/generated.rs"; then
    echo "EDGE-CONTRACT-DRIFT-FAIL: server-rust/crates/edge-contract/src/generated.rs drifted from OpenAPI 3.1 baseline (run npm run build in contracts/edge/)" >&2
    fail=1
  fi
  if [ "$fail" != 0 ]; then
    exit 1
  fi
  echo "edge-contract-drift: PASS (byte-identical OpenAPI 3.1, webmail schema.d.ts, and Rust generated.rs)"
  exit 0
fi

if [ "${EDGE_CONTRACT_REQUIRE_TOOLS:-0}" = "1" ]; then
  echo "EDGE-CONTRACT-DRIFT-FAIL: node + contracts/edge/node_modules required when EDGE_CONTRACT_REQUIRE_TOOLS=1" >&2
  exit 1
fi

# Static structural fallback when running inside a Rust-only container without node_modules.
python3 - "$COMMITTED_OPENAPI" "$COMMITTED_TS" "$COMMITTED_RS" "$ROOT/scripts/guards/check-edge-contract-breaking.py" <<'PY'
import importlib.util, pathlib, sys

openapi_path, ts_path, rs_path, helper_path = [pathlib.Path(p) for p in sys.argv[1:5]]
spec = importlib.util.spec_from_file_location("breaking", str(helper_path))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

doc = mod.load_openapi(openapi_path)
if not str(doc.get("openapi", "")).startswith("3.1."):
    print("EDGE-CONTRACT-DRIFT-FAIL: openapi version must be 3.1.x", file=sys.stderr)
    sys.exit(1)

ts_text = ts_path.read_text(encoding="utf-8")
rs_text = rs_path.read_text(encoding="utf-8")
errors = []
for p, item in sorted((doc.get("paths") or {}).items()):
    if f'"{p}":' not in ts_text:
        errors.append(f"schema.d.ts missing path {p}")
    for m in ("get", "post", "put", "delete", "patch", "head", "options"):
        if isinstance(item, dict) and m in item:
            pair = f'("{m.upper()}", "{p}")'
            if pair not in rs_text:
                errors.append(f"generated.rs missing operation {pair}")

if errors:
    for e in errors:
        print(f"EDGE-CONTRACT-DRIFT-FAIL: {e}", file=sys.stderr)
    sys.exit(1)

print(f"edge-contract-drift: PASS (static structural check; {len(doc.get('paths') or {})} paths aligned)")
PY
