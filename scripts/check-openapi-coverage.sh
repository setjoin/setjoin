#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-openapi-coverage.sh — the route↔spec COVERAGE tripwire (fail-closed).
#
# A "valid OpenAPI" parse certifies the spec is well-formed; it does NOT prove
# the spec matches the routes — it can certify a well-formed lie. THIS guard
# catches the high-value drift: it diffs the gateway's REGISTERED route set
# against the spec's documented paths, in BOTH directions, and fails CI on any
# divergence that is not consciously ledgered. Same positive, fail-closed shape
# as check-account-scope.sh / check-gateway-ownership.sh (ARCH-006): every route
# must be classified — documented OR in the coverage-debt ledger — so a new route
# can never silently ship undocumented, and a documented path can never point at
# a dead route.
#
#   Direction 1 (no stale docs):  every SPEC path must be a REGISTERED route
#                                 (CalDAV/CardDAV protocol prefixes exempted).
#   Direction 2 (no silent gaps): every REGISTERED route must be in the SPEC
#                                 OR in the PENDING ledger (openapi-pending.txt).
#
# Paths are normalized {param} → {} so param-name differences ({id} vs
# {accountId}) don't cause false diffs (position-based comparison).
#
# The route set comes from scripts/check-route-inventory.sh. It replays the six
# gateway registrars plus the production-used Drive, Chat, Meet, and SCIM
# registrars. Source regex is deliberately not an authority here.
#
# Usage:
#   scripts/check-openapi-coverage.sh              # the guard (exit 1 on drift)
#   scripts/check-openapi-coverage.sh --self-test  # prove the guard FIRES
#   scripts/check-openapi-coverage.sh --regen-pending  # regenerate the ledger
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
# Pin collation so sort/comm agree across machines (the --regen-pending comm and
# the per-line grep membership in run_guard must order identically).
export LC_ALL=C
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPEC="$ROOT/mailserver/api/openapi.yaml"
PENDING="$ROOT/mailserver/api/openapi-pending.txt"
INVENTORY="${ROUTE_INVENTORY_FILE:-$ROOT/test-results/mailserver/route-inventory.json}"
INVENTORY_READER="$ROOT/scripts/route-inventory-json.mjs"

# These protocol muxes are governed by DAV contracts rather than OpenAPI.
SUBROUTER_PREFIXES='^(GET|POST|PUT|DELETE|PATCH|ANY) (/caldav/|/carddav/)'

registered_routes() {
  if [[ ! -r "$INVENTORY" ]]; then
    echo "E_ROUTE_INVENTORY_MISSING: $INVENTORY" >&2
    echo "  cause: runtime-derived route evidence has not been generated for this run" >&2
    echo "  fix: bash scripts/verify-architecture-r2.sh route" >&2
    return 1
  fi
  node "$INVENTORY_READER" routes "$INVENTORY"
}

# ── extract documented "METHOD /path" pairs from the OpenAPI spec ─────────────
spec_routes() {
  awk '
    /^paths:/ {inpaths=1; next}
    inpaths && /^[^ ]/ {inpaths=0}           # left the paths: block
    inpaths && /^  \// {                       # a path line: "  /foo:"
      p=$1; sub(/:$/,"",p); curpath=p; next
    }
    inpaths && /^    (get|post|put|delete|patch|head):/ {
      m=$1; sub(/:.*/,"",m); print toupper(m) " " curpath
    }
  ' "$SPEC" \
    | sed -E 's/\{[^}]+\}/{}/g' \
    | sort -u
}

pending_routes() {
  [ -f "$PENDING" ] || { echo ""; return; }
  grep -vE '^\s*(#|$)' "$PENDING" | sed -E 's/\{[^}]+\}/{}/g' | sort -u
}

run_guard() {  # echoes failures to stderr; returns 1 on any
  local rc=0 reg spec pend
  reg="$(registered_routes)"
  spec="$(spec_routes)"
  pend="$(pending_routes)"

  # Direction 1 — every documented path is a real route (DAV protocols exempted).
  while IFS= read -r s; do
    [ -n "$s" ] || continue
    echo "$s" | grep -qE "$SUBROUTER_PREFIXES" && continue
    if ! grep -qxF "$s" <<<"$reg"; then
      echo "  ✗ documented in openapi.yaml but NOT a registered route: $s" >&2
      rc=1
    fi
  done <<<"$spec"

  # Direction 2 — every registered route is documented OR ledgered as pending.
  while IFS= read -r r; do
    [ -n "$r" ] || continue
    grep -qxF "$r" <<<"$spec" && continue
    grep -qxF "$r" <<<"$pend" && continue
    local method path details
    method="${r%% *}"
    path="${r#* }"
    details="$(node "$INVENTORY_READER" describe "$INVENTORY" "$method" "$path" 2>/dev/null || true)"
    echo "E_ROUTE_UNDOCUMENTED" >&2
    echo "  operation: $r" >&2
    [[ -n "$details" ]] && sed 's/^/  /' <<<"$details" >&2
    echo "  absent_ledgers: mailserver/api/openapi.yaml, mailserver/api/openapi-pending.txt" >&2
    echo "  cause: an emitted production route has no reviewed API contract or explicit pending entry" >&2
    echo "  fix: document it, or add the reviewer-approved exact operation to openapi-pending.txt" >&2
    echo "  rerun: bash scripts/verify-architecture-r2.sh route" >&2
    rc=1
  done <<<"$reg"

  return $rc
}

case "${1:-}" in
  --regen-pending)
    # PENDING = every registered route NOT documented in the spec. The honest
    # coverage-debt ledger; shrinks as routes get documented.
    comm -23 <(registered_routes) <(spec_routes) > "$PENDING.tmp"
    { echo "# openapi-pending.txt — coverage-debt ledger (auto-seeded; see check-openapi-coverage.sh)."
      echo "# Every line is a REGISTERED gateway route not yet documented in openapi.yaml."
      echo "# Document a route in the spec, then DELETE its line here. A NEW route that is"
      echo "# neither documented nor listed here fails CI — that is the tripwire."
      cat "$PENDING.tmp"
    } > "$PENDING"
    rm -f "$PENDING.tmp"
    echo "Regenerated $PENDING ($(grep -cvE '^\s*(#|$)' "$PENDING") pending routes)."
    exit 0
    ;;
  --self-test)
    # Prove the guard FIRES: a synthetic registered route that is neither
    # documented nor pending MUST be caught (else the guard is asleep).
    echo "==> openapi-coverage guard self-test (must detect a planted undocumented route)"
    if ! registered_routes | grep -qxF 'HEAD /api/drive/chunks/{}'; then
      echo "  ✗ SELF-TEST FAILED: Drive sub-router routes were not expanded." >&2
      exit 1
    fi
    if registered_routes | grep -qxF 'ANY /api/drive/'; then
      echo "  ✗ SELF-TEST FAILED: opaque Drive mount survived exact expansion." >&2
      exit 1
    fi
    if registered_routes | grep -qxF 'ANY /api/chat/'; then
      echo "  ✗ SELF-TEST FAILED: opaque Chat mount survived exact expansion." >&2
      exit 1
    fi
    echo "  ✓ emitted private routes replace opaque mounts."
    tmpdir="$(mktemp -d)"; trap 'rm -rf "$tmpdir"' EXIT
    planted="$tmpdir/planted.json"
    cp "$INVENTORY" "$planted"
    node -e '
      const fs = require("fs");
      const file = process.argv[1];
      const artifact = JSON.parse(fs.readFileSync(file, "utf8"));
      artifact.operations.push({method:"GET", path:"/chat/__coverage_selftest__",
        pattern:"GET /chat/__coverage_selftest__", owner:"chat", mount:"/chat/",
        middleware:"requireAuth", visibility:"public", satisfying_masks:["00000"]});
      fs.writeFileSync(file, JSON.stringify(artifact));
    ' "$planted"
    original_inventory="$INVENTORY"
    INVENTORY="$planted"
    if run_guard >/dev/null 2>&1; then
      echo "  ✗ SELF-TEST FAILED: guard did NOT catch a planted undocumented private route." >&2
      exit 1
    fi
    INVENTORY="$tmpdir/missing.json"
    if run_guard >/dev/null 2>&1; then
      echo "  ✗ SELF-TEST FAILED: guard accepted a missing inventory." >&2
      exit 1
    fi
    INVENTORY="$original_inventory"
    echo "  ✓ guard fires on an undocumented private route and missing evidence."
    exit 0
    ;;
esac

echo "==> OpenAPI route↔spec coverage guard"
if run_guard; then
  echo "    OK — every documented path is a real route, and every route is documented or ledgered."
  echo "    ($(spec_routes | grep -c .) documented, $(pending_routes | grep -c .) pending, $(registered_routes | grep -c .) registered)"
  exit 0
else
  echo "" >&2
  echo "  OpenAPI coverage drift (see ✗ lines). Fix by documenting the route in" >&2
  echo "  mailserver/api/openapi.yaml or updating mailserver/api/openapi-pending.txt." >&2
  exit 1
fi
