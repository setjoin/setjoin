#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-api-namespace.sh — /api namespace invariants.
#
# WHY. The gateway serves the webmail SPA and the JSON API from one origin.
# JSON API routes are canonically served under /api (main.go mounts the API
# mux via StripPrefix); only the pinned protocol/outward surfaces in
# scripts/api-pinned-prefixes.txt stay at the URL root. This layout ended the
# SPA-route-shadow bug class (a GET JSON route on an SPA page path rendered
# the page blank on refresh — 27 routes were affected before the migration).
#
# INVARIANTS:
#  1. SYNC — apiPinnedPrefixes in cmd/mailserverd/main.go and
#     scripts/api-pinned-prefixes.txt are the same set (the SW list and this
#     guard both derive from the file; main.go embeds its own copy).
#  2. PINNED-SHADOW — no pinned GET route may exactly equal an SPA page path
#     (pinned routes bypass the SPA fallback, so they CAN still shadow).
#     Known product overlap: /downloads (gateway HTML page predates the SPA
#     page — see TODOS.md).
#  3. CLIENT — webmail src must not fetch app-JSON at root paths: any
#     fetch/httpRequest/typedFetch/EventSource literal must start with /api,
#     a pinned prefix, or a static-asset path. (adminFetch is exempt — its
#     API_BASE seam prepends /api.)
#
# Usage: scripts/check-api-namespace.sh [--self-test]
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

PINNED_FILE="$ROOT/scripts/api-pinned-prefixes.txt"
INVENTORY="${ROUTE_INVENTORY_FILE:-$ROOT/server-rust/bins/gateway/data/route-inventory.json}"
INVENTORY_READER="$ROOT/scripts/route-inventory-json.mjs"
ROUTES_DIR="$ROOT/mailserver/webmail/src/routes"
WEBMAIL_SRC="$ROOT/mailserver/webmail/src"

pinned_from_file() { grep -vE '^\s*#|^\s*$' "$PINNED_FILE" | awk '{print $1}' | sort -u; }

spa_paths() {
  find "$ROUTES_DIR" -name '+page.svelte' -print \
    | sed -e "s#^$ROUTES_DIR##" -e 's#/+page.svelte$##' -e 's#/([^/]*)##g' \
    | sed -e 's#^$#/#' | sort -u
}

fail=0

check_pinned_shadow() {
  local hit=0 p routes
  routes="$(API_PINNED_PREFIXES_FILE="$PINNED_FILE" node "$INVENTORY_READER" routes "$INVENTORY")" || return 1
  while IFS= read -r p; do
    while IFS= read -r pin; do
      if [ "$p" = "$pin" ] || case "$p" in "$pin"/*) true ;; *) false ;; esac; then
        if grep -qxF "GET $p" <<<"$routes"; then
          echo "  [PINNED-SHADOW] GET $p is pinned AND an SPA page — the page is unreachable." >&2
          hit=1
        fi
      fi
    done < <(pinned_from_file)
  done < <(spa_paths)
  return $hit
}

check_client_literals() {
  # Direct network-call literals in webmail src that start at the URL root.
  local bad
  bad=$(grep -rnE "(^|[^a-zA-Z])(fetch|httpRequest|typedFetch(<[^>]*>)?|EventSource)\(\s*[\`'\"]/[a-zA-Z]" \
          "$WEBMAIL_SRC" --include='*.ts' --include='*.svelte' 2>/dev/null \
        | grep -vE '\.test\.ts|test-utils' \
        | grep -oE "[\`'\"]/[a-zA-Z][a-zA-Z0-9/._-]*" | tr -d "\"'\`" | sort -u) || true
  local hit=0 path ok pin
  for path in $bad; do
    ok=1
    case "$path" in
      /api|/api/*) ok=0 ;;
      /_app/*|/brand/*|/fonts/*|/manifest.webmanifest) ok=0 ;;
    esac
    if [ $ok -ne 0 ]; then
      while IFS= read -r pin; do
        case "$path" in "$pin"|"$pin"/*) ok=0; break ;; esac
      done < <(pinned_from_file)
    fi
    if [ $ok -ne 0 ]; then
      echo "  [CLIENT] webmail fetches app-JSON at a root path: $path — use /api$path (or adminFetch)." >&2
      hit=1
    fi
  done
  return $hit
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/routes/foo" "$tmp/src"
  : > "$tmp/routes/foo/+page.svelte"
  printf '/foo\n/auth\n' > "$tmp/pinned.txt"
  cat > "$tmp/route-inventory.json" <<'EOF'
{"schema_version":1,"owner":"merged","operations":[{"method":"GET","path":"/foo","pattern":"GET /foo","owner":"gateway","mount":"/","middleware":"none","visibility":"public","satisfying_masks":["00000"]}]}
EOF
  cat > "$tmp/src/app.svelte" <<'EOF'
fetch('/admin/users')
fetch('/api/admin/users')
fetch('/auth/login')
EOF
  INVENTORY="$tmp/route-inventory.json" PINNED_FILE="$tmp/pinned.txt" ROUTES_DIR="$tmp/routes" WEBMAIL_SRC="$tmp/src"
  shadow_rc=0; shadow_out="$(check_pinned_shadow 2>&1)" || shadow_rc=$?
  client_rc=0; client_out="$(check_client_literals 2>&1)" || client_rc=$?
  if [ $shadow_rc -ne 0 ] && grep -qF '[PINNED-SHADOW]' <<<"$shadow_out" && [ $client_rc -ne 0 ] && grep -qF '[CLIENT]' <<<"$client_out"; then
    echo "check-api-namespace self-test: OK (fires on pinned-shadow /foo + root fetch /admin/users; passes /api + pinned)"
    exit 0
  fi
  echo "check-api-namespace SELF-TEST FAILED: shadow=$shadow_rc(want!=0) client=$client_rc(want!=0)" >&2
  printf '  shadow_out: %s\n  client_out: %s\n' "$shadow_out" "$client_out" >&2
  exit 1
fi

echo "==> API-namespace guard: pinned-shadow + client root-path literals"
check_pinned_shadow || fail=1
check_client_literals || fail=1
if [ $fail -ne 0 ]; then
  echo "API-namespace guard FAILED (see above)." >&2
  exit 1
fi
echo "    API-namespace guard: clean."
