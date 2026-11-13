#!/usr/bin/env bash
# check-clients-licenses.sh — third-party licence policy for the clients Rust
# workspaces (clients/Cargo.toml and clients/desktop/src-tauri/Cargo.toml).
#
# 1. Policy drift (Python 3.11+ tomllib): clients/deny.toml [licenses] allow
#    must equal server-rust/deny.toml's allow plus CDLA-Permissive-2.0
#    (webpki-roots / webpki-root-certs), [licenses.private] ignore must be
#    true, and every first-party client crate must set publish = false so
#    cargo-deny skips it as private (Setjoin's own licence is the root LICENSE).
# 2. cargo-deny 0.19.0 (when installed): `cargo deny check licenses sources`
#    on both manifests with clients/deny.toml. Without cargo-deny this prints
#    `CLIENTS-LICENSES-SKIP (reason=cargo-deny-not-found)` and exits 0.
#
# --self-test: the drift check must go red on a deny.toml whose allow-list
# lost an entry and on one with private.ignore = false.
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"

CLIENT_DENY="$ROOT/clients/deny.toml"
SERVER_DENY="$ROOT/server-rust/deny.toml"
MANIFESTS=(
  "$ROOT/clients/Cargo.toml"
  "$ROOT/clients/desktop/src-tauri/Cargo.toml"
)
FIRST_PARTY=(
  "$ROOT/clients/rust/capability-session/Cargo.toml"
  "$ROOT/clients/rust/guard-core/Cargo.toml"
  "$ROOT/clients/rust/offline-core/Cargo.toml"
  "$ROOT/clients/rust/desktop-native/Cargo.toml"
  "$ROOT/clients/rust/ohos-native/Cargo.toml"
  "$ROOT/clients/rust/native-shared/Cargo.toml"
  "$ROOT/clients/desktop/src-tauri/Cargo.toml"
)

have_tomllib() { python3 -c 'import tomllib' >/dev/null 2>&1; }

policy_check() {
  python3 - "$1" "$SERVER_DENY" "${FIRST_PARTY[@]}" <<'PY'
import sys
import tomllib

client_path, server_path, *crates = sys.argv[1:]


def load(path):
    with open(path, "rb") as handle:
        return tomllib.load(handle)


client, server = load(client_path), load(server_path)
errors = []
server_allow = set(server.get("licenses", {}).get("allow", []))
if not server_allow:
    errors.append(f"{server_path}: [licenses] allow is missing or empty")
want = server_allow | {"CDLA-Permissive-2.0"}
have = set(client.get("licenses", {}).get("allow", []))
if have != want:
    errors.append(
        f"{client_path}: [licenses] allow drifted from server-rust + CDLA-Permissive-2.0 "
        f"(missing {sorted(want - have)}, extra {sorted(have - want)})"
    )
if client.get("licenses", {}).get("private", {}).get("ignore") is not True:
    errors.append(f"{client_path}: [licenses.private] ignore must be true")
for crate in crates:
    if load(crate).get("package", {}).get("publish") is not False:
        errors.append(f"{crate}: [package] publish = false is required (first-party crate)")
for error in errors:
    print("✗ clients-licenses: " + error, file=sys.stderr)
sys.exit(1 if errors else 0)
PY
}

selftest() {
  if ! have_tomllib; then
    echo "CLIENTS-LICENSES-SKIP (reason=python-without-tomllib) — self-test NOT run"
    return 0
  fi
  st_tmp="$(mktemp -d)"
  st_rc=0
  if ! policy_check "$CLIENT_DENY"; then
    echo "self-test: FAIL — the real clients/deny.toml is not green" >&2
    st_rc=1
  fi
  sed '/^  "MPL-2.0",$/d' "$CLIENT_DENY" >"$st_tmp/weak-allow.toml"
  sed 's/^ignore = true$/ignore = false/' "$CLIENT_DENY" >"$st_tmp/no-private.toml"
  for mutant in weak-allow no-private; do
    if cmp -s "$CLIENT_DENY" "$st_tmp/$mutant.toml"; then
      echo "self-test: FAIL — mutation $mutant did not apply" >&2
      st_rc=1
      continue
    fi
    if policy_check "$st_tmp/$mutant.toml" 2>/dev/null; then
      echo "self-test: FAIL — mutation $mutant stayed green" >&2
      st_rc=1
    fi
  done
  rm -rf "$st_tmp"
  if [ "$st_rc" -eq 0 ]; then
    echo "self-test: PASS (real policy green, 2 injected violations fired)"
  fi
  return "$st_rc"
}

case "${1:-}" in
  --self-test)
    selftest
    exit $?
    ;;
  "") ;;
  *)
    echo "usage: $0 [--self-test]" >&2
    exit 2
    ;;
esac

rc=0
if have_tomllib; then
  policy_check "$CLIENT_DENY" || rc=1
else
  echo "CLIENTS-LICENSES-SKIP (reason=python-without-tomllib) — policy drift check NOT run"
fi

CARGO_BIN="${CARGO_BIN:-cargo}"
if ! command -v "$CARGO_BIN" >/dev/null 2>&1 || ! "$CARGO_BIN" deny --version >/dev/null 2>&1; then
  echo "CLIENTS-LICENSES-SKIP (reason=cargo-deny-not-found) — clients cargo-deny licences/sources NOT run"
  exit "$rc"
fi
for manifest in "${MANIFESTS[@]}"; do
  echo "cargo deny (licenses, sources): ${manifest#"$ROOT"/}"
  "$CARGO_BIN" deny --manifest-path "$manifest" --locked check --config "$CLIENT_DENY" licenses sources || rc=1
done
exit "$rc"
