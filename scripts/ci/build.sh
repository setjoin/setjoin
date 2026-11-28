#!/usr/bin/env bash
source "$(dirname "$0")/../_base.sh"

echo "==> Building Rust server binaries (setjoind, setjoin-server-shim, setjoin-auth-shim, mailctl, asrbotd, setjoin-updater)"
(cd "$ROOT/server-rust" && cargo build --release --locked -p setjoind -p setjoin-mailctl -p setjoin-asrbot -p setjoin-updater)
rust_target="${CARGO_TARGET_DIR:-$ROOT/server-rust/target}"
install -m 0755 "$rust_target/release/setjoind" "$ROOT/server-rust/setjoind"
install -m 0755 "$rust_target/release/setjoin-server-shim" "$ROOT/server-rust/setjoin-server"
install -m 0755 "$rust_target/release/setjoin-auth-shim" "$ROOT/server-rust/setjoin-auth"
install -m 0755 "$rust_target/release/mailctl" "$ROOT/server-rust/mailctl"
install -m 0755 "$rust_target/release/asrbotd" "$ROOT/server-rust/asrbotd"
install -m 0755 "$rust_target/release/setjoin-updater" "$ROOT/server-rust/setjoin-updater"

# Production webmail bundle (2026-07-18 test-suite review): svelte-check and
# vitest ran in the gate but the actual vite production build did not — a
# Node-major bump could break the shipped bundle while every gate stayed
# green. Skipped only if node_modules is absent (fresh clone before npm ci).
if [ -d "$ROOT/mailserver/webmail/node_modules" ]; then
  echo "==> webmail production build"
  cd "$ROOT/mailserver/webmail" && npm run build --silent >/dev/null
else
  echo "==> SKIP webmail production build (node_modules absent — run npm ci first)"
fi

echo "Build complete."
