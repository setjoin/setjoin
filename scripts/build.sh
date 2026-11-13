#!/usr/bin/env bash
source "$(dirname "$0")/_base.sh"
node "$ROOT/scripts/go-module-catalog.mjs" check
while IFS=$'\t' read -r module_id module_path module_workspace build_tags module_gowork package output; do
  [[ "$module_workspace" == "workspace" ]] || continue
  [[ "$build_tags" == "-" ]] && build_tags=""
  [[ "$module_gowork" == "-" ]] && module_gowork=""
  echo "==> Building $module_id/$output"
  (cd "$ROOT/$module_path" && go build -o "$output" "$package")
done < <(node "$ROOT/scripts/go-module-catalog.mjs" artifacts)

# The frozen Go mailctl remains an oracle; customer builds use the Rust CLI.
# The captions bot is Rust too (#356): the frozen Go asrbot below stays only as the parity oracle.
echo "==> Building Rust mailctl, asrbotd and updater/recovery"
(cd "$ROOT/server-rust" && cargo build --release --locked -p setjoin-mailctl -p setjoin-asrbot -p setjoin-updater)
mailctl_target="${CARGO_TARGET_DIR:-$ROOT/server-rust/target}"
install -m 0755 "$mailctl_target/release/mailctl" "$ROOT/server-rust/mailctl"
install -m 0755 "$ROOT/server-rust/mailctl" "$ROOT/mailctl/mailctl"
install -m 0755 "$mailctl_target/release/asrbotd" "$ROOT/server-rust/asrbotd"
install -m 0755 "$mailctl_target/release/setjoin-updater" "$ROOT/server-rust/setjoin-updater"

# asrbot (B3 Task 12): a FIFTH top-level Go module, deliberately NOT in
# go.work (eng E1) — cgo/libopus must never become a hard dependency of the
# other four modules' build/test/lint. GOWORK=off is load-bearing: with
# go.work present, workspace mode would otherwise refuse a non-member
# module ("not in a module listed in go.work"). A LOUD named skip when
# libopus isn't installed, never a silent one.
#
# -tags nolibopusfile: gopkg.in/hraban/opus.v2 pulls in libopusfile (an
# unrelated Ogg/file-reading library) ONLY for its whole-file Stream API,
# which this module never uses (it decodes live RTP frames via Decoder,
# not files via Stream) — the upstream package's own `!nolibopusfile` build
# tag drops that file, so `pkg-config --exists opus` alone (no opusfile)
# stays sufficient, matching this containment's one real prerequisite.
if pkg-config --exists opus 2>/dev/null; then
  while IFS=$'\t' read -r module_id module_path module_workspace build_tags module_gowork package output; do
    [[ "$module_id" == "asrbot" ]] || continue
    [[ "$build_tags" == "-" ]] && build_tags=""
    [[ "$module_gowork" == "-" ]] && module_gowork=""
    echo "==> $module_id/$output"
    (cd "$ROOT/$module_path" && GOWORK="$module_gowork" go build -tags "$build_tags" -o "$output" "$package")
  done < <(node "$ROOT/scripts/go-module-catalog.mjs" artifacts)
else
  echo "==> SKIP asrbot (libopus not installed — brew install opus / apt install libopus-dev)"
fi

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
