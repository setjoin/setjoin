#!/usr/bin/env bash
# Android NDK r23+ (we pin 27.0.12077973 — see clients/.cargo/config.toml)
# dropped the per-triple binutils symlinks (e.g. aarch64-linux-android-ranlib)
# in favor of the unified llvm-ar/llvm-ranlib. cc-rs's own Android fallback
# still shells out to the old triple-prefixed bare command names when no
# override resolves for a given tool, and openssl-src's vendored OpenSSL
# build (needed by rusqlite's bundled-sqlcipher-vendored-openssl, which
# guard-core/offline-core depend on) invokes them as bare commands via
# /bin/sh, so they must exist somewhere on PATH — not just next to the NDK's
# clang wrapper. This is the root cause of `tauri android build`'s
# "aarch64-linux-android-ranlib: command not found" failure (setting
# RANLIB_<target> in .cargo/config.toml is not sufficient for this specific
# openssl-src code path).
#
# Fix: symlink the missing triple-prefixed names to llvm-ar/llvm-ranlib in
# ~/.cargo/bin (already on PATH for any Rust dev setup, so no shell profile
# edit needed). Idempotent — safe to re-run after an NDK upgrade.
#
# Usage: clients/desktop/scripts/setup-android-ndk-compat.sh
set -euo pipefail

NDK_HOME="${ANDROID_NDK_HOME:-${NDK_HOME:-$HOME/Library/Android/sdk/ndk/27.0.12077973}}"
BIN="$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin"
DEST="$HOME/.cargo/bin"

if [ ! -d "$BIN" ]; then
  echo "error: NDK toolchain bin dir not found: $BIN" >&2
  echo "       set ANDROID_NDK_HOME to your NDK install (this repo pins 27.0.12077973)" >&2
  exit 1
fi

mkdir -p "$DEST"

triples=(
  aarch64-linux-android
  armv7-linux-androideabi
  arm-linux-androideabi
  i686-linux-android
  x86_64-linux-android
)
tools=(ar ranlib strip nm objcopy objdump strings as)

for triple in "${triples[@]}"; do
  for tool in "${tools[@]}"; do
    link="$DEST/${triple}-${tool}"
    target="$BIN/llvm-${tool}"
    [ -e "$target" ] || continue
    ln -sf "$target" "$link"
    echo "linked $link -> $target"
  done
done
