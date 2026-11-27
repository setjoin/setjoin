#!/usr/bin/env bash
# Install the pinned tools the server-rust parallel lane needs into a job-owned
# directory (default $HOME/.cache/setjoin-server-rust-lane/bin, override LANE_BIN_DIR):
# cargo-nextest, cargo-deny, and pebble (all sha256-verified prebuilt binaries,
# zero Go toolchain required). Idempotent; prints the bin dir.
set -euo pipefail

NEXTEST_VERSION=0.9.150
NEXTEST_SHA256=b0959bc64232974224cf9fb22c915845398c0e8668fa7831eb5b43fb1eef781f
DENY_VERSION=0.19.0
DENY_SHA256=0e8c2aa59128612c90d9e09c02204e912f29a5b8d9a64671b94608cbe09e064f
PEBBLE_VERSION=v2.10.1
PEBBLE_SHA256_AMD64=4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed
PEBBLE_SHA256_ARM64=b53fd072a69eb7692451de4e8b0667e0bdf5cccd7e36fc51b8eaf2fcc135ed9f

BIN="${LANE_BIN_DIR:-$HOME/.cache/setjoin-server-rust-lane/bin}"
mkdir -p "$BIN"

fetch_tar() { # URL SHA256 DEST_DIR [tar args...]
  local url="$1" sha="$2" dest="$3" tmp
  shift 3
  tmp="$(mktemp)"
  curl -fsSL --retry 3 "$url" -o "$tmp"
  echo "$sha  $tmp" | sha256sum -c - >&2 || { rm -f "$tmp"; return 1; }
  tar -xz -C "$dest" "$@" -f "$tmp"
  rm -f "$tmp"
}

if ! "$BIN/cargo-nextest" nextest --version 2>/dev/null | grep -q "cargo-nextest $NEXTEST_VERSION "; then
  fetch_tar "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$NEXTEST_VERSION/cargo-nextest-$NEXTEST_VERSION-x86_64-unknown-linux-gnu.tar.gz" \
    "$NEXTEST_SHA256" "$BIN"
fi

if ! "$BIN/cargo-deny" --version 2>/dev/null | grep -q "cargo-deny $DENY_VERSION"; then
  tmpd="$(mktemp -d)"
  fetch_tar "https://github.com/EmbarkStudios/cargo-deny/releases/download/$DENY_VERSION/cargo-deny-$DENY_VERSION-x86_64-unknown-linux-musl.tar.gz" \
    "$DENY_SHA256" "$tmpd" --strip-components=1
  install -m 0755 "$tmpd/cargo-deny" "$BIN/cargo-deny"
  rm -rf "$tmpd"
fi

if [ ! -x "$BIN/pebble" ]; then
  case "$(uname -m)" in
    x86_64|amd64) pebble_arch=amd64; pebble_sha="$PEBBLE_SHA256_AMD64" ;;
    aarch64|arm64) pebble_arch=arm64; pebble_sha="$PEBBLE_SHA256_ARM64" ;;
    *) echo "unsupported architecture for pebble: $(uname -m)" >&2; exit 1 ;;
  esac
  tmpd="$(mktemp -d)"
  fetch_tar "https://github.com/letsencrypt/pebble/releases/download/$PEBBLE_VERSION/pebble-linux-$pebble_arch.tar.gz" \
    "$pebble_sha" "$tmpd"
  install -m 0755 "$tmpd/pebble-linux-$pebble_arch/linux/$pebble_arch/pebble" "$BIN/pebble"
  rm -rf "$tmpd"
fi

echo "$BIN"
