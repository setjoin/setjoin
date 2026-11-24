#!/usr/bin/env bash
# cross-build.sh — Multi-arch Xinchuang Rust floor build.
# Usage: bash scripts/cross-build.sh [--rust] --arch x86_64|arm64|loong64
# Run inside the selected floor toolchain container.
# Rust uses CARGO_TARGET_DIR (Cargo's default when unset).
set -euo pipefail
source "$(dirname "$0")/_base.sh"

ARCH=""
OS="linux"
SMOKE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch) ARCH="$2"; shift 2 ;;
        --os) OS="$2"; shift 2 ;;
        --smoke) SMOKE=1; shift ;;
        --rust) shift ;;
        --help|-h)
            echo 'Rust (inside its floor container): cross-build.sh [--rust] --arch x86_64|arm64|loong64'
            exit 0 ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
done

if [[ -z "$ARCH" ]]; then
    echo "Usage: cross-build.sh [--rust] --arch <x86_64|arm64|loong64> [--os linux]"
    exit 1
fi

[[ "$OS" == linux ]] || { echo 'Rust floor builds require Linux' >&2; exit 1; }
[[ "$SMOKE" -eq 0 ]] || { echo 'Rust smoke uses scripts/smoke-rust-floor.sh' >&2; exit 1; }
case "$ARCH" in
    x86_64|amd64) TARGET=x86_64-unknown-linux-gnu; FLOOR=2.28 ;;
    arm64|aarch64) TARGET=aarch64-unknown-linux-gnu; FLOOR=2.28 ;;
    loong64|loongarch64) TARGET=loongarch64-unknown-linux-gnu; FLOOR=2.36 ;;
    *) echo "Unsupported Rust architecture: $ARCH" >&2; exit 1 ;;
esac
exec python3 "$ROOT/scripts/build-rust-floor.py" "$TARGET" "$FLOOR"
