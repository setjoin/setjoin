#!/usr/bin/env bash
# cross-build.sh — Multi-arch Xinchuang build with QEMU smoke test.
# Go:   bash scripts/cross-build.sh --arch arm64|loong64 [--os linux] [--smoke]
# Rust: bash scripts/cross-build.sh --rust --arch x86_64|arm64|loong64
#       Run Rust mode inside its selected floor toolchain container.
# Go produces stripped, versioned binaries in build/xinchuang/<arch>-<os>/.
# Rust uses CARGO_TARGET_DIR (Cargo's default when unset).
set -euo pipefail
source "$(dirname "$0")/_base.sh"

ARCH=""
OS="linux"
SMOKE=0
RUST=0
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch) ARCH="$2"; shift 2 ;;
        --os) OS="$2"; shift 2 ;;
        --smoke) SMOKE=1; shift ;;
        --rust) RUST=1; shift ;;
        --help|-h)
            echo 'Go: cross-build.sh --arch arm64|loong64 [--os linux] [--smoke]'
            echo 'Rust (inside its floor container): cross-build.sh --rust --arch x86_64|arm64|loong64'
            exit 0 ;;
        *) echo "Unknown flag: $1"; exit 1 ;;
    esac
done

if [[ -z "$ARCH" ]]; then
    echo "Usage: cross-build.sh [--rust] --arch <x86_64|arm64|loong64> [--os linux] [--smoke]"
    exit 1
fi

if [[ "$RUST" -eq 1 ]]; then
    [[ "$OS" == linux ]] || { echo 'Rust floor builds require Linux' >&2; exit 1; }
    [[ "$SMOKE" -eq 0 ]] || { echo 'Rust smoke uses scripts/smoke-rust-floor.sh' >&2; exit 1; }
    case "$ARCH" in
        x86_64|amd64) TARGET=x86_64-unknown-linux-gnu; FLOOR=2.28 ;;
        arm64|aarch64) TARGET=aarch64-unknown-linux-gnu; FLOOR=2.28 ;;
        loong64|loongarch64) TARGET=loongarch64-unknown-linux-gnu; FLOOR=2.36 ;;
        *) echo "Unsupported Rust architecture: $ARCH" >&2; exit 1 ;;
    esac
    exec python3 "$ROOT/scripts/build-rust-floor.py" "$TARGET" "$FLOOR"
fi

OUTDIR="$ROOT/build/xinchuang/${ARCH}-${OS}"
mkdir -p "$OUTDIR"

echo "==> Building authserver for $OS/$ARCH"
cd "$ROOT/authserver"
CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build \
    -ldflags="-s -w -X main.version=$VERSION" \
    -o "$OUTDIR/authserverd" ./cmd/authserverd

echo "==> Building mailserver for $OS/$ARCH"
cd "$ROOT/mailserver"
CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" go build \
    -ldflags="-s -w -X main.version=$VERSION" \
    -o "$OUTDIR/mailserverd" ./cmd/mailserverd

echo "==> Binaries:"
ls -lh "$OUTDIR/authserverd" "$OUTDIR/mailserverd"
file "$OUTDIR/authserverd" "$OUTDIR/mailserverd"

if [[ "$SMOKE" -eq 1 ]]; then
    echo "==> QEMU smoke test"
    if ! command -v "qemu-${ARCH}" &>/dev/null && ! command -v "qemu-${ARCH}-static" &>/dev/null; then
        echo "WARNING: qemu-${ARCH} not found — skipping smoke test"
        exit 0
    fi
    QEMU="qemu-${ARCH}-static"
    if ! command -v "$QEMU" &>/dev/null; then
        QEMU="qemu-${ARCH}"
    fi

    # Smoke test: run authserverd --version (self-contained static binary)
    "$QEMU" "$OUTDIR/authserverd" --version 2>&1 || {
        echo "ERROR: authserverd binary failed QEMU smoke test"
        exit 1
    }
    "$QEMU" "$OUTDIR/mailserverd" --version 2>&1 || {
        echo "ERROR: mailserverd binary failed QEMU smoke test"
        exit 1
    }
    echo "QEMU smoke test passed."
fi

echo "Cross-build complete: $OUTDIR"
