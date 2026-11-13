#!/usr/bin/env bash
# verify-server-rust-image.sh — run the server-rust guard INSIDE the Linux CI
# toolchain image (.github/ci/linux-toolchain.Dockerfile), so the image's
# claim to build and test the Rust workspace is executed, not asserted (#211
# review item 8).
#
# Usage: bash scripts/verify-server-rust-image.sh [IMAGE]
#   IMAGE defaults to $SERVER_RUST_IMAGE or setjoin-ci-linux-tc:local-<arch>
#   (<arch> = the host's dpkg/uname architecture: amd64 or arm64). Build it
#   first with:
#     docker build -t setjoin-ci-linux-tc:local-amd64 -f .github/ci/linux-toolchain.Dockerfile .github/ci
#
# What runs in a throwaway container (--rm, no published ports, repository
# mounted read-only): `rustc --version`, then `bash scripts/check-server-rust.sh
# --self-test` and `bash scripts/check-server-rust.sh` with CARGO_HOME and
# CARGO_TARGET_DIR on container-local tmpfs paths (the locked dependencies are
# fetched once inside the container; nothing is written to the checkout). No
# database is attached, so DB-backed cases print their SKIP markers (counted by
# the guard); REQUIRE_DB is not set here.
#
# The result line names the architecture it ran on. Only the architecture of
# the host that ran this script is evidence; any other is NOT_RUN.
#
# Not a scripts/check-*.sh guard: it needs Docker and an image, which the CI
# guard runner does not provide.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) ARCH="$(uname -m)" ;;
esac
IMAGE="${1:-${SERVER_RUST_IMAGE:-setjoin-ci-linux-tc:local-$ARCH}}"
NAME="setjoin-server-rust-image-$$"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "SERVER-RUST-IMAGE NOT_RUN (reason=image-missing image=$IMAGE arch=$ARCH)"
  exit 1
fi

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# The checkout is read-only; the guard writes only under CARGO_TARGET_DIR,
# CARGO_HOME and mktemp, all container-local.
docker run --rm --name "$NAME" \
  -v "$ROOT:/work:ro" -w /work \
  --tmpfs /cargo:exec,size=8g \
  -e CARGO_HOME=/cargo/home -e CARGO_TARGET_DIR=/cargo/target \
  "$IMAGE" bash -euo pipefail -c '
    image_arch="$(dpkg --print-architecture)"
    echo "server-rust in image: arch=$image_arch $(rustc --version)"
    bash scripts/check-server-rust.sh --self-test
    bash scripts/check-server-rust.sh
    echo "SERVER-RUST-IMAGE PASS (arch=$image_arch)"
  '
