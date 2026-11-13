#!/usr/bin/env bash
# Adapter for smoke-rust-floor.sh: execute the compiled LoongArch gateway in
# the scratch image whose rootfs is the glibc 2.36 new-world sysroot.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
binary="$root/build/rust-floor/loongarch64/loongarch64-unknown-linux-gnu/release/setjoin-gateway"
[[ -x "$binary" ]] || { echo "missing gateway: $binary" >&2; exit 1; }
name="setjoin-floor-loong-smoke-$$"
cleanup() {
  if docker container inspect "$name" >/dev/null 2>&1; then
    docker stop --time 5 "$name" >/dev/null || true
  fi
  if docker container inspect "$name" >/dev/null 2>&1; then
    echo "container cleanup failed: $name" >&2
    return 1
  fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM
docker run --rm --name "$name" --network host \
  -e GATEWAY_LISTEN -e GATEWAY_AUTH_UPSTREAM \
  --mount "type=bind,source=$binary,target=/setjoin-gateway,readonly" \
  setjoin-rust-loong-floor:ci /setjoin-gateway "$@" &
wait "$!"
