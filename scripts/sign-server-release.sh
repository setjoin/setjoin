#!/usr/bin/env bash
# Build, sign and independently verify a server manifest before publishing it.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -lt 11 ]]; then
  echo 'usage: sign-server-release.sh DRAFT ARTIFACTS ROOTS HELPER OUTPUT CHANNEL CURRENT_VERSION PLATFORM ARCH KEY_ID KEY_ID [KEY_ID...]' >&2
  exit 1
fi
draft=$1 artifacts=$2 roots=$3 helper=$4 output=$5 channel=$6 current=$7 platform=$8 arch=$9
shift 9
publisher=${SETJOIN_RELEASE_BIN:-}
if [[ -z "$publisher" ]]; then
  cargo build --locked --release --manifest-path "$ROOT/server-rust/Cargo.toml" -p setjoin-release
  target_dir=$(cargo metadata --locked --no-deps --format-version 1 --manifest-path "$ROOT/server-rust/Cargo.toml" | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
  publisher="$target_dir/release/setjoin-release"
fi
[[ -x "$publisher" && -x "$helper" ]] || { echo 'publisher and signer helper must be executable' >&2; exit 1; }
output_dir=$(dirname -- "$output")
stage=$(mktemp -d "$output_dir/.setjoin-release-sign.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
"$publisher" manifest build --draft "$draft" --artifacts-dir "$artifacts" --output "$stage/manifest.json"
for key_id in "$@"; do
  "$publisher" manifest sign --manifest "$stage/manifest.json" --signer-helper "$helper" --key-id "$key_id" --output "$stage/manifest.json"
done
"$publisher" manifest verify --offline --manifest "$stage/manifest.json" --artifacts-dir "$artifacts" \
  --trust-roots "$roots" --channel "$channel" --current-version "$current" --platform "$platform" --arch "$arch"
# Same-filesystem rename; the publisher has already fsynced the signed file.
python3 - "$stage/manifest.json" "$output" "$output_dir" <<'PY'
import os, sys
os.replace(sys.argv[1], sys.argv[2])
fd = os.open(sys.argv[3], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
