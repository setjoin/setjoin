#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../../../.."
binary="${1:?supply the compiled Go recorder}"
output="${2:?supply a NEW golden output path}"
shift 2
test ! -e "$output"
docker run --rm --name gofree-boot-record --label org.setjoin.task=gofree-boot --network host \
 -v "$PWD:/src:ro" -w /src -v "$(dirname "$binary"):/recorder:ro" -v "$(dirname "$output"):/out" \
 -e TEST_DB_DSN -e DB_APP_DSN -e GOFREE_GO_SOURCE="$(git rev-parse HEAD)" \
 setjoin-ci-linux-tc:local-amd64 python3 server-rust/crates/boot/tests/oracle/oracle.py \
 record "/recorder/$(basename "$binary")" --output "/out/$(basename "$output")" "$@"
