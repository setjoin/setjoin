#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../../../.."
output="${1:?supply a new output directory}"
mkdir "$output"
cache="${BOOT_GO_CACHE:-$output/cache}"
mkdir -p "$cache"
printf '{"Replace":{"/src/mailserver/internal/startup/boot_record_test.go":"/src/server-rust/crates/boot/tests/oracle/record_test.go.txt"}}\n' > "$output/overlay.json"
docker run --rm --name gofree-boot-recorder-build --label org.setjoin.task=gofree-boot --network host \
 -v "$PWD:/src:ro" -w /src/mailserver -v "${GOFREE_GO_MOD_CACHE:-$HOME/go/pkg/mod}:/root/go/pkg/mod" \
 -v "$cache:/root/.cache/go-build" \
 -v "$output:/out" setjoin-ci-linux-tc:local-amd64 \
 go test -p 1 -overlay /out/overlay.json -c -o /out/boot-go.test ./internal/startup
