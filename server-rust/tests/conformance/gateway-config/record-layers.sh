#!/usr/bin/env bash
# Test-only overlay; frozen Go production sources remain unchanged.
set -euo pipefail
cd "$(dirname "$0")/../../../.."
output="${1:?usage: record-layers.sh OUTPUT (new path; never overwrite goldens)}"
test ! -e "$output"
tmp=$(mktemp -d /tmp/gofree-gwconfig-layers.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/overlay.json" <<'JSON'
{"Replace":{"/src/mailserver/internal/config/gwconfig_record_test.go":"/src/server-rust/tests/conformance/gateway-config/record_layers_test.go.txt"}}
JSON
docker run --rm --name gofree-gwconfig-record-layers --network host \
 -v "$PWD:/src:ro" -w /src/mailserver \
 -v "${GOFREE_GO_MOD_CACHE:-$HOME/go/pkg/mod}:/root/go/pkg/mod" \
 -v "$tmp:/evidence" \
 -e GWCONFIG_CASES=/src/server-rust/tests/conformance/gateway-config/layers.json \
 -e GWCONFIG_OUTPUT=/evidence/layers.json \
 setjoin-ci-linux-tc:local-amd64 \
 go test -overlay /evidence/overlay.json ./internal/config -run '^TestGWConfigRecord$' -count=1
cp "$tmp/layers.json" "$output"
