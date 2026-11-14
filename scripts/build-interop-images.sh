#!/usr/bin/env bash
# build-interop-images.sh [LABEL]: build the protocol interop client images the IMAP, SMTP and LDAP
# container interop tests run (#141): setjoin-interop-imap:local and setjoin-interop-smtp:local
# (mailserver/deploy/docker/test-imap and test-smtp plus a CPython layer) and setjoin-interop-ldap:local
# (test-ldap, OpenLDAP clients). .github/workflows/ci-images.yml builds and pins them in
# .github/ci/images.lock and the lane preloads them; a dev host runs this script once. The tests never
# build, tag or remove images (the Go-deletion rehearsal rejects image mutations and unpinned images).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
label=()
[[ -n "${1:-}" ]] && label=(--label "$1")
contexts="$ROOT/mailserver/deploy/docker"
build() { docker build -q --network host ${label[@]+"${label[@]}"} "$@" >/dev/null; }
build -t setjoin-interop-imap-base:local "$contexts/test-imap"
build -t setjoin-interop-smtp-base:local "$contexts/test-smtp"
for proto in imap smtp; do
  printf 'FROM setjoin-interop-%s-base:local\nRUN apk add --no-cache python3\n' "$proto" |
    build -t "setjoin-interop-$proto:local" -
done
build -t setjoin-interop-ldap:local "$contexts/test-ldap"
echo "setjoin-interop-imap:local setjoin-interop-smtp:local setjoin-interop-ldap:local"
