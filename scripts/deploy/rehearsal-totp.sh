#!/bin/sh
# Pure rehearsal-only TOTP URI/code leaf shared by disposable D3/D4/D5,
# updater and rewind controllers. It owns no HTTP, retry, cookie, enrollment,
# credential-reset, topology, or evidence policy.
# R5_REHEARSAL_BOOTSTRAP_BOUNDARY
set -eu

usage() {
  echo 'usage: rehearsal-totp.sh secret <provisioning-uri> | code <base32-secret> [unix-time]' >&2
  exit 2
}

case "${1:-}" in
  secret)
    [ "$#" -eq 2 ] || usage
    python3 - "$2" <<'PY'
import sys
from urllib.parse import parse_qs, urlparse

values = parse_qs(urlparse(sys.argv[1]).query)
secrets = values.get("secret", [])
if len(secrets) != 1 or not secrets[0]:
    raise SystemExit("provisioning URI must contain exactly one non-empty secret")
print(secrets[0])
PY
    ;;
  code)
    [ "$#" -eq 2 ] || [ "$#" -eq 3 ] || usage
    python3 - "$2" "${3:-}" <<'PY'
import base64
import hashlib
import hmac
import struct
import sys
import time

secret = sys.argv[1]
now = int(sys.argv[2]) if sys.argv[2] else int(time.time())
key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
counter = now // 30
digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
offset = digest[-1] & 0x0F
value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
print(f"{value:06d}")
PY
    ;;
  *) usage ;;
esac
