#!/bin/sh
# Run one real browser-equivalent OIDC authorization-code flow from a retained
# Setjoin RP stack to a retained Setjoin OP stack. This helper intentionally
# performs mandatory first TOTP enrollment: its caller must supply a dedicated,
# resettable test account and must never use production credentials.
set -eu

: "${TEST_ADMIN_EMAIL:?missing TEST_ADMIN_EMAIL}"
: "${TEST_ADMIN_PASSWORD:?missing TEST_ADMIN_PASSWORD}"
RP_ORIGIN="${RP_ORIGIN:-https://mail.example.com}"
OP_ORIGIN="${OP_ORIGIN:-https://oidc-c.test}"
OIDC_PROVIDER="${OIDC_PROVIDER:-d4c}"

work=$(mktemp -d /tmp/setjoin-d4-oidc-flow.XXXXXX)
trap 'rm -rf "$work"' EXIT INT TERM
chmod 700 "$work"
jar="$work/cookies"
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
totp_helper="$script_dir/rehearsal-totp.sh"

status() {
  awk 'toupper($1) ~ /^HTTP/ {code=$2} END {print code}' "$1"
}

location() {
  awk 'BEGIN {IGNORECASE=1} /^Location:/ {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); value=$0} END {print value}' "$1"
}

join_url() {
  python3 - "$1" "$2" <<'PY'
import sys
from urllib.parse import urljoin
print(urljoin(sys.argv[1], sys.argv[2]))
PY
}

require_status() {
  actual=$(status "$1")
  expected=$2
  step=$3
  if [ "$actual" != "$expected" ]; then
    echo "OIDC_FLOW_FAIL step=$step status=$actual expected=$expected" >&2
    body=${1%.headers}.body
    if [ -s "$body" ]; then
      python3 - "$body" >&2 <<'PY'
import json, sys
try:
    value = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    raise SystemExit(0)
for key in ("detail", "error", "title"):
    if key in value:
        print(f"OIDC_FLOW_PROBLEM {key}={value[key]}")
PY
    fi
    exit 1
  fi
  echo "OIDC_FLOW_OK step=$step status=$actual"
}

request() {
  name=$1
  shift
  curl -ksS --max-time 30 \
    -D "$work/$name.headers" -o "$work/$name.body" \
    -c "$jar" -b "$jar" "$@"
}

request start "$RP_ORIGIN/auth/oidc/login?provider=$OIDC_PROVIDER"
require_status "$work/start.headers" 302 rp_start
authorize_url=$(join_url "$RP_ORIGIN/" "$(location "$work/start.headers")")

request authorize "$authorize_url"
require_status "$work/authorize.headers" 302 op_authorize
complete_url=$(join_url "$authorize_url" "$(location "$work/authorize.headers")")

request anonymous_complete "$complete_url"
require_status "$work/anonymous_complete.headers" 302 anonymous_complete
continue_url=$(join_url "$complete_url" "$(location "$work/anonymous_complete.headers")")
python3 - "$continue_url" "$complete_url" <<'PY'
import sys
from urllib.parse import parse_qs, urlparse
actual = urlparse(sys.argv[1])
expected = urlparse(sys.argv[2])
values = parse_qs(actual.query, keep_blank_values=True)
want = expected.path + ("?" + expected.query if expected.query else "")
if actual.path != "/" or values.get("continue") != [want]:
    raise SystemExit("anonymous completion did not preserve the exact same-origin continuation")
PY
echo "OIDC_FLOW_OK step=login_continuation"

python3 - "$TEST_ADMIN_EMAIL" "$TEST_ADMIN_PASSWORD" >"$work/login.json" <<'PY'
import json, sys
json.dump({"email": sys.argv[1], "password": sys.argv[2]}, sys.stdout)
PY
request login -H "Content-Type: application/json" \
  --data-binary "@$work/login.json" "$OP_ORIGIN/auth/login"
require_status "$work/login.headers" 403 password_login
mfa_token=$(python3 - "$work/login.body" <<'PY'
import json, sys
body = json.load(open(sys.argv[1], encoding="utf-8"))
if body.get("status") != "mfa_enrollment_required":
    raise SystemExit("mandatory MFA enrollment was not required")
print(body["mfa_token"])
PY
)

python3 - "$mfa_token" >"$work/setup.json" <<'PY'
import json, sys
json.dump({"mfa_token": sys.argv[1]}, sys.stdout)
PY
request setup -H "Content-Type: application/json" \
  --data-binary "@$work/setup.json" "$OP_ORIGIN/auth/totp/enroll/setup"
require_status "$work/setup.headers" 200 totp_setup

totp_uri=$(python3 - "$work/setup.body" <<'PY'
import json, sys
body = json.load(open(sys.argv[1], encoding="utf-8"))
print(body["provisioning_uri"])
PY
)
totp_secret=$(sh "$totp_helper" secret "$totp_uri")
totp_code=$(sh "$totp_helper" code "$totp_secret")
python3 - "$mfa_token" "$totp_code" >"$work/confirm.json" <<'PY'
import json, sys
json.dump({"mfa_token": sys.argv[1], "code": sys.argv[2]}, sys.stdout)
PY
request confirm -H "Content-Type: application/json" \
  --data-binary "@$work/confirm.json" "$OP_ORIGIN/auth/totp/enroll/confirm"
require_status "$work/confirm.headers" 200 totp_confirm

request complete "$complete_url"
require_status "$work/complete.headers" 302 authenticated_complete
op_callback_url=$(join_url "$complete_url" "$(location "$work/complete.headers")")

request op_callback "$op_callback_url"
require_status "$work/op_callback.headers" 302 op_callback
rp_callback_url=$(join_url "$op_callback_url" "$(location "$work/op_callback.headers")")

request rp_callback "$rp_callback_url"
require_status "$work/rp_callback.headers" 200 rp_callback
python3 - "$work/rp_callback.body" <<'PY'
import json, sys
body = json.load(open(sys.argv[1], encoding="utf-8"))
if not body.get("access_token"):
    raise SystemExit("RP callback did not issue an access token")
PY

request me "$RP_ORIGIN/auth/me"
require_status "$work/me.headers" 200 rp_session
python3 - "$work/me.body" <<'PY'
import json, sys
body = json.load(open(sys.argv[1], encoding="utf-8"))
if not body.get("user_id"):
    raise SystemExit("RP session did not resolve an authenticated user")
PY

echo "OIDC_FLOW_PASS"
