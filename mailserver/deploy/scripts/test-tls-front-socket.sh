#!/usr/bin/env bash
# Hermetic release seam: public TLS belongs to the native activated front door.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
source "$ROOT/mailserver/deploy/scripts/lib-livekit.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/gofree-tlsfront-render.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
INSTALL_DIR="$tmp/runtime" GATEWAY_ENV="$tmp/gateway.env" CONFIG_ENV="$tmp/config.env" DB_CRED_FILE="$tmp/db.env" TLS_ENV="$tmp/tls.env"
cat > "$CONFIG_ENV" <<'ENV'
HOSTNAME=mail.example.test
LISTEN_ADDR=:443
TLS_CERT=/fixture/leaf.crt
TLS_KEY=/fixture/leaf.key
TLS_AUTOCERT_DOMAINS=mail.example.test
TLS_AUTOCERT_CHALLENGE=tls-alpn-01
TLS_AUTOCERT_EMAIL=ops@example.test
TLS_AUTOCERT_CACHE_DIR=/var/cache/mailserver/fixture-autocert
TLS_SESSION_TICKET_KEY_ROTATE_SECS=60
TLS_DNS_PROVIDER=cloudflare
TLS_DNS_CONFIG={"CF_API_TOKEN":"literal-$-value"}
DB_DSN=postgres://app@fixture/db
GO_WORKERS_OFF=backup-engine,federation-service,federation-residue-reap
RUST_WORKERS_ON=federation-residue-reap
DB_OWNER_DSN=must-not-reach-gateway
S3_SECRET_KEY=must-not-reach-gateway
JWT_SECRET=must-not-reach-gateway
ENV
cat > "$DB_CRED_FILE" <<'ENV'
DB_WORKER_DSN=postgres://worker@fixture/db
DB_OWNER_DSN=must-not-reach-gateway
ENV
configure_tls_front "$CONFIG_ENV"
render_tls_front_env "$TLS_ENV" "$CONFIG_ENV"
render_federation_env "$tmp/federation.env" "$CONFIG_ENV" "$DB_CRED_FILE"
render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/setjoin-gateway.service"
test -s "$tmp/setjoin-https.socket"
grep -qx 'FileDescriptorName=https' "$tmp/setjoin-https.socket"
grep -qx 'ListenStream=443' "$tmp/setjoin-https.socket"
grep -qx 'Service=setjoin-gateway.service' "$tmp/setjoin-https.socket"
grep -qx 'Wants=setjoin-https.socket' "$tmp/setjoin-gateway.service"
grep -qx "EnvironmentFile=-$TLS_ENV" "$tmp/setjoin-gateway.service"
grep -qx 'ReadWritePaths=-/var/cache/mailserver/fixture-autocert' "$tmp/setjoin-gateway.service"
grep -qx 'CapabilityBoundingSet=' "$tmp/setjoin-gateway.service"
grep -qx 'LISTEN_ADDR=127.0.0.1:0' "$CONFIG_ENV"
for name in cert-monitor tls-ticket-keys http-tls http-h2c acme-renewal; do
  for key in GO_WORKERS_OFF RUST_WORKERS_ON; do
    sed -n "s/^$key=//p" "$tmp/federation.env" | tr ',' '\n' | grep -qx "$name"
  done
done
grep -q '^RUST_WORKERS_ON=.*federation-residue-reap' "$tmp/federation.env"
grep -qx 'TLS_CERT=/fixture/leaf.crt' "$TLS_ENV"
grep -qx 'TLS_SESSION_TICKET_KEY_ROTATE_SECS=60' "$TLS_ENV"
grep -Fxq 'TLS_DNS_CONFIG={"CF_API_TOKEN":"literal-$-value"}' "$TLS_ENV"
if grep -Eq 'OWNER_DSN|S3_SECRET|JWT_SECRET|DB_DSN' "$TLS_ENV"; then echo 'secret leaked to tls.env' >&2; exit 1; fi
test "$(stat -c '%a' "$TLS_ENV")" = 640
# Re-rendering is idempotent and leaves unrelated worker ownership intact.
cp "$CONFIG_ENV" "$tmp/once.env"
configure_tls_front "$CONFIG_ENV"
diff -u "$tmp/once.env" "$CONFIG_ENV"
# Config regeneration preserves managed settings and literal credentials;
# explicit empty/updated environment assignments override previous values.
TLS_AUTOCERT_EMAIL=new@example.test TLS_DNS_PROVIDER=cloudflare tls_front_preserve_settings "$CONFIG_ENV" > "$tmp/preserved.env"
grep -qx 'TLS_AUTOCERT_EMAIL=new@example.test' "$tmp/preserved.env"
grep -qx 'TLS_SESSION_TICKET_KEY_ROTATE_SECS=60' "$tmp/preserved.env"
grep -Fxq 'TLS_DNS_CONFIG={"CF_API_TOKEN":"literal-$-value"}' "$tmp/preserved.env"
if grep -Eq 'OWNER_DSN|S3_SECRET|JWT_SECRET|DB_DSN' "$tmp/preserved.env"; then echo 'secret leaked to preserved.env' >&2; exit 1; fi
GATEWAY_HTTPS_LISTEN='[::1]:1443' render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/setjoin-gateway.service"
grep -Fxq 'ListenStream=[::1]:1443' "$tmp/setjoin-https.socket"
cat > "$tmp/yaml-config.env" <<'ENV'
HOSTNAME=mail.example.test
ENV
cat > "$tmp/setjoin.yaml" <<'YAML'
tls:
  nested:
    autocert_cache_dir: /wrong/nested/path
  "autocert_cache_dir": /var/lib/setjoin/custom-tls
YAML
echo 'TLS_AUTOCERT_CACHE_DIR=/var/lib/setjoin/stale-cache' > "$tmp/yaml-gateway.env"
CONFIG_ENV="$tmp/yaml-config.env" GATEWAY_ENV="$tmp/yaml-gateway.env" AUTHSERVER_URL=http://127.0.0.1:8443 SETJOIN_CONFIG="$tmp/setjoin.yaml" render_gateway_env "$tmp/yaml-gateway.env"
grep -qx 'TLS_AUTOCERT_CACHE_DIR=/var/lib/setjoin/custom-tls' "$tmp/yaml-gateway.env"
CONFIG_ENV="$tmp/yaml-config.env" GATEWAY_ENV="$tmp/yaml-gateway.env" SETJOIN_CONFIG="$tmp/setjoin.yaml" render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/yaml-gateway.service"
grep -qx 'ReadWritePaths=-/var/lib/setjoin/custom-tls' "$tmp/yaml-gateway.service"

cat > "$tmp/quoted-config.env" <<'ENV'
HOSTNAME=mail.example.test
TLS_AUTOCERT_CACHE_DIR="/var/lib/setjoin/quoted"
WORM_MODE="compliance"
WORM_RETENTION_DAYS="3650"
WORM_LEGAL_HOLD_ENABLED=
S3_ENDPOINT=http://127.0.0.1:9000
S3_BUCKET=mailblobs
S3_ACCESS_KEY=ak-test
S3_SECRET_KEY=must-not-reach-gateway
DB_OWNER_DSN=must-not-reach-gateway
JWT_SECRET=must-not-reach-gateway
ENV
CONFIG_ENV="$tmp/quoted-config.env" GATEWAY_ENV="$tmp/quoted-gateway.env" AUTHSERVER_URL=http://127.0.0.1:8443 render_gateway_env "$tmp/quoted-gateway.env"
grep -qx 'TLS_AUTOCERT_CACHE_DIR=/var/lib/setjoin/quoted' "$tmp/quoted-gateway.env"
grep -qx 'WORM_MODE=compliance' "$tmp/quoted-gateway.env"
grep -qx 'WORM_RETENTION_DAYS=3650' "$tmp/quoted-gateway.env"
grep -qx 'WORM_LEGAL_HOLD_ENABLED=' "$tmp/quoted-gateway.env"
if grep -Eq 'OWNER_DSN|S3_SECRET|JWT_SECRET' "$tmp/quoted-gateway.env"; then echo 'secret leaked to gateway.env' >&2; exit 1; fi
tls_front_preserve_settings "$tmp/quoted-config.env" > "$tmp/quoted-preserved.env"
grep -qx 'WORM_MODE="compliance"' "$tmp/quoted-preserved.env"
grep -qx 'WORM_RETENTION_DAYS="3650"' "$tmp/quoted-preserved.env"
grep -qx 'WORM_LEGAL_HOLD_ENABLED=' "$tmp/quoted-preserved.env"
CONFIG_ENV="$tmp/quoted-config.env" GATEWAY_ENV="$tmp/quoted-gateway.env" render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/quoted-gateway.service"
grep -qx 'ReadWritePaths=-/var/lib/setjoin/quoted' "$tmp/quoted-gateway.service"

# Storage allowlist is rendered independent of SMTP enablement.
printf 'SMTP_FRONT_ENABLED=false\nSMTP_INBOUND_ADDR=\nSMTP_SUBMISSION_ADDR=\n' >> "$tmp/quoted-config.env"
render_smtp_env "$tmp/quoted-smtp.env" "$tmp/quoted-config.env" /nonexistent
test ! -s "$tmp/quoted-smtp.env"
render_storage_env "$tmp/quoted-storage.env" "$tmp/quoted-config.env"
grep -qx 'S3_ENDPOINT=http://127.0.0.1:9000' "$tmp/quoted-storage.env"
grep -qx 'S3_BUCKET=mailblobs' "$tmp/quoted-storage.env"
grep -qx 'S3_ACCESS_KEY=ak-test' "$tmp/quoted-storage.env"
grep -qx 'S3_SECRET_KEY=must-not-reach-gateway' "$tmp/quoted-storage.env"
if grep -Eq 'OWNER_DSN|JWT_SECRET|DB_DSN' "$tmp/quoted-storage.env"; then echo 'secret leaked to storage.env' >&2; exit 1; fi
test "$(stat -c '%a' "$tmp/quoted-storage.env")" = 640

# Quoted empty TLS_AUTOCERT_CACHE_DIR="" must not enter tls.env and override gateway.env.
cat > "$tmp/empty-cache.env" <<'ENV'
HOSTNAME=mail.example.test
TLS_AUTOCERT_CACHE_DIR=""
ENV
render_tls_front_env "$tmp/empty-tls.env" "$tmp/empty-cache.env"
if grep -q '^TLS_AUTOCERT_CACHE_DIR=' "$tmp/empty-tls.env"; then echo 'TLS_AUTOCERT_CACHE_DIR leaked into tls.env' >&2; exit 1; fi
CONFIG_ENV="$tmp/empty-cache.env" GATEWAY_ENV="$tmp/empty-gateway.env" AUTHSERVER_URL=http://127.0.0.1:8443 render_gateway_env "$tmp/empty-gateway.env"
grep -qx 'TLS_AUTOCERT_CACHE_DIR=/var/cache/mailserver/autocert' "$tmp/empty-gateway.env"
CONFIG_ENV="$tmp/empty-cache.env" GATEWAY_ENV="$tmp/empty-gateway.env" render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/empty-gateway.service"
grep -qx 'ReadWritePaths=-/var/cache/mailserver/autocert' "$tmp/empty-gateway.service"

cat > "$tmp/flow.yaml" <<'YAML'
tls: {
  nested: { autocert_cache_dir: /wrong/flow }, # comment after comma must not hide next entry
  autocert_cache_dir: "/var/lib/setjoin\/flow-tls"
}
worm:
  mode: governance
  retention_days: 730
  legal_hold_enabled: false
s3:
  endpoint: http://127.0.0.1:9100
  secure: false
  bucket: yaml-blobs
  access_key: yaml-ak
  secret_key: yaml-sk
YAML
CONFIG_ENV="$tmp/yaml-config.env" GATEWAY_ENV="$tmp/flow-gateway.env" AUTHSERVER_URL=http://127.0.0.1:8443 SETJOIN_CONFIG="$tmp/flow.yaml" render_gateway_env "$tmp/flow-gateway.env"
grep -qx 'TLS_AUTOCERT_CACHE_DIR=/var/lib/setjoin/flow-tls' "$tmp/flow-gateway.env"
grep -qx 'WORM_MODE=governance' "$tmp/flow-gateway.env"
grep -qx 'WORM_RETENTION_DAYS=730' "$tmp/flow-gateway.env"
# Go overrides YAML worm.legal_hold_enabled unless WORM_LEGAL_HOLD_ENABLED is explicitly set in env.
if grep -q '^WORM_LEGAL_HOLD_ENABLED=' "$tmp/flow-gateway.env"; then echo 'YAML worm.legal_hold_enabled should not override Go default' >&2; exit 1; fi
CONFIG_ENV="$tmp/yaml-config.env" GATEWAY_ENV="$tmp/flow-gateway.env" SETJOIN_CONFIG="$tmp/flow.yaml" render_gateway_unit "$ROOT/mailserver/deploy/setjoin-gateway.service.template" "$tmp/flow-gateway.service"
grep -qx 'ReadWritePaths=-/var/lib/setjoin/flow-tls' "$tmp/flow-gateway.service"

# YAML-only S3 settings populate storage.env when config.env has no S3_* literals, and SETJOIN_CONFIG is preserved.
SETJOIN_CONFIG="$tmp/flow.yaml" render_storage_env "$tmp/yaml-storage.env" "$tmp/yaml-config.env"
grep -qx 'S3_ENDPOINT=http://127.0.0.1:9100' "$tmp/yaml-storage.env"
grep -qx 'S3_BUCKET=yaml-blobs' "$tmp/yaml-storage.env"
grep -qx 'S3_ACCESS_KEY=yaml-ak' "$tmp/yaml-storage.env"
grep -qx 'S3_SECRET_KEY=yaml-sk' "$tmp/yaml-storage.env"
SETJOIN_CONFIG="$tmp/flow.yaml" tls_front_preserve_settings "$tmp/yaml-config.env" > "$tmp/yaml-preserved.env"
grep -qx "SETJOIN_CONFIG=$tmp/flow.yaml" "$tmp/yaml-preserved.env"

# Double-quoted YAML backslash/\u0023/\u002f/multiline-hash escapes and single-quoted '' unescaping.
cat > "$tmp/esc.yaml" <<'YAML'
tls:
  autocert_cache_dir: "\u002fvar/lib\\setjoin/cache\u0023hash"
worm:
  mode: "line1 # keep
    line2"
s3:
  bucket: 'it''s-blobs'
YAML
esc_val=$(yaml_section_value "$tmp/esc.yaml" tls autocert_cache_dir)
test "$esc_val" = '/var/lib\setjoin/cache#hash'
hash_val=$(yaml_section_value "$tmp/esc.yaml" worm mode)
test "$hash_val" = 'line1 # keep line2'
squote_val=$(yaml_section_value "$tmp/esc.yaml" s3 bucket)
test "$squote_val" = "it's-blobs"

# Missing or syntactically invalid YAML fails closed (exit status 2).
printf 'tls: [unclosed\n' > "$tmp/bad.yaml"
rc=0; yaml_section_value "$tmp/bad.yaml" tls autocert_cache_dir 2>/dev/null || rc=$?
test "$rc" = 2
rc=0; yaml_section_value "$tmp/does-not-exist.yaml" tls autocert_cache_dir 2>/dev/null || rc=$?
test "$rc" = 2

# validate_tls_cache_target rejects control chars, trailing-slash symlinks, intermediate parent symlinks, and top-level dirs.
mkdir -p "$tmp/real-dir/sub1/sub2"
ln -s "$tmp/real-dir" "$tmp/sym-dir" 2>/dev/null || true
if [ "$(uname -s)" = Linux ] && [ ! -L "$tmp/sym-dir" ]; then
  echo 'expected symlink creation on Linux' >&2
  exit 1
fi
if [ -L "$tmp/sym-dir" ]; then
  ln -s / "$tmp/sym-root"
  for bad_sym in "$tmp/sym-root" "$tmp/sym-root/" "$tmp/sym-root/autocert" "$tmp/sym-dir" "$tmp/sym-dir/" "$tmp/sym-dir/sub1/sub2"; do
    if validate_tls_cache_target "$bad_sym" 2>/dev/null; then
      echo "validate_tls_cache_target accepted symlink: $bad_sym" >&2
      exit 1
    fi
  done
fi
for bad in / /etc /var/../etc /var/cache/.. relative/path $'/tmp/has\nnewline' $'/tmp/ctrl\x01char' '/tmp/has space'; do
  if validate_tls_cache_target "$bad" 2>/dev/null; then
    echo "validate_tls_cache_target accepted unsafe path: $bad" >&2
    exit 1
  fi
done

# systemd EnvironmentFile parser + Go config.go S3/MINIO precedence (including bogus S3_SECURE + MINIO_SECURE,
# explicit empty S3_ACCESS_KEY=, and double-quoted unrecognized backslash preservation in config.env).
cat > "$tmp/tricky-s3.yaml" <<'YAML'
hostname: trace.example.test
internal:
  domains: localhost
s3:
  endpoint: 127.0.0.1:9000
  bucket: mailblobs
  secure: false
  access_key: ak-yaml
  secret_key: '  lead\mid"quote#hash  '
worm:
  mode: compliance
YAML
cat > "$tmp/tricky-config.env" <<'ENV'
S3_BUCKET=mailblobs
MINIO_BUCKET=minio-override
S3_SECURE=bogus
MINIO_SECURE=true
S3_ACCESS_KEY=
WORM_MODE=
INTERNAL_DOMAINS=
ENV
SETJOIN_CONFIG="$tmp/tricky-s3.yaml" render_storage_env "$tmp/tricky-storage.env" "$tmp/tricky-config.env"
grep -qx 'S3_BUCKET=minio-override' "$tmp/tricky-storage.env"
grep -qx 'S3_SECURE=true' "$tmp/tricky-storage.env"
grep -qx 'S3_ACCESS_KEY=' "$tmp/tricky-storage.env"

cat > "$tmp/bs-config.env" <<'ENV'
S3_ENDPOINT=127.0.0.1:9000
S3_SECRET_KEY="abc\def\\g\"h\$i"
ENV
render_storage_env "$tmp/bs-storage.env" "$tmp/bs-config.env"
python3 - "$tmp/tricky-storage.env" "$tmp/bs-storage.env" <<'PY'
import sys
def parse_systemd(path):
    parsed = {}
    for line in open(path, encoding="utf-8"):
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, raw = s.split("=", 1)
        if raw.startswith('"'):
            out, i = [], 1
            while i < len(raw):
                ch = raw[i]
                if ch == '"':
                    break
                if ch == "\\" and i + 1 < len(raw) and raw[i + 1] in ("\\", '"', "$", "`"):
                    out.append(raw[i + 1]); i += 2; continue
                out.append(ch); i += 1
            parsed[k] = "".join(out)
        else:
            parsed[k] = raw
    return parsed
tricky = parse_systemd(sys.argv[1])
assert tricky["S3_SECRET_KEY"] == '  lead\\mid"quote#hash  ', tricky
bs = parse_systemd(sys.argv[2])
assert bs["S3_SECRET_KEY"] == 'abc\\def\\g"h$i', bs
PY

# Explicit empty INTERNAL_DOMAINS= and WORM_MODE= suppress YAML defaults, while exported HOSTNAME beats YAML hostname,
# and YAML default internal.domains=localhost is omitted when HOSTNAME is set (matching Go config.go).
(
  unset HOSTNAME
  SETJOIN_CONFIG="$tmp/tricky-s3.yaml" CONFIG_ENV="$tmp/tricky-config.env" GATEWAY_ENV="$tmp/tricky-gw.env" AUTHSERVER_URL=http://127.0.0.1:8443 render_gateway_env "$tmp/tricky-gw.env"
)
grep -qx 'WORM_MODE=' "$tmp/tricky-gw.env"
grep -qx 'HOSTNAME=trace.example.test' "$tmp/tricky-gw.env"
grep -qx 'INTERNAL_DOMAINS=' "$tmp/tricky-gw.env"
CONFIG_ENV="$tmp/tricky-config.env" tls_front_preserve_settings "$tmp/tricky-config.env" > "$tmp/tricky-preserved.env"
grep -qx 'WORM_MODE=' "$tmp/tricky-preserved.env"
grep -qx 'INTERNAL_DOMAINS=' "$tmp/tricky-preserved.env"

: > "$tmp/empty-host.env"
HOSTNAME=env.example.test SETJOIN_CONFIG="$tmp/tricky-s3.yaml" CONFIG_ENV="$tmp/empty-host.env" GATEWAY_ENV="$tmp/envhost-gw.env" AUTHSERVER_URL=http://127.0.0.1:8443 render_gateway_env "$tmp/envhost-gw.env"
grep -qx 'HOSTNAME=env.example.test' "$tmp/envhost-gw.env"
if grep -q '^INTERNAL_DOMAINS=' "$tmp/envhost-gw.env"; then echo 'YAML localhost should defer to HOSTNAME' >&2; exit 1; fi

cat > "$tmp/quoted-root.yaml" <<'YAML'
"tls":
  autocert_cache: /fixture/quoted-cache
YAML
[ "$(python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" get "$tmp/quoted-root.yaml" tls autocert_cache)" = "/fixture/quoted-cache" ]

printf 'tls: cache: invalid\n' > "$tmp/bad-plain.yaml"
rc=0; python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" get "$tmp/bad-plain.yaml" tls cache >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || { echo "expected exit 2 for plain ': ', got $rc" >&2; exit 1; }

cat > "$tmp/alias.yaml" <<'YAML'
defaults: &p
  autocert_cache: /fixture/alias-cache
tls: *p
YAML
[ "$(python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" get "$tmp/alias.yaml" tls autocert_cache)" = "/fixture/alias-cache" ]

printf 'tls:\n  autocert_cache: *missing\n' > "$tmp/missing-alias.yaml"
rc=0; python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" get "$tmp/missing-alias.yaml" tls autocert_cache >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || { echo "expected exit 2 for undefined alias, got $rc" >&2; exit 1; }

cat > "$tmp/multiline-s3.env" <<'ENV'
S3_ENDPOINT=127.0.0.1:9000
S3_SECURE=" true "
S3_SECRET_KEY="line1
line2"
ENV
python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" render-storage "$tmp/multiline-s3.env" > "$tmp/multiline-storage.out"
grep -qx 'S3_SECURE=false' "$tmp/multiline-storage.out"
python3 - "$ROOT/mailserver/deploy/scripts/yaml-config.py" "$tmp/multiline-storage.out" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("yc", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
parsed = mod.parse_systemd_env_file(sys.argv[2])
assert parsed.get("S3_SECRET_KEY") == "line1\nline2", parsed
assert parsed.get("S3_SECURE") == "false", parsed
PY

if validate_tls_cache_target '/tmp/cache%h' 2>/dev/null; then
  echo 'expected % systemd specifier rejection' >&2
  exit 1
fi

for bad_cache in /var/lib /var/cache '/tmp/a"b' "/tmp/a'b" '/tmp/a\b'; do
  if validate_tls_cache_target "$bad_cache" 2>/dev/null; then
    echo "expected rejection for $bad_cache" >&2
    exit 1
  fi
done

cat > "$tmp/merge.yaml" <<'YAML'
defaults: &p
  endpoint: 127.0.0.1:9001
  bucket: merged-bucket
s3:
  bucket: override-bucket
  <<: *p
YAML
[ "$(python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" get "$tmp/merge.yaml" s3 endpoint)" = "127.0.0.1:9001" ]
[ "$(python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" get "$tmp/merge.yaml" s3 bucket)" = "override-bucket" ]

cat > "$tmp/dup-key.yaml" <<'YAML'
tls:
  a: 1
  a: 2
YAML
rc=0; python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" get "$tmp/dup-key.yaml" tls a >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || { echo "expected exit 2 for duplicate YAML key, got $rc" >&2; exit 1; }

cat > "$tmp/tags-blocks.yaml" <<'YAML'
tls:
  str_bool: !!str true
  lit: |2
      deep
  keep: |+
    line1

  fold: >
    alpha
    beta

    gamma
YAML
[ "$(python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" get "$tmp/tags-blocks.yaml" tls str_bool)" = "true" ]
python3 - "$ROOT/mailserver/deploy/scripts/yaml-config.py" "$tmp/tags-blocks.yaml" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("yc", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
doc = mod.parse_yaml_mapping(sys.argv[2])["tls"]
assert doc["str_bool"] == "true" and isinstance(doc["str_bool"], str), doc
assert doc["lit"] == "  deep\n", repr(doc["lit"])
assert doc["keep"] == "line1\n\n", repr(doc["keep"])
assert doc["fold"] == "alpha beta\ngamma\n", repr(doc["fold"])
PY

printf 's3:\n  secure: 1.0\n' > "$tmp/float-bool.yaml"
printf 's3:\n  secure: "1.0"\n' > "$tmp/str-float-bool.yaml"
: > "$tmp/empty-env.env"
python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" render-storage "$tmp/empty-env.env" "$tmp/float-bool.yaml" | grep -qx 'S3_SECURE=true'
python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" render-storage "$tmp/empty-env.env" "$tmp/str-float-bool.yaml" | grep -qx 'S3_SECURE=false'

cat > "$tmp/systemd-edge.env" <<'ENV'
S3_ENDPOINT=127.0.0.1:9000
S3_SECRET_KEY="part1"part2
S3_ACCESS_KEY=foo\ bar\\baz
ENV
python3 - "$ROOT/mailserver/deploy/scripts/yaml-config.py" "$tmp/systemd-edge.env" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("yc", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
parsed = mod.parse_systemd_env_file(sys.argv[2])
assert parsed["S3_SECRET_KEY"] == "part1part2", parsed
assert parsed["S3_ACCESS_KEY"] == "foo bar\\baz", parsed
PY

cat > "$tmp/ws-worm.env" <<'ENV'
HOSTNAME=
  WORM_LEGAL_HOLD_ENABLED = false
ENV
cat > "$tmp/yaml-host.yaml" <<'YAML'
hostname: trace.example.test
YAML
(
  unset HOSTNAME
  SETJOIN_CONFIG="$tmp/yaml-host.yaml" CONFIG_ENV="$tmp/ws-worm.env" GATEWAY_ENV="$tmp/ws-worm-gw.env" AUTHSERVER_URL=http://127.0.0.1:8443 render_gateway_env "$tmp/ws-worm-gw.env"
  SETJOIN_CONFIG="$tmp/yaml-host.yaml" CONFIG_ENV="$tmp/empty-host.env" GATEWAY_ENV="$tmp/yamlonly-gw.env" AUTHSERVER_URL=http://127.0.0.1:8443 render_gateway_env "$tmp/yamlonly-gw.env"
)
grep -qx 'HOSTNAME=' "$tmp/ws-worm-gw.env"
grep -qx 'WORM_LEGAL_HOLD_ENABLED=false' "$tmp/ws-worm-gw.env"
grep -qx 'HOSTNAME=trace.example.test' "$tmp/yamlonly-gw.env"
grep -qx 'INTERNAL_DOMAINS=localhost' "$tmp/yamlonly-gw.env"

cat > "$tmp/unquoted-quotes.env" <<'ENV'
S3_SECRET_KEY=foo"bar"baz
S3_ACCESS_KEY=foo'bar'
ENV
python3 - "$ROOT/mailserver/deploy/scripts/yaml-config.py" "$tmp/unquoted-quotes.env" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("yc", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
parsed = mod.parse_systemd_env_file(sys.argv[2])
assert parsed["S3_SECRET_KEY"] == 'foo"bar"baz', parsed
assert parsed["S3_ACCESS_KEY"] == "foo'bar'", parsed
PY

cat > "$tmp/merge-compact.yaml" <<'YAML'
s3:
  "<<": /ignored/literal
  !!str endpoint: 127.0.0.1:9002
  <<:
    - endpoint: 127.0.0.1:9003
      bucket: compact-b
  fold_more: >
    a

      more

    b
YAML
python3 - "$ROOT/mailserver/deploy/scripts/yaml-config.py" "$tmp/merge-compact.yaml" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("yc", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
s3 = mod.parse_yaml_mapping(sys.argv[2])["s3"]
assert s3["<<"] == "/ignored/literal", s3
assert s3["endpoint"] == "127.0.0.1:9002", s3
assert s3["bucket"] == "compact-b", s3
assert s3["fold_more"] == "a\n\n  more\n\nb\n", repr(s3["fold_more"])
PY

for fval in 1e0 1.; do
  printf 's3:\n  secure: %s\n' "$fval" > "$tmp/fbool.yaml"
  python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" render-storage "$tmp/empty-env.env" "$tmp/fbool.yaml" | grep -qx 'S3_SECURE=true'
  printf 's3:\n  secure: "%s"\n' "$fval" > "$tmp/fbool-str.yaml"
  python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" render-storage "$tmp/empty-env.env" "$tmp/fbool-str.yaml" | grep -qx 'S3_SECURE=false'
done

for days in 3650. 3.65e3; do
  printf 'worm:\n  mode: compliance\n  retention_days: %s\n' "$days" > "$tmp/worm-float.yaml"
  [ "$(python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" get "$tmp/worm-float.yaml" worm retention_days)" = 3650 ]
done

cat > "$tmp/merge-flow-in-seq.yaml" <<'YAML'
!!str s3:
  !!str access_key: top-ak
  <<:
    - { endpoint: http://127.0.0.1:9200, bucket: seq-flow-bucket }
YAML
python3 "$ROOT/mailserver/deploy/scripts/yaml-config.py" render-storage "$tmp/empty-env.env" "$tmp/merge-flow-in-seq.yaml" > "$tmp/merge-flow-storage.env"
grep -qx 'S3_ENDPOINT=http://127.0.0.1:9200' "$tmp/merge-flow-storage.env"
grep -qx 'S3_BUCKET=seq-flow-bucket' "$tmp/merge-flow-storage.env"
grep -qx 'S3_ACCESS_KEY=top-ak' "$tmp/merge-flow-storage.env"

cat > "$tmp/adjacent-quotes.env" <<'ENV'
WORM_MODE="com""pliance"
WORM_LEGAL_HOLD_ENABLED="tr"'ue'
ENV
python3 - "$ROOT/mailserver/deploy/scripts/yaml-config.py" "$tmp/adjacent-quotes.env" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("yc", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
parsed = mod.parse_systemd_env_file(sys.argv[2])
assert parsed["WORM_MODE"] == "compliance", parsed
assert parsed["WORM_LEGAL_HOLD_ENABLED"] == "true", parsed
PY

printf 'WORM_MODE=governance\n  WORM_MODE = compliance\n  WORM_LEGAL_HOLD_ENABLED = false\n' > "$tmp/preserve-ws.env"
tls_front_preserve_settings "$tmp/preserve-ws.env" > "$tmp/preserve-ws.out"
grep -qx 'WORM_MODE=compliance' "$tmp/preserve-ws.out"
grep -qx 'WORM_LEGAL_HOLD_ENABLED=false' "$tmp/preserve-ws.out"
printf 'WORM_MODE=compliance\n  WORM_MODE = \n' > "$tmp/preserve-empty.env"
tls_front_preserve_settings "$tmp/preserve-empty.env" > "$tmp/preserve-empty.out"
grep -qx 'WORM_MODE=' "$tmp/preserve-empty.out"

for bad_dir in /var/lib/postgresql /var/cache/apt /etc/ssh /srv/postgres /opt/other /var/lib/setjoin; do
  if validate_tls_cache_target "$bad_dir" 2>/dev/null; then
    echo "expected rejection for $bad_dir" >&2
    exit 1
  fi
done
validate_tls_cache_target /var/lib/setjoin/custom-tls
validate_tls_cache_target /var/cache/mailserver/autocert
echo 'native TLS release socket: PASS'
