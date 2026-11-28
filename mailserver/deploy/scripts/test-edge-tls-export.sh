#!/usr/bin/env bash
# Adversarial tests for export-edge-pem.sh and official edge TLS/ACME templates (#559).
# Portable across Linux and macOS.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
EXPORTER="$ROOT/mailserver/deploy/scripts/export-edge-pem.sh"
DEPLOY_DIR="$ROOT/mailserver/deploy"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/setjoin-edge-tls-test.XXXXXX")"
# Canonicalize temp root (e.g. /var -> /private/var on macOS) so ancestor symlink checks
# reflect only the symlinks intentionally planted by this test.
tmp="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$tmp")"
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
ok() {
  echo "  ok: $1"
  pass=$((pass + 1))
}
bad() {
  echo "  FAIL: $1" >&2
  fail=$((fail + 1))
}

mode_of() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

inode_of() {
  stat -c '%i' "$1" 2>/dev/null || stat -f '%i' "$1"
}

gen_key() {
  openssl ecparam -name prime256v1 -genkey -noout -out "$1" 2>/dev/null
}

gen_cert() {
  local key="$1" out="$2" cn="$3" days="${4:-365}"
  openssl req -new -x509 -key "$key" -out "$out" -days "$days" \
    -subj "/CN=$cn" -addext "subjectAltName=DNS:$cn" 2>/dev/null
}

# Generate expired certificate using openssl ca or a backdated self-signed cert via openssl/python.
gen_expired_cert() {
  local key="$1" out="$2"
  local ca_dir="$tmp/expired-ca"
  mkdir -p "$ca_dir/newcerts"
  : >"$ca_dir/index.txt"
  echo "01" >"$ca_dir/serial"
  cat >"$ca_dir/openssl.cnf" <<EOF
[ca]
default_ca = CA_default
[CA_default]
dir = $ca_dir
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
serial = \$dir/serial
default_md = sha256
policy = policy_any
[policy_any]
commonName = supplied
[req]
distinguished_name = dn
[dn]
EOF
  openssl req -new -key "$key" -out "$ca_dir/req.csr" -subj "/CN=expired.test" 2>/dev/null
  openssl ca -batch -selfsign -config "$ca_dir/openssl.cnf" -keyfile "$key" \
    -in "$ca_dir/req.csr" -out "$ca_dir/raw.pem" \
    -startdate 20200101000000Z -enddate 20200102000000Z 2>/dev/null
  # Strip human-readable text header prepended by openssl ca (portable across OpenSSL 3 & LibreSSL).
  openssl x509 -in "$ca_dir/raw.pem" -out "$out" 2>/dev/null
}

# Generate test keys & certs
mkdir -p "$tmp/src"
gen_key "$tmp/src/k1.pem"
gen_cert "$tmp/src/k1.pem" "$tmp/src/c1.pem" "mail.example.test"
gen_cert "$tmp/src/k1.pem" "$tmp/src/c1_renewed.pem" "mail.example.test"

gen_key "$tmp/src/k2.pem"
gen_cert "$tmp/src/k2.pem" "$tmp/src/c2.pem" "mail.example.test"

gen_expired_cert "$tmp/src/k1.pem" "$tmp/src/c1_expired.pem"

# 1. Valid initial export into 0750 directory
dest="$tmp/dest"
mkdir -p "$dest"
chmod 0750 "$dest"
if bash "$EXPORTER" --cert "$tmp/src/c1.pem" --key "$tmp/src/k1.pem" --dest-dir "$dest" >/dev/null; then
  if [ "$(mode_of "$dest/server.pem")" = "644" ] && [ "$(mode_of "$dest/server-key.pem")" = "640" ]; then
    ok "initial export writes 0644 cert and 0640 key"
  else
    bad "unexpected modes: cert=$(mode_of "$dest/server.pem") key=$(mode_of "$dest/server-key.pem")"
  fi
else
  bad "initial export failed"
fi

# 2. Skip-rewrite path preserves key inode AND normalizes drifted key mode back to 0640
orig_ino="$(inode_of "$dest/server-key.pem")"
chmod 0600 "$dest/server-key.pem"
if bash "$EXPORTER" --cert "$tmp/src/c1_renewed.pem" --key "$tmp/src/k1.pem" --dest-dir "$dest" >/dev/null; then
  new_ino="$(inode_of "$dest/server-key.pem")"
  new_mode="$(mode_of "$dest/server-key.pem")"
  if [ "$orig_ino" = "$new_ino" ] && [ "$new_mode" = "640" ] && cmp -s "$tmp/src/c1_renewed.pem" "$dest/server.pem"; then
    ok "key-reuse renewal preserves key inode, normalizes mode to 0640, and updates server.pem"
  else
    bad "skip-rewrite mismatch: ino=$orig_ino->$new_ino mode=$new_mode"
  fi
else
  bad "key-reuse renewal failed"
fi

# 3. DANE_ENFORCE_KEY_PIN=1 refuses accidental key change without --allow-key-rotation
out="$(bash "$EXPORTER" --cert "$tmp/src/c2.pem" --key "$tmp/src/k2.pem" --dest-dir "$dest" 2>&1 || true)"
if bash "$EXPORTER" --cert "$tmp/src/c2.pem" --key "$tmp/src/k2.pem" --dest-dir "$dest" >/dev/null 2>&1; then
  bad "accidental key rotation was NOT blocked under DANE_ENFORCE_KEY_PIN=1"
elif printf '%s' "$out" | grep -q 'TLSA 3 1 1' && cmp -s "$tmp/src/k1.pem" "$dest/server-key.pem"; then
  ok "DANE_ENFORCE_KEY_PIN=1 blocks key change, leaves live files untouched, prints double-TLSA guidance"
else
  bad "DANE guard output or live-file preservation unexpected: $out"
fi

# 4. --allow-key-rotation succeeds and updates key + cert
if bash "$EXPORTER" --cert "$tmp/src/c2.pem" --key "$tmp/src/k2.pem" --dest-dir "$dest" --allow-key-rotation >/dev/null; then
  if cmp -s "$tmp/src/k2.pem" "$dest/server-key.pem" && cmp -s "$tmp/src/c2.pem" "$dest/server.pem"; then
    ok "--allow-key-rotation rotates key and cert cleanly"
  else
    bad "--allow-key-rotation did not write expected files"
  fi
else
  bad "--allow-key-rotation failed"
fi

# 5. Reject fullchain with valid leaf + corrupt intermediate cert
cat "$tmp/src/c2.pem" >"$tmp/src/bad_chain.pem"
cat >>"$tmp/src/bad_chain.pem" <<'EOF'
-----BEGIN CERTIFICATE-----
NOT_VALID_BASE64_INTERMEDIATE_DATA!!!
-----END CERTIFICATE-----
EOF
rc=0
err="$(bash "$EXPORTER" --cert "$tmp/src/bad_chain.pem" --key "$tmp/src/k2.pem" --dest-dir "$dest" 2>&1)" || rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$err" | grep -q 'invalid X.509 certificate in chain block #2'; then
  ok "rejects fullchain with valid leaf + corrupt intermediate cert"
else
  bad "corrupt intermediate rejection unexpected (rc=$rc): $err"
fi

# 6. Reject expired leaf cert (pure PEM must reach -checkend 0 check)
rc=0
err="$(bash "$EXPORTER" --cert "$tmp/src/c1_expired.pem" --key "$tmp/src/k1.pem" --dest-dir "$dest" --allow-key-rotation 2>&1)" || rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$err" | grep -q 'leaf certificate is already expired'; then
  ok "rejects expired leaf certificate"
else
  bad "expired leaf certificate rejection unexpected (rc=$rc): $err"
fi

# 7. Reject mismatched cert and key
rc=0
err="$(bash "$EXPORTER" --cert "$tmp/src/c1.pem" --key "$tmp/src/k2.pem" --dest-dir "$dest" --allow-key-rotation 2>&1)" || rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$err" | grep -q 'certificate public key does not match private key'; then
  ok "rejects mismatched cert/key pair"
else
  bad "mismatched cert/key rejection unexpected (rc=$rc): $err"
fi

# 7b. Fail closed on corrupt existing server-key.pem under DANE_ENFORCE_KEY_PIN=1 (no empty-string SHA-256)
corrupt_dest="$tmp/corrupt-dest"
mkdir -p "$corrupt_dest"
chmod 0750 "$corrupt_dest"
printf 'NOT A VALID PEM KEY\n' >"$corrupt_dest/server-key.pem"
rc=0
err="$(bash "$EXPORTER" --cert "$tmp/src/c1.pem" --key "$tmp/src/k1.pem" --dest-dir "$corrupt_dest" 2>&1)" || rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$err" | grep -q 'unreadable/corrupt' && ! printf '%s' "$err" | grep -q 'e3b0c44298fc1c14'; then
  ok "fails closed on corrupt existing server-key.pem under DANE_ENFORCE_KEY_PIN=1"
else
  bad "corrupt existing key handling unexpected (rc=$rc): $err"
fi

# 8. Refuse symlink destination files
sym_dest="$tmp/sym-dest-file"
mkdir -p "$sym_dest"
chmod 0750 "$sym_dest"
touch "$tmp/innocent-target"
ln -s "$tmp/innocent-target" "$sym_dest/server.pem"
if bash "$EXPORTER" --cert "$tmp/src/c1.pem" --key "$tmp/src/k1.pem" --dest-dir "$sym_dest" >/dev/null 2>&1; then
  bad "symlink destination server.pem was NOT refused"
else
  ok "refuses symlink destination server.pem"
fi

# 9. Refuse symlink DEST_DIR
real_dir="$tmp/real-dir"
mkdir -p "$real_dir"
chmod 0750 "$real_dir"
ln -s "$real_dir" "$tmp/symlink-dest-dir"
if bash "$EXPORTER" --cert "$tmp/src/c1.pem" --key "$tmp/src/k1.pem" --dest-dir "$tmp/symlink-dest-dir" >/dev/null 2>&1; then
  bad "symlink DEST_DIR was NOT refused"
else
  ok "refuses symlink DEST_DIR"
fi

# 10. Refuse symlink intermediate parent
mkdir -p "$tmp/real-parent/tls"
chmod 0750 "$tmp/real-parent/tls"
ln -s "$tmp/real-parent" "$tmp/symlink-parent"
if bash "$EXPORTER" --cert "$tmp/src/c1.pem" --key "$tmp/src/k1.pem" --dest-dir "$tmp/symlink-parent/tls" >/dev/null 2>&1; then
  bad "symlink intermediate parent was NOT refused"
else
  ok "refuses symlink intermediate parent"
fi

# 11. Refuse group-writable and world-writable DEST_DIR
for bad_mode in 0770 0757; do
  wdir="$tmp/writable-$bad_mode"
  mkdir -p "$wdir"
  chmod "$bad_mode" "$wdir"
  if bash "$EXPORTER" --cert "$tmp/src/c1.pem" --key "$tmp/src/k1.pem" --dest-dir "$wdir" >/dev/null 2>&1; then
    bad "writable DEST_DIR ($bad_mode) was NOT refused"
  else
    ok "refuses writable DEST_DIR ($bad_mode)"
  fi
done

# 12. Source symlinks (e.g. /etc/letsencrypt/live/...) are dereferenced cleanly
live_src="$tmp/live"
mkdir -p "$live_src"
ln -s "$tmp/src/c1.pem" "$live_src/fullchain.pem"
ln -s "$tmp/src/k1.pem" "$live_src/privkey.pem"
dest_live="$tmp/dest-live"
mkdir -p "$dest_live"
chmod 0750 "$dest_live"
if bash "$EXPORTER" --cert "$live_src/fullchain.pem" --key "$live_src/privkey.pem" --dest-dir "$dest_live" >/dev/null; then
  if [ ! -L "$dest_live/server.pem" ] && cmp -s "$tmp/src/c1.pem" "$dest_live/server.pem"; then
    ok "dereferences source symlinks into regular destination files"
  else
    bad "destination should be a regular file matching source bytes"
  fi
else
  bad "source symlink export failed"
fi

# 13. certbot-deploy-hook.sh.template refuses empty or mismatched RENEWED_LINEAGE and succeeds on match
hook_rendered="$tmp/certbot-hook.sh"
sed \
  -e "s|{{CERTBOT_LINEAGE}}|$live_src|g" \
  -e "s|{{INSTALL_DIR}}/deploy/scripts/export-edge-pem.sh|$EXPORTER|g" \
  -e "s|{{TLS_DIR}}|$dest_live|g" \
  "$DEPLOY_DIR/certbot-deploy-hook.sh.template" >"$hook_rendered"
chmod 0755 "$hook_rendered"
bash -n "$hook_rendered" && ok "certbot-deploy-hook.sh.template passes bash -n" || bad "certbot hook syntax error"

if env -u RENEWED_LINEAGE bash "$hook_rendered" >/dev/null 2>&1; then
  bad "certbot hook did NOT refuse empty RENEWED_LINEAGE"
else
  ok "certbot hook refuses empty RENEWED_LINEAGE"
fi

if RENEWED_LINEAGE="$tmp/other-domain" bash "$hook_rendered" >/dev/null 2>&1; then
  bad "certbot hook did NOT refuse mismatched RENEWED_LINEAGE"
else
  ok "certbot hook refuses mismatched RENEWED_LINEAGE"
fi

if RENEWED_LINEAGE="$live_src" bash "$hook_rendered" >/dev/null; then
  ok "certbot hook succeeds when RENEWED_LINEAGE matches EXPECTED_LINEAGE"
else
  bad "certbot hook failed for matching RENEWED_LINEAGE"
fi

# 14. Template syntax, posture & placeholder checks
if grep -q 'key_type p256' "$DEPLOY_DIR/Caddyfile.template" &&
  grep -q 'reuse_private_keys' "$DEPLOY_DIR/Caddyfile.template" &&
  grep -q 'reverse_proxy 127.0.0.1:8090' "$DEPLOY_DIR/Caddyfile.template" &&
  ! grep -Eq 'reverse_proxy[[:space:]]+localhost' "$DEPLOY_DIR/Caddyfile.template"; then
  ok "Caddyfile.template has global key_type/reuse_private_keys and literal 127.0.0.1:8090"
else
  bad "Caddyfile.template missing required directives"
fi

if grep -q '^PathChanged={{CADDY_CERT_PATH}}' "$DEPLOY_DIR/setjoin-tls-export.path.template" &&
  grep -q '^Unit=setjoin-tls-export.service' "$DEPLOY_DIR/setjoin-tls-export.path.template" &&
  grep -q 'export-edge-pem.sh' "$DEPLOY_DIR/setjoin-tls-export.service.template"; then
  ok "setjoin-tls-export.{path,service}.template placeholders intact"
else
  bad "setjoin-tls-export templates missing required fields"
fi

if grep -q 'ssl_ntls on;' "$DEPLOY_DIR/angie-guomi.conf.template" &&
  grep -q 'ssl_certificate[[:space:]]\+{{GUOMI_SIGN_CERT}} {{GUOMI_ENC_CERT}};' "$DEPLOY_DIR/angie-guomi.conf.template" &&
  grep -q 'ssl_certificate_key[[:space:]]\+{{GUOMI_SIGN_KEY}} {{GUOMI_ENC_KEY}};' "$DEPLOY_DIR/angie-guomi.conf.template" &&
  grep -q 'ssl_protocols TLSv1.3;' "$DEPLOY_DIR/angie-guomi.conf.template" &&
  grep -q 'proxy_pass http://127.0.0.1:8090;' "$DEPLOY_DIR/angie-guomi.conf.template" &&
  grep -q 'proxy_buffering off;' "$DEPLOY_DIR/angie-guomi.conf.template"; then
  ok "angie-guomi.conf.template matches Tongsuo+Angie dual-arg ARCH-014 contract"
else
  bad "angie-guomi.conf.template missing required directives"
fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "test-edge-tls-export FAILED ($fail/$((pass + fail)) failed)" >&2
  exit 1
fi
echo "test-edge-tls-export: all $pass checks passed."
