#!/bin/bash
# Run on Ubuntu: bash ~/setjoin/scripts/deploy-and-test.sh
set -e
cd ~/setjoin
git pull origin main

echo "=== BUILD ==="
cd authserver && GOPROXY=https://goproxy.cn,direct go build -o /tmp/authd ./cmd/authserverd && echo "auth: OK"
cd ../mailserver && GOPROXY=https://goproxy.cn,direct go build -o /tmp/gwd ./cmd/mailserverd && echo "gw: OK"
cd webmail && npm run build 2>&1 | tail -1 && echo "web: OK"
cd ../../mailctl && GOPROXY=https://goproxy.cn,direct go build -o /tmp/mailctl . && echo "mailctl: OK"
cd ..

echo "=== KILL ==="
sudo kill -9 $(pgrep -f authserverd) $(pgrep -f mailserverd) 2>/dev/null; sleep 2; echo "killed"

echo "=== DB RESET ==="
PGPASSWORD=mail psql -h 127.0.0.1 -U mail -d mailserver_test << 'SQL'
ALTER TABLE mailboxes DISABLE TRIGGER mailbox_primary_enforce;
DELETE FROM mailboxes; DELETE FROM users; DELETE FROM domains;
ALTER TABLE mailboxes ENABLE TRIGGER mailbox_primary_enforce;
SQL
echo "db reset"

echo "=== CERTS ==="
mkdir -p /tmp/certs
openssl req -x509 -newkey rsa:2048 -keyout /tmp/certs/key.pem -out /tmp/certs/cert.pem \
  -days 365 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

echo "=== START ==="
JW=$(openssl rand -hex 32)
ENC=$(openssl rand -hex 16)
AP=$(openssl rand -hex 32)
S="postgres://mail:mail@127.0.0.1:5432/mailserver_test?sslmode=disable"
# Native-RLS credential shape (the production shape; e2e harness flipped
# 2026-07-03, this script flipped 2026-07-15): runtimes connect as the
# constrained setjoin_app / setjoin_worker roles so FORCE'd policies are live;
# `mail` (owner identity here) stays for the psql reset + DB_OWNER_DSN.
PGPASSWORD=mail psql -h 127.0.0.1 -U mail -d mailserver_test -X -q \
  -c "ALTER ROLE setjoin_app WITH LOGIN PASSWORD 'dt-app'; ALTER ROLE setjoin_worker WITH LOGIN PASSWORD 'dt-worker';"
APP="postgres://setjoin_app:dt-app@127.0.0.1:5432/mailserver_test?sslmode=disable"
WORKER="postgres://setjoin_worker:dt-worker@127.0.0.1:5432/mailserver_test?sslmode=disable"

# Authserver (threat detection disabled to avoid interceptor hangs)
THREAT_FEED_ENABLED=false GEO_BLOCK_ENABLED=false SPRAY_DETECT_ENABLED=false \
CAPTCHA_ENABLED=false TARPIT_ENABLED=false \
LISTEN_ADDR=127.0.0.1:8444 DB_DSN="$APP" JWT_SECRET="$JW" INTERNAL_API_KEY="$AP" \
nohup /tmp/authd >> /tmp/auth.log 2>&1 &
sleep 2
curl -s http://127.0.0.1:8444/health | grep -q ok && echo "auth: OK" || { echo "auth: FAIL"; exit 1; }

# Gateway on port 8443 (443 is taken by xray/sing-box). The redirect is
# intentionally performed by the invoking operator into operator-writable /tmp.
# shellcheck disable=SC2024
sudo env LISTEN_ADDR=:8443 DB_DSN="$APP" DB_WORKER_DSN="$WORKER" DB_OWNER_DSN="$S" \
  SETJOIN_CONTROL_SOCKET=/tmp/setjoin-deploy-test-control.sock \
  DB_ENCRYPTION_KEY="$ENC" \
  JWT_SECRET="$JW" INTERNAL_API_KEY="$AP" \
  TLS_CERT=/tmp/certs/cert.pem TLS_KEY=/tmp/certs/key.pem \
  MINIO_ACCESS_KEY=t MINIO_SECRET_KEY=t S3_ACCESS_KEY=t S3_SECRET_KEY=t \
  WEBSITE_DIR=$HOME/setjoin/mailserver/webmail/build \
  HTTP_MODE=serve AUTHSERVER_URL=http://127.0.0.1:8444 \
  nohup /tmp/gwd >> /tmp/gw.log 2>&1 &
sleep 5

B=https://localhost:8443
echo "=== TESTS ==="
echo -n "health: "; curl -sk $B/health; echo
echo -n "setup: "; curl -sk $B/setup/status; echo
echo -n "redirect: "; curl -sko /dev/null -w '%{http_code}\n' $B/
echo -n "public create blocked: "; curl -sk -o /dev/null -w '%{http_code}\n' -X POST $B/setup/create-admin -H 'Content-Type: application/json' -d '{}'
echo -n "local bootstrap: "; printf '%s\n' 'Test123!' | DB_OWNER_DSN="$S" /tmp/mailctl bootstrap-admin --email a@t.local --password-stdin
echo -n "login: "; curl -sk --max-time 10 -X POST $B/auth/login -H 'Content-Type: application/json' -d '{"email":"a@t.local","password":"Test123!"}'; echo
echo -n "gw errors: "; grep -c '"level":"ERROR"' /tmp/gw.log 2>/dev/null || echo 0
echo -n "auth errors: "; grep -c '"level":"ERROR"' /tmp/auth.log 2>/dev/null || echo 0
echo "=== DONE: https://localhost:8443 ==="
