#!/usr/bin/env bash
# Executed INSIDE the setjoin-ci-linux-tc throwaway container (linux/arm64) by
# the xinchuang unit-tests job. This is a 1:1 port of the previous
# unit-tests-amd64 job body from the retired .github/workflows/xinchuang-ci.yml (removed; see webmail.yml, rust-floor.yml) — same
# steps, same order, same controls; only the runtime changed (it now runs in
# this container with an in-container postgres).
#
# Isolation posture (D--GITHUB-002, CWE-306 — preserved):
#   - the throwaway container publishes NO ports;
#   - postgres listens ONLY on 127.0.0.1 inside the container;
#   - role `mail` authenticates with a fresh per-run SCRAM secret
#     (an uncredentialed local process is denied by pg_hba, not just by the
#     binding);
#   - evidence files land in the repo's test-results/ through the rw mount.
set -euo pipefail

REPO="${REPO_MOUNT:-/work}"
cd "$REPO"

# ── environment the workflow used to inject ─────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
# Docker exports HOSTNAME=<container id>; a bare-metal runner does not, and
# shared/config defaults Hostname from it (TestLoadDefaults expects localhost).
unset HOSTNAME
export PATH="$HOME/.local/setjoin-ci-tools:$HOME/.local/bin:$HOME/.cargo/bin:/usr/lib/postgresql/17/bin:/usr/local/go/bin:$PATH"

echo "== toolchain =="
go version
node --version
pg_config --version
pg_prove --version | head -1

# ── postgres provision (run-scoped, loopback-only, SCRAM per-run secret) ────
CI_PG_PORT=15432
CI_PG_PASSWORD="$(openssl rand -hex 24)"
echo "::add-mask::$CI_PG_PASSWORD"
PGDATA="$(mktemp -d /tmp/ci-pgdata.XXXXXX)"
chown postgres:postgres "$PGDATA"
pwfile="$(mktemp)"
printf '%s\n' "$CI_PG_PASSWORD" >"$pwfile"
chown postgres:postgres "$pwfile"
su postgres -c "$(command -v initdb) -D '$PGDATA' -U mail --pwfile='$pwfile' -A scram-sha-256 --auth-local=scram-sha-256" \
  >/tmp/initdb.log 2>&1 || {
  cat /tmp/initdb.log
  exit 1
}
rm -f "$pwfile"
su postgres -c "$(command -v pg_ctl) -D '$PGDATA' -l /tmp/pg.log -o '-c listen_addresses=127.0.0.1 -c port=$CI_PG_PORT' -w start" \
  >/tmp/pgctl.log 2>&1 || {
  cat /tmp/pg.log /tmp/pgctl.log
  exit 1
}
export PGPASSWORD="$CI_PG_PASSWORD"
# load-test-schema.sh and the pgTAP suite resolve the server through these
export DB_HOST="127.0.0.1"
export DB_PORT="$CI_PG_PORT"
export DB_DSN="postgres://mail:${CI_PG_PASSWORD}@127.0.0.1:${CI_PG_PORT}/mailserver_test?sslmode=disable"
export TEST_DB_DSN="$DB_DSN"
cleanup() {
  su postgres -c "$(command -v pg_ctl) -D '$PGDATA' -m fast stop" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== isolation assertions (D--GITHUB-002) =="
# 1. in-container: postgres listens ONLY on loopback
if ss -tln | grep -E '(\[::\]|0\.0\.0\.0):15432' >/dev/null; then
  echo "FAIL: postgres has a non-loopback listener inside the container" >&2
  exit 1
fi
# 2. the container's own non-loopback address cannot reach it (nothing published)
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$HOST_IP" ] || {
  echo "FAIL: no non-loopback address — off-host isolation cannot be asserted" >&2
  exit 1
}
if pg_isready -h "$HOST_IP" -p "$CI_PG_PORT" -t 3 >/dev/null 2>&1; then
  echo "FAIL: postgres answers on the container non-loopback address" >&2
  exit 1
fi
# 3. credentialed on-host path passes; uncredentialed local process denied
psql -h 127.0.0.1 -p "$CI_PG_PORT" -U mail -d postgres -c 'SELECT 1;' >/dev/null
if env -u PGPASSWORD PGPASSFILE=/dev/null \
  psql -w "postgres://mail@127.0.0.1:${CI_PG_PORT}/postgres?sslmode=disable" \
  -c 'SELECT 1;' >/dev/null 2>&1; then
  echo "FAIL: uncredentialed local process connected — SCRAM enforcement missing" >&2
  exit 1
fi
echo "isolation: OK (loopback-only; off-host unreachable; credentialed OK; uncredentialed denied)"

# ── pgtap availability (the baseline hard-requires CREATE EXTENSION pgtap) ──
ls /usr/share/postgresql/17/extension/pgtap.control >/dev/null ||
  {
    echo "FAIL: pgtap extension files missing in the toolchain image" >&2
    exit 1
  }

echo "== load test schema =="
bash scripts/load-test-schema.sh

# setjoin_app runtime credential (run-scoped secret). The isolation suites
# (imap setupIMAPIso and every other DB_APP_DSN-consuming test) connect as the
# RLS-constrained runtime role; provision-roles.sql creates the role LOGIN
# WITHOUT a password, and this server is SCRAM-enforced (assertion 3 above),
# so without a credential those suites silently skip — which surfaced as a
# changed-lines coverage gap when the WP4 batch rewrite made imap.go's
# DB-path lines ratchet-visible. Provision a per-run password and export the
# DSN the tests derive from.
CI_APP_PASSWORD="$(openssl rand -hex 24)"
echo "::add-mask::$CI_APP_PASSWORD"
# CI_APP_PASSWORD is [0-9a-f] only (openssl rand -hex), so single-quoting is
# injection-safe.
psql -h 127.0.0.1 -p "$CI_PG_PORT" -U mail -d mailserver_test \
  -c "ALTER ROLE setjoin_app LOGIN PASSWORD '${CI_APP_PASSWORD}';" >/dev/null
export DB_APP_DSN="postgres://setjoin_app:${CI_APP_PASSWORD}@127.0.0.1:${CI_PG_PORT}/mailserver_test?sslmode=disable"
# The credential must actually authenticate before anything trusts the lane.
psql "$DB_APP_DSN" -c 'SELECT 1;' >/dev/null

echo "== webmail dependencies (guards shell into webmail tooling) =="
(cd mailserver/webmail && npm ci --no-audit --no-fund)

echo "== pinned quality tools =="
TOOLS="$HOME/.local/setjoin-ci-tools"
mkdir -p "$TOOLS"
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b "$TOOLS" v2.13.2
GOBIN="$TOOLS" go install mvdan.cc/sh/v3/cmd/shfmt@v3.13.1
GOBIN="$TOOLS" go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
case "$(uname -m)" in
  aarch64 | arm64) RUFF_ARCH=aarch64 GITLEAKS_ARCH=arm64 ;;
  x86_64) RUFF_ARCH=x86_64 GITLEAKS_ARCH=x64 ;;
  *)
    echo "FAIL: unsupported toolchain architecture $(uname -m)" >&2
    exit 1
    ;;
esac
RUFF_TMP="$(mktemp -d)"
curl -fsSL "https://github.com/astral-sh/ruff/releases/download/0.16.4/ruff-${RUFF_ARCH}-unknown-linux-musl.tar.gz" | tar -xz -C "$RUFF_TMP"
install -m 0755 "$RUFF_TMP/ruff-${RUFF_ARCH}-unknown-linux-musl/ruff" "$TOOLS/ruff"
rm -rf "$RUFF_TMP"
curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${GITLEAKS_ARCH}.tar.gz" | tar -xz -C "$TOOLS" gitleaks

echo "== webmail build (performance guard input) =="
(cd mailserver/webmail && npm run build)

echo "== client toolchains (R2 native lane: electron deps; rust is in the image) =="
(cd clients/desktop/electron && npm ci --no-audit --no-fund)

echo "== structural guards (full manifest, self-test first) =="
bash scripts/run-guards.sh

echo "== architecture R2 five-sample timing surrogate =="
bash scripts/verify-architecture-r2.sh benchmark --class warm --samples 5 --warmup 1

echo "== verify architecture R2 timing evidence =="
bash scripts/check-architecture-r2-dx-metrics.sh --require

echo "== govulncheck (non-blocking) =="
go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
while IFS=$'\t' read -r module_id module_path _workspace _kind module_tags module_gowork; do
  echo "==> govulncheck $module_id"
  vuln_args=()
  [[ -n "$module_tags" ]] && vuln_args=(-tags "$module_tags")
  # continue-on-error in the workflow: report findings, never fail the job.
  if [[ "$module_gowork" == "off" ]]; then
    (cd "$module_path" && GOWORK=off govulncheck "${vuln_args[@]}" ./...) || echo "govulncheck $module_id: findings reported (non-blocking)"
  else
    (cd "$module_path" && govulncheck "${vuln_args[@]}" ./...) || echo "govulncheck $module_id: findings reported (non-blocking)"
  fi
done < <(node scripts/go-module-catalog.mjs list vulnerability)

# -p 1: DB-backed packages share ONE test database; parallel packages racing it
# flake global-state assertions (same reason scripts/test.sh runs sequentially).
echo "== DB-backed module tests =="
bash scripts/run-go-test-evidence.sh authserver test-results/go/authserver.json ./... -count=1 -p 1 -timeout 600s
bash scripts/run-go-test-evidence.sh mailserver test-results/go/mailserver.json ./... -count=1 -p 1 -timeout 600s
bash scripts/run-go-test-evidence.sh shared test-results/go/shared.json ./... -count=1 -p 1 -timeout 300s
bash scripts/run-go-test-evidence.sh mailctl test-results/go/mailctl.json ./... -count=1 -p 1 -timeout 300s
bash scripts/run-go-test-evidence.sh setjoin-release test-results/go/setjoin-release.json ./... -count=1 -p 1 -timeout 300s

echo "== asrbot (libopus-dev is in the toolchain image) =="
pkg-config --exists opus || {
  echo "FAIL: libopus development files missing in the toolchain image" >&2
  exit 1
}
GOWORK=off bash scripts/run-go-test-evidence.sh asrbot test-results/go/asrbot.json -tags nolibopusfile ./... -count=1 -timeout 300s

echo "== verify named Go evidence =="
TEST_EVIDENCE_OUTPUT=test-results/go/test-evidence.json bash scripts/check-test-evidence-results.sh --verify go-json

echo "== enforce Go coverage ratchets =="
COVERAGE_BASE="${COVERAGE_BASE:-}" node scripts/report-go-coverage.mjs --mode enforce

echo "== bounded Go fuzz smoke =="
bash scripts/run-go-fuzz-smoke.sh

echo "== pgTAP reducer suite (reload first: the Go suites mutate mailserver_test) =="
bash scripts/load-test-schema.sh
bash scripts/run-pgtap-evidence.sh test-results/pgtap/mailserver.tap --ext .pg -h 127.0.0.1 -p "$CI_PG_PORT" -U mail -d mailserver_test mailserver/sql/tests/*.pg
bash scripts/run-pgtap-evidence.sh test-results/pgtap/authserver.tap --ext .pg -h 127.0.0.1 -p "$CI_PG_PORT" -U mail -d mailserver_test authserver/sql/tests/*.pg

echo "== verify named pgTAP evidence =="
TEST_EVIDENCE_OUTPUT=test-results/pgtap/test-evidence.json bash scripts/check-test-evidence-results.sh --verify tap

echo "unit-tests linux/$(uname -m): PASS"
