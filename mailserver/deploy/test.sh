#!/bin/bash
# ── Mailserver E2E Test Runner ──────────────────────────────────────────
# Starts all test Docker services, runs E2E integration tests, and tears
# down the services on exit (even on failure).
#
# Usage:
#   bash deploy/test.sh              # local Docker IMAP + SMTP/LDAP suites
#   bash deploy/test.sh imap         # Docker IMAP connector E2E only
#   bash deploy/test.sh ews          # real EWS (requires TEST_EWS_CONFIG)
#   bash deploy/test.sh m365         # real M365 (requires TEST_M365_CONFIG)
#
# Note: SMTP and LDAP protocol tests are unit tests (go test ./internal/smtp/...).
# Full-stack E2E tests for IMAP/SMTP/LDAP are covered by Playwright browser tests
# (npm run test:e2e). This script handles Go-level integration tests only.
#
# Requires: Docker, Go 1.22+

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/deploy/docker-compose.test.yml"

# Parse optional test filter
FILTER="${1:-all}"

start_local_services() {
    echo "=== Starting local protocol test services ==="
    docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" build --quiet
    docker compose -f "$COMPOSE_FILE" up -d

    export TEST_IMAP_HOST=127.0.0.1
    export TEST_IMAP_PORT=3143
    export TEST_SMTP_HOST=127.0.0.1
    export TEST_SMTP_PORT=3025
    export TEST_LDAP_HOST=127.0.0.1
    export TEST_LDAP_PORT=3389

    # Bound startup on protocol banners, not only accepted TCP sockets. James
    # starts a JVM and is intentionally allowed longer than Dovecot.
    local target name service port attempts banner ready domain_status user_status
    for target in "dovecot:imap-test:3143:30" "james:imap-james:3144:60"; do
        IFS=: read -r name service port attempts <<<"$target"
        ready=false
        for _ in $(seq 1 "$attempts"); do
            banner="$(bash -c "exec 3<>/dev/tcp/127.0.0.1/$port; IFS= read -r -t 2 line <&3; printf '%s' \"\$line\"" 2>/dev/null || true)"
            if [[ "$banner" == \*\ OK* ]]; then
                ready=true
                break
            fi
            sleep 1
        done
        if [ "$ready" != true ]; then
            echo "$name IMAP test service did not become ready on 127.0.0.1:$port within ${attempts}s" >&2
            docker compose -f "$COMPOSE_FILE" ps >&2 || true
            docker compose -f "$COMPOSE_FILE" logs --tail=80 "$service" >&2 || true
            return 1
        fi
    done

    # The demo image documents sample users, but recreating the account through
    # its loopback-only WebAdmin API makes the fixture deterministic across
    # architectures and image initialization paths.
    ready=false
    for _ in $(seq 1 30); do
        if curl -fsS --connect-timeout 1 --max-time 2 http://127.0.0.1:38000/healthcheck >/dev/null 2>&1; then
            ready=true
            break
        fi
        sleep 1
    done
    if [ "$ready" != true ]; then
        echo "james WebAdmin did not become ready on 127.0.0.1:38000 within 30s" >&2
        docker compose -f "$COMPOSE_FILE" logs --tail=80 imap-james >&2 || true
        return 1
    fi
    domain_status="$(curl -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' \
        -X PUT http://127.0.0.1:38000/domains/james.local)"
    if [ "$domain_status" != 204 ] && [ "$domain_status" != 409 ]; then
        echo "james domain provisioning failed with HTTP $domain_status" >&2
        return 1
    fi
    user_status="$(curl -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' \
        -X PUT 'http://127.0.0.1:38000/users/user01@james.local?force' \
        -H 'Content-Type: application/json' -d '{"password":"1234"}')"
    if [ "$user_status" != 204 ]; then
        echo "james user provisioning failed with HTTP $user_status" >&2
        return 1
    fi
}

cleanup() {
    echo ""
    echo "=== Tearing down local protocol test services ==="
    docker compose -f "$COMPOSE_FILE" down --remove-orphans
    if [ -n "${IMAP_TLS_TMP_DIR:-}" ]; then
        rm -rf "$IMAP_TLS_TMP_DIR"
    fi
}

if [ "$FILTER" = "all" ] || [ "$FILTER" = "imap" ]; then
    start_local_services
    trap cleanup EXIT

    IMAP_TLS_TMP_DIR="$(mktemp -d)"
    docker compose -f "$COMPOSE_FILE" cp imap-james:/root/conf/private.csr "$IMAP_TLS_TMP_DIR/james-ca.pem" >/dev/null
    export TEST_IMAP_JAMES_CA="$IMAP_TLS_TMP_DIR/james-ca.pem"
    export TEST_IMAP_JAMES_HOST=localhost
    export TEST_IMAP_JAMES_PORT=3144
fi

# ── Run tests ───────────────────────────────────────────────────────
# The Go module root is mailserver/ itself ($PROJECT_DIR); "gateway" was a
# pre-restructure name and no longer exists.
cd "$PROJECT_DIR"

case "$FILTER" in
    all)
        echo "=== Running local Docker IMAP E2E ==="
        go test -tags e2e -run '^TestIMAPDocker_' -v -count=1 -timeout 60s ./internal/migration/...
        echo "=== Running SMTP surface suite ==="
        go test -count=1 -timeout 120s ./internal/smtp/...
        echo "=== Running LDAP surface suite ==="
        go test -count=1 -timeout 120s ./internal/ldap/...
        echo "=== External lanes excluded: ews, m365, link-protect (require explicit credentials/services) ==="
        ;;
    imap)
        echo "=== Running IMAP connector E2E tests ==="
        go test -tags e2e -run TestIMAPDocker -v -count=1 -timeout 60s ./internal/migration/...
        ;;
    smtp|ldap)
        # 2026-07-18 test-suite review: this arm used to PRINT "covered by
        # unit tests" and exit green while running NOTHING. If the claim is
        # unit-test coverage, run the unit tests.
        echo "=== $FILTER: running the unit tests that cover this surface ==="
        go test -count=1 -timeout 120s "./internal/$FILTER/..."
        echo "=== Full-stack E2E: use Playwright (cd mailserver/webmail && npm run test:e2e) ==="
        ;;
    link-protect)
        : "${SAFEBROWSING_API_KEY:?SAFEBROWSING_API_KEY is required for link-protect E2E}"
        : "${TEST_ADMIN_TOKEN:?TEST_ADMIN_TOKEN is required for link-protect E2E}"
        : "${TEST_GATEWAY_URL:?TEST_GATEWAY_URL is required for link-protect E2E}"
        echo "=== Running Link Protection E2E tests ==="
        go test -tags e2e -run TestLinkProtectE2E -v -count=1 -timeout 120s ./internal/smtp/...
        ;;
    ews)
        : "${TEST_EWS_CONFIG:?TEST_EWS_CONFIG is required for EWS E2E}"
        echo "=== Running real EWS connector E2E ==="
        go test -tags e2e -run TestEWSRealServer -v -count=1 -timeout 300s ./internal/migration/...
        ;;
    m365)
        : "${TEST_M365_CONFIG:?TEST_M365_CONFIG is required for M365 E2E}"
        echo "=== Running real M365 connector E2E ==="
        go test -tags e2e -run TestM365RealServer -v -count=1 -timeout 300s ./internal/migration/...
        ;;
    *)
        echo "Unknown filter: $FILTER"
        echo "Usage: bash deploy/test.sh [all|imap|smtp|ldap|link-protect|ews|m365]"
        exit 1
        ;;
esac

echo ""
echo "=== All E2E tests passed ==="
