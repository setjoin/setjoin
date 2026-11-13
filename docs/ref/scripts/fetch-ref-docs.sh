#!/bin/bash
# ── Reference Docs Fetcher ──────────────────────────────────────────────
# Downloads/caches API docs, RFCs, and infrastructure configs for all
# external dependencies. Compares against MANIFEST.md to detect stale docs.
#
# Usage:
#   bash docs/ref/scripts/fetch-ref-docs.sh           # fetch missing/stale
#   bash docs/ref/scripts/fetch-ref-docs.sh --check   # dry-run: report status
#   bash docs/ref/scripts/fetch-ref-docs.sh --force   # re-download everything
#
# Requires: Go (for go doc), curl, git

set -euo pipefail

CHECK=false
FORCE=false
for arg in "$@"; do
    case "$arg" in
        --check) CHECK=true ;;
        --force) FORCE=true ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REF_DIR="$(dirname "$SCRIPT_DIR")"
GATEWAY_DIR="$(dirname "$(dirname "$(dirname "$REF_DIR")")")/gateway"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

status_line() {
    local status="$1" label="$2"
    case "$status" in
        OK)    echo -e "  ${GREEN}✔${NC} $label" ;;
        STALE) echo -e "  ${YELLOW}⚠${NC} $label (needs update)" ;;
        MISS)  echo -e "  ${RED}✘${NC} $label (missing)" ;;
        SKIP)  echo -e "  - $label (up to date)" ;;
    esac
}

# ── Go library API docs ──────────────────────────────────────────────

fetch_go_doc() {
    local pkg="$1" version="$2" file="$3"
    local out="$REF_DIR/go/$file"

    if [[ -f "$out" ]] && ! $FORCE; then
        status_line SKIP "$file"
        return
    fi

    if $CHECK; then
        if [[ -f "$out" ]]; then
            status_line OK "$file"
        else
            status_line MISS "$file"
        fi
        return
    fi

    echo -n "  fetching $file... "
    cd "$GATEWAY_DIR"
    if go doc -all "$pkg" > "$out" 2>&1; then
        echo "done ($(wc -l < "$out" | tr -d ' ') lines)"
        status_line OK "$file"
    else
        echo "FAILED"
        status_line MISS "$file"
    fi
}

echo "=== Go Library API Docs ==="
fetch_go_doc "github.com/emersion/go-imap"         "v1.2.1" "emersion-go-imap-v1.2.1.md"
fetch_go_doc "github.com/jackc/pgx/v5/pgxpool"      "v5.9.2" "jackc-pgx-v5.9.2.md"
fetch_go_doc "github.com/minio/minio-go/v7"          "v7.0.100" "minio-go-v7.0.100.md"
fetch_go_doc "github.com/gorilla/websocket"          "v1.5.3" "gorilla-websocket-v1.5.3.md"
fetch_go_doc "github.com/golang-jwt/jwt/v5"          "v5.3.1" "golang-jwt-v5.3.1.md"
fetch_go_doc "github.com/go-webauthn/webauthn/webauthn" "v0.17.2" "go-webauthn-v0.17.2.md"
fetch_go_doc "golang.org/x/crypto/acme/autocert"     "v0.50.0" "x-crypto-autocert-v0.50.0.md"

# ── RFC documents ───────────────────────────────────────────────────

fetch_rfc() {
    local rfc="$1" slug="$2"
    local out="$REF_DIR/rfc/rfc${rfc}.txt"

    if [[ -f "$out" ]] && ! $FORCE; then
        status_line SKIP "RFC $rfc ($slug)"
        return
    fi

    if $CHECK; then
        if [[ -f "$out" ]]; then
            status_line OK "RFC $rfc ($slug)"
        else
            status_line MISS "RFC $rfc ($slug)"
        fi
        return
    fi

    echo -n "  fetching RFC $rfc ($slug)... "
    if curl -sLf "https://www.rfc-editor.org/rfc/rfc${rfc}.txt" > "$out" 2>/dev/null; then
        # Header/number identity check (reference-corpus integrity): a fetched
        # mirror must carry the IETF header for the exact RFC number requested.
        # A truncated or mis-numbered mirror (e.g. a COSE body saved under an
        # IMAP LIST name) fails the fetch instead of silently entering the
        # normative corpus.
        if ! grep -Eq "Request for Comments: ${rfc}([^0-9]|[$])" "$out"; then
            rm -f "$out"
            echo "FAILED (identity check: header does not match RFC ${rfc})"
            status_line MISS "RFC $rfc ($slug)"
            return
        fi
        echo "done ($(wc -l < "$out" | tr -d ' ') lines)"
        status_line OK "RFC $rfc"
    else
        echo "FAILED"
        status_line MISS "RFC $rfc"
    fi
}

echo ""
echo "=== RFC Documents ==="
fetch_rfc 8620 "JMAP Core"
fetch_rfc 8621 "JMAP Mail"
fetch_rfc 8887 "JMAP Push"
fetch_rfc 9404 "JMAP Blob"
fetch_rfc 8461 "MTA-STS"
fetch_rfc 8460 "TLS-RPT"
fetch_rfc 7672 "DANE/TLSA"
fetch_rfc 8617 "ARC"
fetch_rfc 6350 "vCard 4.0"

# ── Infrastructure configs ──────────────────────────────────────────

echo ""
echo "=== Infrastructure Configs ==="

# Dovecot
dovecot_out="$REF_DIR/infra/dovecot-2.3.21-config.md"
if [[ -f "$dovecot_out" ]] && ! $FORCE; then
    status_line SKIP "Dovecot config"
elif $CHECK; then
    status_line SKIP "Dovecot config (manual only)"
else
    echo -n "  fetching dovecot config... "
    docker run --rm test-imap-imap-test dovecot -n > "$dovecot_out" 2>/dev/null && echo "done" || echo "SKIP (Docker image not found)"
fi

# Summary
echo ""
echo "=== Summary ==="
total=$(find "$REF_DIR/go" "$REF_DIR/rfc" -type f 2>/dev/null | wc -l | tr -d ' ')
echo "  Go API docs: $(find "$REF_DIR/go" -type f 2>/dev/null | wc -l | tr -d ' ') files"
echo "  RFCs: $(find "$REF_DIR/rfc" -type f 2>/dev/null | wc -l | tr -d ' ') files"
echo "  Infra configs: $(find "$REF_DIR/infra" -type f 2>/dev/null | wc -l | tr -d ' ') files"
echo "  Manifest: $REF_DIR/MANIFEST.md"
echo ""
echo "Done."
