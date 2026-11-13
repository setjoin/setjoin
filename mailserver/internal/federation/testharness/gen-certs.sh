#!/usr/bin/env bash
# gen-certs.sh — one self-signed CA PER DOMAIN, no cross-signing.
#
# Models two (or three) real strangers: alpha.test, bravo.test, and
# charlie.test each mint their OWN root CA and their own leaf, signed by
# nobody else. There is no shared trust bundle — this is deliberate (R1: the
# question C0 exists to answer is whether anchor-on-allowlist can bind peer
# identity between strangers with NO shared CA; a shared/cross-signed CA
# would make that question trivial). alpha trusts bravo ONLY because a human
# pinned bravo's CA cert (or fingerprint) on alpha's federation_allowlist
# row, and vice versa.
#
# Output: <domain>.ca.key / <domain>.ca.crt (the per-domain root) and
# <domain>.key / <domain>.crt (the leaf a fedharness instance for that
# domain presents both when dialing out and when accepting inbound
# connections — Ed25519, 30-day validity, harness-only).
#
# Usage: gen-certs.sh [output-dir]   (default: ./certs next to this script)
set -euo pipefail

OUT_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs}"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

for d in alpha.test bravo.test charlie.test; do
  echo "==> $d"
  openssl req -x509 -newkey ed25519 -keyout "$d.ca.key" -out "$d.ca.crt" \
    -days 30 -nodes -subj "/CN=$d-CA"
  openssl req -newkey ed25519 -keyout "$d.key" -out "$d.csr" \
    -nodes -subj "/CN=$d"
  openssl x509 -req -in "$d.csr" -CA "$d.ca.crt" -CAkey "$d.ca.key" -CAcreateserial \
    -out "$d.crt" -days 30 -extfile <(printf "subjectAltName=DNS:%s" "$d")
  rm -f "$d.csr"
done
# NO cross-signing anywhere above: alpha trusts bravo ONLY via bravo's
# CA cert/fingerprint pinned on alpha's federation_allowlist row (and
# symmetrically for every other pair) — never via a shared root.

echo "Certs written to $OUT_DIR"
