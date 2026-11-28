#!/usr/bin/env bash
# Monotonic EdgeContract CI coverage ratchet (#561).
# Enforces that no new non-JMAP/non-DAV HTTP route lands without a TypeSpec /
# OpenAPI 3.1 contract, covered routes never regress, and contracted webmail
# routes stay bound through openapi-fetch.
#
# Usage:
#   bash scripts/guards/check-edge-contract-ratchet.sh [--diff-base <git-ref>] [extra args...]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec python3 "$ROOT/scripts/guards/check-edge-contract-ratchet.py" "$@"
