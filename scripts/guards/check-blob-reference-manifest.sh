#!/usr/bin/env bash
# Static blob-reference manifest and SQL catalog parity guard (Issue #550).
# Delegates to scripts/guards/check-blob-reference-manifest.py (stdlib-only Python).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/check-blob-reference-manifest.py" "$@"
