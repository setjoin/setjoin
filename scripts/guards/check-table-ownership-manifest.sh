#!/usr/bin/env bash
# Static table-ownership and 3-class security manifest guard (Issue #539).
# Delegates to scripts/guards/check-table-ownership-manifest.py (stdlib-only Python).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/check-table-ownership-manifest.py" "$@"
