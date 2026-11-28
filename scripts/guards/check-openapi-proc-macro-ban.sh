#!/usr/bin/env bash
# Structural guard: ban OpenAPI proc-macro crates and attributes in
# server/crates/{domains/*,contracts/*,pg/*} (#561).
# Usage: bash scripts/guards/check-openapi-proc-macro-ban.sh [--root <server-rust-dir>]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec python3 "$ROOT/scripts/guards/check-openapi-proc-macro-ban.py" "$@"
