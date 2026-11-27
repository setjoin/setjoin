#!/usr/bin/env bash
# Structural guard: ban OpenAPI proc-macro crates and attributes in
# server-rust/crates/{domains/*,contracts/*,pg/*} (#561).
# Usage: bash scripts/check-openapi-proc-macro-ban.sh [--root <server-rust-dir>]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/scripts/check-openapi-proc-macro-ban.py" "$@"
