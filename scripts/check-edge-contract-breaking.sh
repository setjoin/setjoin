#!/usr/bin/env bash
# EdgeContract breaking-change gate (#561).
# Runs oasdiff breaking --format json (when installed in PATH) AND the built-in
# deterministic Python OpenAPI 3.1 breaking-change + 12-month sunset waiver
# validator so per-change waivers never globally silence unrelated oasdiff ERR
# findings.
#
# Usage:
#   bash scripts/check-edge-contract-breaking.sh
#   bash scripts/check-edge-contract-breaking.sh --base <base.yaml> --head <head.yaml> [--waivers <json>] [--today YYYY-MM-DD]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_HEAD="$ROOT/contracts/edge/openapi/edge.v1.yaml"
DEFAULT_WAIVERS="$ROOT/contracts/edge/approved-breaking.json"

BASE=""
HEAD="$DEFAULT_HEAD"
WAIVERS="$DEFAULT_WAIVERS"
TODAY=""

while [ $# -gt 0 ]; do
  case "$1" in
    --base)
      shift
      BASE="${1:?--base requires a path}"
      ;;
    --head)
      shift
      HEAD="${1:?--head requires a path}"
      ;;
    --waivers)
      shift
      WAIVERS="${1:?--waivers requires a path}"
      ;;
    --today)
      shift
      TODAY="${1:?--today requires YYYY-MM-DD}"
      ;;
    *)
      echo "usage: check-edge-contract-breaking.sh [--base FILE] [--head FILE] [--waivers FILE] [--today YYYY-MM-DD]" >&2
      exit 2
      ;;
  esac
  shift
done

tmp_base=""
tmp_oasdiff=""
cleanup() {
  if [ -n "$tmp_base" ]; then
    rm -f "$tmp_base"
  fi
  if [ -n "$tmp_oasdiff" ]; then
    rm -f "$tmp_oasdiff"
  fi
}
trap cleanup EXIT

if [ -z "$BASE" ]; then
  if [ -n "${EDGE_CONTRACT_BASE_REF:-}" ]; then
    # Explicit base ref MUST resolve to a real commit; fail closed on bad refs.
    if ! git -C "$ROOT" rev-parse --verify "${EDGE_CONTRACT_BASE_REF}^{commit}" >/dev/null 2>&1; then
      echo "EDGE-CONTRACT-BREAKING-FAIL: cannot resolve EDGE_CONTRACT_BASE_REF='${EDGE_CONTRACT_BASE_REF}'" >&2
      exit 1
    fi
    if git -C "$ROOT" cat-file -e "${EDGE_CONTRACT_BASE_REF}:contracts/edge/openapi/edge.v1.yaml" 2>/dev/null; then
      tmp_base="$(mktemp "${TMPDIR:-/tmp}/edge-contract-base.XXXXXX.yaml")"
      git -C "$ROOT" show "${EDGE_CONTRACT_BASE_REF}:contracts/edge/openapi/edge.v1.yaml" >"$tmp_base"
      BASE="$tmp_base"
    else
      # Verified base commit predates contracts/edge/openapi/edge.v1.yaml.
      BASE="$HEAD"
    fi
  else
    for ref in origin/main main HEAD; do
      if git -C "$ROOT" cat-file -e "${ref}:contracts/edge/openapi/edge.v1.yaml" 2>/dev/null; then
        tmp_base="$(mktemp "${TMPDIR:-/tmp}/edge-contract-base.XXXXXX.yaml")"
        git -C "$ROOT" show "${ref}:contracts/edge/openapi/edge.v1.yaml" >"$tmp_base"
        BASE="$tmp_base"
        break
      fi
    done
    if [ -z "$BASE" ]; then
      BASE="$HEAD"
    fi
  fi
fi

py_args=(--base "$BASE" --head "$HEAD")
if [ -n "$WAIVERS" ] && [ -f "$WAIVERS" ]; then
  py_args+=(--waivers "$WAIVERS")
fi
if [ -n "$TODAY" ]; then
  py_args+=(--today "$TODAY")
fi

# 1. Run oasdiff breaking in JSON mode when installed (CI installs pinned oasdiff v1.41.0).
#    Pass structured findings into Python so ONLY explicitly waived, matured
#    changes are suppressed and any unwaived oasdiff ERR still fails closed.
if command -v oasdiff >/dev/null 2>&1; then
  tmp_oasdiff="$(mktemp "${TMPDIR:-/tmp}/edge-oasdiff.XXXXXX.json")"
  oasdiff_rc=0
  oasdiff breaking "$BASE" "$HEAD" --format json >"$tmp_oasdiff" || oasdiff_rc=$?
  if [ "$oasdiff_rc" -ne 0 ] && [ ! -s "$tmp_oasdiff" ]; then
    echo "EDGE-CONTRACT-BREAKING-FAIL: oasdiff exited with status $oasdiff_rc without JSON findings" >&2
    exit 1
  fi
  py_args+=(--oasdiff-json "$tmp_oasdiff")
fi

# 2. Always run deterministic OpenAPI 3.1 breaking-change + 12-month waiver checker.
python3 "$ROOT/scripts/check-edge-contract-breaking.py" "${py_args[@]}"
