#!/usr/bin/env bash
# Workflow hygiene for the public repository: jobs run on GitHub-hosted runners
# only (no `self-hosted` mention anywhere outside a comment), and no step dumps
# the environment or host details; tool output stays version-only
# (`go version`, not `go env`).
# Usage: bash scripts/check-workflow-log-hygiene.sh [--self-test] [workflow-dir]
set -euo pipefail

# Any non-comment mention: runs-on lists, block lists, JSON label strings, matrix values.
HOSTED_ONLY='self-hosted'
# Commands whose output carries host paths, users, addresses or every env var.
FORBIDDEN='(^|[;&|[:space:]])(printenv|set -x|set -o xtrace|go env|docker info|uname -a|ip addr|ifconfig|hostnamectl|cat /proc/)([[:space:]]|$)|^[[:space:]]*env[[:space:]]*$'

check_dir() {
  local dir="$1" f fail=0
  for f in "$dir"/*.yml "$dir"/*.yaml; do
    [ -f "$f" ] || continue
    if grep -n -i -F "$HOSTED_ONLY" "$f" | grep -v -E '^[0-9]+:[[:space:]]*#' >&2; then
      echo "WORKFLOW-HYGIENE-FAIL: $f names a self-hosted runner (lines above); use GitHub-hosted labels only" >&2
      fail=1
    fi
    if grep -n -E "$FORBIDDEN" "$f" | grep -v -E '^[0-9]+:[[:space:]]*#' >&2; then
      echo "WORKFLOW-HYGIENE-FAIL: $f dumps environment or host details (lines above); print versions only" >&2
      fail=1
    fi
  done
  return "$fail"
}

self_test() {
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/workflow-hygiene-selftest.XXXXXX")"
  trap 'rm -rf "$tmp"' RETURN
  good() {
    printf 'jobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: go version\n      # self-hosted runners were retired; set -x is never used here\n' >"$tmp/w.yml"
  }
  expect_fail() {
    if check_dir "$tmp" 2>/dev/null; then
      echo "self-test: $1 not caught" >&2
      return 1
    fi
  }
  good
  check_dir "$tmp" 2>/dev/null || {
    echo "self-test: compliant workflow rejected" >&2
    return 1
  }
  printf 'jobs:\n  a:\n    runs-on: [self-hosted, linux, x64]\n' >"$tmp/w.yml"
  expect_fail "inline self-hosted label" || return 1
  printf 'jobs:\n  a:\n    runs-on:\n      - self-hosted\n      - linux\n' >"$tmp/w.yml"
  expect_fail "block-list self-hosted label" || return 1
  printf 'on:\n  workflow_dispatch:\n    inputs:\n      r:\n        default: %s\n' "'[\"self-hosted\"]'" >"$tmp/w.yml"
  expect_fail "self-hosted label in an input default" || return 1
  good
  printf '      - run: go env\n' >>"$tmp/w.yml"
  expect_fail "go env dump" || return 1
  good
  printf '      - run: |\n          env\n' >>"$tmp/w.yml"
  expect_fail "bare env dump" || return 1
  echo "check-workflow-log-hygiene self-test: OK (self-hosted labels, go env, bare env caught; comments and version prints allowed)"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit
fi
DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.github/workflows}"
check_dir "$DIR"
echo "workflow hygiene: clean ($(find "$DIR" -maxdepth 1 -name '*.y*ml' | wc -l) workflows, GitHub-hosted only)"
