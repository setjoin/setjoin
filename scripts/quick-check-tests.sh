#!/usr/bin/env bash
# Runs `cargo test --lib -p PKG [-- FILTER...]` and proves tests really executed.
#   quick-check-tests.sh run PKG [FILTER...]   (cwd: repo root; filters must not start with '-')
#   quick-check-tests.sh verify                 libtest output on stdin -> exit 0 only if passed+failed > 0
#   quick-check-tests.sh selftest               fixture checks, no cargo needed
set -uo pipefail

# Sum `test result: ok. N passed; M failed; ...` over all binaries. Prints "executed=N skip_markers=K".
verify() {
  local log; log="$(cat)"
  local passed failed skips
  passed="$(sed -nE 's/^test result: .*[^0-9]([0-9]+) passed;.*/\1/p' <<<"$log" | awk '{s+=$1} END{print s+0}')"
  failed="$(sed -nE 's/^test result: .*[^0-9]([0-9]+) failed;.*/\1/p' <<<"$log" | awk '{s+=$1} END{print s+0}')"
  skips="$(grep -cE '[A-Z][A-Z0-9-]*-SKIP \(reason=' <<<"$log" || true)"
  passed="${passed:-0}"; failed="${failed:-0}"
  echo "quick-check-tests: executed=$((passed + failed)) passed=$passed failed=$failed skip_markers=$skips"
  if [ $((passed + failed)) -eq 0 ]; then
    echo "quick-check-tests: FAIL: zero tests executed (misspelled filter or listing-only run)" >&2
    return 1
  fi
}

run() {
  local pkg="$1"; shift
  local a
  for a in "$@"; do
    case "$a" in -*) echo "quick-check-tests: FAIL: option-like test argument '$a' rejected" >&2; return 2 ;; esac
  done
  local tmp rc; tmp="$(mktemp)"
  ( cd server-rust && cargo test --locked -p "$pkg" --lib ${1:+--} "$@" ) > "$tmp" 2>&1
  rc=$?
  cat "$tmp"
  if [ "$rc" -ne 0 ]; then rm -f "$tmp"; return "$rc"; fi
  verify < "$tmp"; rc=$?
  rm -f "$tmp"; return "$rc"
}

selftest() {
  local fails=0 out
  expect() { # name want_rc fixture
    out="$(printf '%s\n' "$3" | verify 2>&1)"; local rc=$?
    if [ "$rc" -eq "$2" ]; then echo "ok   $1"; else echo "FAIL $1 (rc=$rc want $2): $out"; fails=1; fi
  }
  expect zero-run 1 $'running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s'
  expect listing-only 1 $'a::b: test\nc::d: test\n\n2 tests, 0 benchmarks'
  expect normal-pass 0 $'running 2 tests\ntest a ... ok\ntest b ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
  expect multi-binary 0 $'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s\ntest result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
  expect skip-marker-line 0 $'SETJOIN-PG-DB-SKIP (reason=no-dsn)\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
  if run pkg --list >/dev/null 2>&1; then echo "FAIL option-arg accepted"; fails=1; else echo "ok   option-arg rejected"; fi
  return "$fails"
}

case "${1:-}" in
  run) shift; run "$@" ;;
  verify) verify ;;
  selftest) selftest ;;
  *) echo "usage: $0 run PKG [FILTER...]|verify|selftest" >&2; exit 2 ;;
esac
