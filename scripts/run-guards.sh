#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# run-guards.sh — THE structural-guard manifest.
#
# "Which guards gate a merge" used to be a literal list re-typed (and drifted)
# across test.sh / ci-local.sh / lint.sh, while GitHub CI ran none of them.
# This script makes the guard set the FILESYSTEM: every scripts/check-*.sh
# (excluding *-selftest.sh companions) runs here, self-test first, so adding a
# guard = dropping a file — no orchestrator edits, nothing to forget.
#
# Per guard, in glob (alphabetical) order:
#   1. If check-X-selftest.sh exists → run it (prove the guard still FIRES
#      before trusting its clean verdict).
#   2. Else if the guard advertises a --self-test flag → run `check-X.sh --self-test`.
#   3. Else warn "(no self-test)" — the gap stays visible on every run.
#   4. Run the guard itself.
# All failures are collected (not first-fail) so one run yields the full punch
# list; exit is non-zero if anything failed.
#
# Flags:
#   --no-db   skip guards marked with a literal `# guard-requires: db` line
#             (currently check-schema-determinism.sh, the double-DB-rebuild one)
#             for environments without Postgres.
#
# Consumers: scripts/test.sh (merge gate) · scripts/ci-local.sh (--no-db path)
#            (the xinchuang-ci.yml unit-tests job that also ran it was retired).
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

NO_DB=0
for a in "$@"; do
  case "$a" in
    --no-db) NO_DB=1 ;;
    *) echo "usage: run-guards.sh [--no-db]" >&2; exit 2 ;;
  esac
done

fail=()
no_selftest=()
skipped=()
ran=0

# OpenAPI coverage/visibility consume the runtime-derived route artifact. Build
# and validate it once before the alphabetical guard loop reaches either
# consumer; skip its normal position below so this prerequisite is not repeated.
route_guard="$ROOT/scripts/check-route-inventory.sh"
if [[ -f "$route_guard" ]]; then
  echo "──[ guard prerequisite: check-route-inventory ]──"
  if ! bash "$route_guard" --self-test; then
    echo "✗ SELF-TEST FAILED: check-route-inventory (guard may no longer fire — do not trust it)"
    fail+=("check-route-inventory (self-test)")
  elif bash "$route_guard"; then
    ran=$((ran + 1))
  else
    echo "✗ GUARD FAILED: check-route-inventory"
    fail+=("check-route-inventory")
  fi
fi

for g in "$ROOT"/scripts/check-*.sh; do
  case "$g" in *-selftest.sh) continue ;; esac
  name="$(basename "$g" .sh)"
  [[ "$name" == "check-route-inventory" ]] && continue

  if [ "$NO_DB" = 1 ] && grep -q '^# guard-requires: db' "$g"; then
    skipped+=("$name")
    continue
  fi

  st="${g%.sh}-selftest.sh"
  echo "──[ guard: $name ]──"
  if [ -f "$st" ]; then
    if ! bash "$st"; then
      echo "✗ SELF-TEST FAILED: $name (guard may no longer fire — do not trust it)"
      fail+=("$name (self-test)")
      continue
    fi
  elif grep -q -- '--self-test' "$g"; then
    if ! bash "$g" --self-test; then
      echo "✗ SELF-TEST FAILED: $name (guard may no longer fire — do not trust it)"
      fail+=("$name (self-test)")
      continue
    fi
  elif grep -q -- '"-selftest"' "$g"; then
    # single-dash spelling (check-jit-coverage / check-reach-coverage)
    if ! bash "$g" -selftest; then
      echo "✗ SELF-TEST FAILED: $name (guard may no longer fire — do not trust it)"
      fail+=("$name (self-test)")
      continue
    fi
  else
    echo "  (no self-test — verdict below is untested against a planted violation)"
    no_selftest+=("$name")
  fi

  if bash "$g"; then
    ran=$((ran + 1))
  else
    echo "✗ GUARD FAILED: $name"
    fail+=("$name")
  fi
done

echo
echo "══ run-guards summary ══"
echo "  passed:  $ran"
[ ${#skipped[@]} -gt 0 ]     && echo "  skipped (--no-db): ${skipped[*]}"
[ ${#no_selftest[@]} -gt 0 ] && echo "  no self-test: ${no_selftest[*]}"
if [ ${#fail[@]} -gt 0 ]; then
  echo "  FAILED:  ${fail[*]}"
  exit 1
fi
echo "  all structural guards green."
