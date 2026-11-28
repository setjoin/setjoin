#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# run-guards.sh — THE structural-guard manifest.
#
# "Which guards gate a merge" used to be a literal list re-typed (and drifted)
# across test.sh / ci-local.sh / lint.sh, while GitHub CI ran none of them.
# This script makes the guard set the FILESYSTEM: every scripts/guards/check-*.sh
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
#   --known-red FILE
#             tolerate listed guards (one `name  # reason, #issue` per line). A listed
#             guard still runs, self-test first; its failure is printed as a warning and
#             does not fail the run. A listed name with no guard file fails the run.
#
# Consumers: scripts/test.sh (merge gate) · scripts/ci/ci-local.sh (--no-db path)
#            (the xinchuang-ci.yml unit-tests job that also ran it was retired).
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

NO_DB=0
KNOWN_RED_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-db) NO_DB=1 ;;
    --known-red) shift; KNOWN_RED_FILE="${1:?--known-red needs a file}" ;;
    *) echo "usage: run-guards.sh [--no-db] [--known-red FILE]" >&2; exit 2 ;;
  esac
  shift
done

known_red=()
if [ -n "$KNOWN_RED_FILE" ]; then
  while IFS= read -r line; do
    line="${line%%#*}"; line="${line//[[:space:]]/}"
    [ -n "$line" ] || continue
    [ -f "$ROOT/scripts/guards/$line.sh" ] || { echo "known-red entry has no guard: $line" >&2; exit 2; }
    known_red+=("$line")
  done < "$KNOWN_RED_FILE"
fi
is_known_red() { local n; for n in "${known_red[@]:-}"; do [ "$n" = "$1" ] && return 0; done; return 1; }
tolerated=()
stale_red=()

fail=()
no_selftest=()
skipped=()
ran=0

JOBS="${RUN_GUARDS_JOBS:-1}"
case "$JOBS" in
  '' | *[!0-9]* | 0) echo "invalid RUN_GUARDS_JOBS: $JOBS (expected positive integer)" >&2; exit 2 ;;
esac

run_one_guard() { # <script-path> <status-file>
  local g="$1" status_file="$2" tmp_status name st
  tmp_status="${status_file}.tmp"
  name="$(basename "$g" .sh)"
  st="${g%.sh}-selftest.sh"
  : > "$tmp_status"
  echo "──[ guard: $name ]──"
  if [ -f "$st" ]; then
    if ! bash "$st"; then
      echo "✗ SELF-TEST FAILED: $name (guard may no longer fire — do not trust it)"
      if is_known_red "$name"; then
        printf 'tolerated\t%s (self-test)\n' "$name" >> "$tmp_status"
      else
        printf 'fail\t%s (self-test)\n' "$name" >> "$tmp_status"
      fi
      mv "$tmp_status" "$status_file"
      return 0
    fi
  elif grep -q -- '--self-test' "$g"; then
    if ! bash "$g" --self-test; then
      echo "✗ SELF-TEST FAILED: $name (guard may no longer fire — do not trust it)"
      if is_known_red "$name"; then
        printf 'tolerated\t%s (self-test)\n' "$name" >> "$tmp_status"
      else
        printf 'fail\t%s (self-test)\n' "$name" >> "$tmp_status"
      fi
      mv "$tmp_status" "$status_file"
      return 0
    fi
  elif grep -q -- '"-selftest"' "$g"; then
    # single-dash spelling (check-jit-coverage / check-reach-coverage)
    if ! bash "$g" -selftest; then
      echo "✗ SELF-TEST FAILED: $name (guard may no longer fire — do not trust it)"
      if is_known_red "$name"; then
        printf 'tolerated\t%s (self-test)\n' "$name" >> "$tmp_status"
      else
        printf 'fail\t%s (self-test)\n' "$name" >> "$tmp_status"
      fi
      mv "$tmp_status" "$status_file"
      return 0
    fi
  else
    echo "  (no self-test — verdict below is untested against a planted violation)"
    printf 'no_selftest\t%s\n' "$name" >> "$tmp_status"
  fi

  if bash "$g"; then
    printf 'pass\t%s\n' "$name" >> "$tmp_status"
    ! is_known_red "$name" || printf 'stale_red\t%s\n' "$name" >> "$tmp_status"
  else
    echo "✗ GUARD FAILED: $name"
    if is_known_red "$name"; then
      printf 'tolerated\t%s\n' "$name" >> "$tmp_status"
    else
      printf 'fail\t%s\n' "$name" >> "$tmp_status"
    fi
  fi
  mv "$tmp_status" "$status_file"
}

apply_guard_status() { # <status-file> <guard-name>
  local kind val saw_terminal=0
  while IFS=$'\t' read -r kind val; do
    case "$kind" in
      no_selftest) no_selftest+=("$val") ;;
      pass) ran=$((ran + 1)); saw_terminal=1 ;;
      stale_red) stale_red+=("$val") ;;
      tolerated) tolerated+=("$val"); saw_terminal=1 ;;
      fail) fail+=("$val"); saw_terminal=1 ;;
    esac
  done < "$1"
  if [ "$saw_terminal" -ne 1 ]; then
    fail+=("$2 (incomplete status)")
  fi
}

all_guards=()
non_db_guards=()
db_guards=()

for g in "$ROOT"/scripts/guards/check-*.sh; do
  case "$g" in *-selftest.sh) continue ;; esac
  name="$(basename "$g" .sh)"
  # Release-signing workflow gate (requires GITHUB_REPOSITORY and BUILD_RUN_ID;
  # exercised by scripts/guards/test-check-server-release-build.sh, not a repo-tree guard).
  [[ "$name" == "check-server-release-build" ]] && continue

  if grep -q '^# guard-requires: db' "$g"; then
    if [ "$NO_DB" = 1 ]; then
      skipped+=("$name")
      continue
    fi
    idx="${#all_guards[@]}"
    all_guards+=("$g")
    db_guards+=("$idx")
  else
    idx="${#all_guards[@]}"
    all_guards+=("$g")
    non_db_guards+=("$idx")
  fi
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ "${#all_guards[@]}" -eq 0 ]; then
  :
elif [ "$JOBS" -le 1 ] || [ "${#all_guards[@]}" -le 1 ]; then
  for idx in "${!all_guards[@]}"; do
    name="$(basename "${all_guards[$idx]}" .sh)"
    run_one_guard "${all_guards[$idx]}" "$WORK/$idx.status"
    apply_guard_status "$WORK/$idx.status" "$name"
  done
else
  worker_pids=()
  if [ "${#db_guards[@]}" -gt 0 ]; then
    (
      for idx in "${db_guards[@]}"; do
        run_one_guard "${all_guards[$idx]}" "$WORK/$idx.status" > "$WORK/$idx.log" 2>&1
      done
    ) &
    worker_pids+=("$!")
  fi
  if [ "${#non_db_guards[@]}" -gt 0 ]; then
    n_workers="$JOBS"
    [ "${#non_db_guards[@]}" -lt "$n_workers" ] && n_workers="${#non_db_guards[@]}"
    for ((w = 0; w < n_workers; w++)); do
      (
        for idx in "${non_db_guards[@]}"; do
          mkdir "$WORK/claim.$idx" 2>/dev/null || continue
          run_one_guard "${all_guards[$idx]}" "$WORK/$idx.status" > "$WORK/$idx.log" 2>&1
        done
      ) &
      worker_pids+=("$!")
    done
  fi
  for pid in "${worker_pids[@]}"; do
    if ! wait "$pid"; then
      fail+=("worker-pid-$pid (aborted)")
    fi
  done
  for idx in "${!all_guards[@]}"; do
    name="$(basename "${all_guards[$idx]}" .sh)"
    [ -f "$WORK/$idx.log" ] && cat "$WORK/$idx.log"
    if [ -f "$WORK/$idx.status" ]; then
      apply_guard_status "$WORK/$idx.status" "$name"
    else
      fail+=("$name (missing status)")
    fi
  done
fi

echo
echo "══ run-guards summary ══"
echo "  passed:  $ran"
[ ${#skipped[@]} -gt 0 ]     && echo "  skipped (--no-db): ${skipped[*]}"
[ ${#no_selftest[@]} -gt 0 ] && echo "  no self-test: ${no_selftest[*]}"
if [ ${#tolerated[@]} -gt 0 ]; then
  echo "  KNOWN RED (tolerated via $KNOWN_RED_FILE): ${tolerated[*]}"
  [ -z "${GITHUB_ACTIONS:-}" ] || echo "::warning title=known-red guards::${tolerated[*]} (see $KNOWN_RED_FILE)"
fi
if [ ${#stale_red[@]} -gt 0 ]; then
  # Ratchet: the allowlist can only shrink.
  echo "  STALE known-red (now PASS): ${stale_red[*]} — remove from $KNOWN_RED_FILE"
  fail+=("stale known-red: ${stale_red[*]}")
fi
if [ ${#fail[@]} -gt 0 ]; then
  echo "  FAILED:  ${fail[*]}"
  exit 1
fi
echo "  all structural guards green."
