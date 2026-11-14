#!/usr/bin/env bash
# check-server-rust.sh — the Rust server tests gate the build (#211).
#
# Checks workspace family isolation, licence exceptions, cargo-deny licence,
# source, ban and advisory policy, the recorded-oracle floor, selected replay/mutant tests,
# and per-route Rust coverage (Python 3.11+, cargo-deny 0.19.0, llvm-tools).
# Runs every server-rust Cargo root with `cargo test --locked`:
#   1. server-rust/                        — workspace: bins/gateway (front door,
#                                            fake-upstream proxy tests), authz, contracts,
#                                            db, domains/jmap, domains/recording, pg, push, schema,
#                                            tests/conformance (DB-backed parity oracles)
#      Includes shared certificate/PEM/trust foundation in crates/certificates (#526).
#      Includes shared spam model and inbound scoring in crates/spam (#526).
#      Includes shared auth runtime/protocol admission in crates/threat (#420).
#      Includes the CI-only setjoin-release and shared release-format crate (#357),
#      and the standalone setjoin-updater process/installer oracles (#358).
#   2. server-rust/pilot/                  — Seen-intent pilot (own package + lockfile, sha2 =0.11.1)
#   3. server-rust/tools/schema-simulation — independent tooling workspace (Rust 1.99, resolver 3)
#   4. server-rust/tools/bench-mark-read   — #217 Rust-vs-Go mark-read harness (own package, std only)
# The workspace runs `--no-fail-fast`, so one red binary no longer skips every later suite
# (the lane is still red; the full list of failing targets is reported once, #421).
# A failing, ignored, or non-compiling test, a stale lockfile, or a root that
# runs zero tests is red. schema-simulation and bench-mark-read have no external
# dependencies and always run --offline. The workspace (setjoin-pg: tokio-postgres + deadpool-postgres;
# setjoin-gateway: hyper + hyper-util + tokio) and
# the pilot run --offline when their locked dependencies are already in the
# cargo cache; otherwise each fetches the exact locked versions once
# (`cargo fetch --locked`) and then tests --offline. setjoin-pg's DB-backed
# tests read TEST_DB_DSN/DB_DSN (+ DB_APP_DSN): absent → each prints
# `SETJOIN-PG-DB-SKIP (reason=no-dsn)`; REQUIRE_DB=1 turns that into a failure.
# Every `<NAME>-SKIP (reason=` marker a root prints is counted per marker in a
# `DB-SKIP (marker=… count=… root=…)` line; under REQUIRE_DB=1 any skip is red.
#
# The conformance oracles need the same database: with TEST_DB_DSN/DB_DSN unset
# each case prints `CONFORMANCE-SKIP (reason=no-db …)` (summarised per root
# below); with REQUIRE_DB set and no DSN they fail (the Go
# `testsupport.OpenTestPool` rule).
#
# SERVER_RUST_NEXTEST=1 (the parallel full lane, #550) runs the workspace root with
# `cargo nextest run --profile lane` (one cloned database per test, serial groups for host
# state, see server-rust/.config/nextest.toml and scripts/server-rust-parallel-lane.sh)
# plus `cargo test --doc`, and keeps every check below: zero tests, ignored (nextest
# "skipped") and DB-skip markers stay red. Needs LANE_ADMIN_DSN/LANE_TEMPLATE_DB/LANE_BASE_DB.
#
# No cargo on PATH → prints `SERVER-RUST-SKIP (reason=cargo-not-found)` and
# exits 0: greppable, never a silent pass. CI's toolchain image ships Rust, so
# the skip only appears on a bare laptop.
#
# Env: SERVER_RUST_CARGO (cargo binary, default `cargo`); CARGO_TARGET_DIR is
# honoured (default: each root's own target/, gitignored).
#
# --self-test proves the guard fires: a throwaway temp crate with a failing
# test must go red, the same crate fixed must go green, ignored and zero-test
# crates must go red, and a missing cargo must print the SKIP line. The real tree is
# never touched by the self-test.
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"

CARGO="${SERVER_RUST_CARGO:-cargo}"

# leak_guard on|off: on the parallel lane every test owns a cloned database and the base
# database is only for the serial stages (doc tests, pilot, schema-simulation). While the
# nextest run and the adequacy gate are going the base refuses connections, so a test whose
# connection the wrapper did not re-point (a DSN assembled from parts, a scrubbed child env)
# fails with "not currently accepting connections" instead of silently sharing the base.
# LANE_LEAK_GUARD=0 turns it off. Always restored.
leak_guard() {
  [[ -n "${LANE_ADMIN_DSN:-}" && -n "${LANE_BASE_DB:-}" && "${LANE_LEAK_GUARD:-1}" != 0 ]] || return 0
  local allow=false
  [[ "$1" == off ]] && allow=true
  psql "$LANE_ADMIN_DSN" -X -q -v ON_ERROR_STOP=1 \
    -c "ALTER DATABASE \"$LANE_BASE_DB\" WITH ALLOW_CONNECTIONS $allow" >/dev/null || {
    echo "✗ server-rust: could not set the base database leak guard ($1)" >&2
    return 1
  }
  [[ "$1" == on ]] && echo "leak guard: $LANE_BASE_DB refuses connections while the per-test clones run"
  return 0
}

# lane_disk_sampler start|stop: every two minutes print the free space of the lane Postgres
# data disk and its largest directories (a gate run filled the 8 GB tmpfs while the databases
# summed to 110 MB, so the space went somewhere pg_database_size does not show: pg_wal,
# temp files, deleted-but-open files). A no-op without LANE_PG_CONTAINER.
LANE_DISK_SAMPLER_PID=""
lane_disk_sampler() {
  [[ -n "${LANE_PG_CONTAINER:-}" ]] && command -v docker >/dev/null 2>&1 || return 0
  if [[ "$1" == start ]]; then
    (
      while true; do
        sleep 120
        echo "lane disk $(date -u +%T): $(docker exec "$LANE_PG_CONTAINER" df -h /var/lib/postgresql/data 2>&1 | tail -1)"
        psql "${LANE_ADMIN_DSN:-}" -X -q -At -c "SELECT 'lane disk   db '||datname||' '||pg_size_pretty(pg_database_size(datname)) FROM pg_database ORDER BY pg_database_size(datname) DESC LIMIT 4" 2>/dev/null || true
        docker exec "$LANE_PG_CONTAINER" du -x -d 2 /var/lib/postgresql/data 2>/dev/null | sort -rn | head -6 | sed 's/^/lane disk   /'
        docker exec "$LANE_PG_CONTAINER" bash -c 'ls /proc/[0-9]*/fd 2>/dev/null >/dev/null; n=0; for l in /proc/[0-9]*/fd/*; do case "$(readlink "$l" 2>/dev/null)" in *"(deleted)") n=$((n+1));; esac; done; echo "lane disk   deleted-but-open files: $n"' 2>/dev/null
      done
    ) &
    LANE_DISK_SAMPLER_PID=$!
  elif [[ -n "$LANE_DISK_SAMPLER_PID" ]]; then
    kill "$LANE_DISK_SAMPLER_PID" 2>/dev/null || true
    wait "$LANE_DISK_SAMPLER_PID" 2>/dev/null || true
    LANE_DISK_SAMPLER_PID=""
  fi
}

# lane_go_watch start|stop (#141, Go-deletion rehearsal): around the nextest run and the adequacy gate,
# scripts/check-gofree-rehearsal.py records container create/start/exec and image events, pinned image
# identities, a container snapshot and a whole-container Go-ELF scan into
# $LANE_ARTIFACT_DIR/rehearsal-containers.jsonl. `start` returns once a probe proved the event stream
# live (red after 600 s); `stop` drains, reaps the watcher within 600 s, propagates its exit status and
# is red on any finding. A no-op without LANE_ARTIFACT_DIR or docker.
LANE_GO_WATCH_PID=""
lane_go_watch_reap() {
  local pid="$1" i
  kill -TERM "$pid" 2>/dev/null || true
  for i in $(seq 1 1200); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
  done
  if kill -KILL "$pid" 2>/dev/null; then
    echo "✗ server-rust: the rehearsal container watch did not stop within 600 s" >&2
    wait "$pid" 2>/dev/null
    return 1
  fi
  wait "$pid"
}
lane_go_watch() {
  [[ -n "${LANE_ARTIFACT_DIR:-}" ]] && command -v docker >/dev/null 2>&1 || return 0
  local file="$LANE_ARTIFACT_DIR/rehearsal-containers.jsonl" ready="$LANE_ARTIFACT_DIR/rehearsal-watch.ready" rc=0 i
  if [[ "$1" == start ]]; then
    rm -f "$ready"
    python3 "$ROOT/scripts/check-gofree-rehearsal.py" watch "$file" --ready "$ready" &
    LANE_GO_WATCH_PID=$!
    for i in $(seq 1 1200); do
      [[ -f "$ready" ]] && return 0
      kill -0 "$LANE_GO_WATCH_PID" 2>/dev/null || break
      sleep 0.5
    done
    echo "✗ server-rust: the rehearsal container watch did not become ready" >&2
    lane_go_watch_reap "$LANE_GO_WATCH_PID" || true
    LANE_GO_WATCH_PID=""
    return 1
  fi
  if [[ -z "$LANE_GO_WATCH_PID" ]]; then
    echo "✗ server-rust: the rehearsal container watch was not running" >&2
    return 1
  fi
  lane_go_watch_reap "$LANE_GO_WATCH_PID" || rc=1
  LANE_GO_WATCH_PID=""
  python3 "$ROOT/scripts/check-gofree-rehearsal.py" containers ${LANE_GO_MASKED:+--require-masked} "$file" || rc=1
  return "$rc"
}

# lane_clones report|sweep LABEL: the parallel lane keeps its Postgres in a job-owned data directory and
# every test or gate run owns a ~45 MB clone. `report` prints how many clones and how many bytes
# the cluster holds; `sweep` first drops any clone a finished phase left behind (a killed test
# cannot run its own cleanup), so one phase never starves the next (#472: the gate ran out of
# space after the nextest phase).
lane_clones() {
  [[ -n "${LANE_ADMIN_DSN:-}" && -n "${LANE_DB_PREFIX:-}" ]] || return 0
  local mode="$1" label="$2" name
  if [[ "$mode" == sweep ]]; then
    for name in $(psql "$LANE_ADMIN_DSN" -X -q -At -c "SELECT datname FROM pg_database WHERE datname ~ '^${LANE_DB_PREFIX}[0-9a-f]{24}\$'" 2>/dev/null); do
      echo "LANE-DB-LEAK (swept before $label): $name"
      psql "$LANE_ADMIN_DSN" -X -q -c "DROP DATABASE IF EXISTS \"$name\" WITH (FORCE)" >/dev/null 2>&1 || true
    done
  fi
  psql "$LANE_ADMIN_DSN" -X -q -At -c "SELECT format('lane databases %s: %s databases, %s', '$label', count(*), pg_size_pretty(sum(pg_database_size(datname)))) FROM pg_database" 2>/dev/null || true
}

# nextest_tests DIR LABEL: the parallel lane's test run. Workspace: lane profile with a
# cloned database per test and the generated serial groups; fixtures: plain nextest.
# Doc tests are not run by nextest, so `cargo test --doc` covers them (serially, on the
# base database).
nextest_tests() {
  local dir="$1" label="$2" groups rc=0
  if [[ "$label" == workspace ]]; then
    groups="$(mktemp)"
    python3 "$ROOT/scripts/server-rust-lane-groups.py" --root "$dir" >"$groups" || return 1
    leak_guard on || return 1
    lane_disk_sampler start
    lane_go_watch start || rc=1
    # Hosted CI: run the build job's archive (extracted to the same absolute target dir) and
    # only this shard's partition; doc tests then run in the roots stage.
    local build=(--workspace --locked --offline) partition=()
    if [[ -n "${SERVER_RUST_NEXTEST_ARCHIVE:-}" ]]; then
      build=(--archive-file "$SERVER_RUST_NEXTEST_ARCHIVE" --workspace-remap "$dir"
             --extract-to "${SERVER_RUST_NEXTEST_EXTRACT_TO:?SERVER_RUST_NEXTEST_EXTRACT_TO is required with an archive}" --extract-overwrite)
    fi
    [[ -n "${SERVER_RUST_NEXTEST_PARTITION:-}" ]] && partition=(--partition "$SERVER_RUST_NEXTEST_PARTITION")
    (cd "$dir" && "$CARGO" nextest run "${build[@]}" ${partition[@]+"${partition[@]}"} --no-fail-fast --profile lane \
      --tool-config-file "lane:$groups" -j "${LANE_JOBS:-5}" --success-output immediate --failure-output immediate-final \
      --color never 2>&1) || rc=1
    lane_disk_sampler stop
    lane_go_watch stop || rc=1
    leak_guard off || rc=1
    lane_clones report "after nextest"
    rm -f "$groups"
  else
    (cd "$dir" && "$CARGO" nextest run --workspace --locked --offline --no-fail-fast --success-output immediate \
      --failure-output immediate-final --color never 2>&1) || rc=1
  fi
  if [[ -z "${SERVER_RUST_NEXTEST_ARCHIVE:-}" ]]; then
    (cd "$dir" && "$CARGO" test --doc --locked --offline --workspace --no-fail-fast --color never 2>&1) || rc=1
  fi
  return "$rc"
}

# run_root DIR LABEL [offline|auto]: cargo test --locked in DIR; red on a test
# failure or when no test ran at all.
run_root() {
  local dir="$1" label="$2" mode="${3:-offline}" log passed skipped ignored
  [[ -f "$dir/Cargo.toml" ]] || {
    echo "✗ server-rust: $label missing ($dir/Cargo.toml)" >&2
    return 1
  }
  # an archive run has no registry cache and compiles nothing: skip the fetch
  if [[ "$mode" == auto && -z "${SERVER_RUST_NEXTEST_ARCHIVE:-}" ]] && ! (cd "$dir" && "$CARGO" fetch --locked --offline >/dev/null 2>&1); then
    echo "server-rust: $label dependencies not cached; fetching the locked versions"
    (cd "$dir" && "$CARGO" fetch --locked) || {
      echo "✗ server-rust: $label cargo fetch --locked failed" >&2
      return 1
    }
  fi
  log="$(mktemp)"
  if [[ "$label" == workspace-doc ]]; then
    nextest=0
    if ! (cd "$dir" && "$CARGO" test --doc --locked --offline --workspace --no-fail-fast 2>&1) | tee "$log"; then
      rm -f "$log"
      echo "✗ server-rust: $label cargo test --doc failed" >&2
      return 1
    fi
  elif [[ "${SERVER_RUST_NEXTEST:-}" == 1 && ( "$label" == workspace || "${SERVER_RUST_NEXTEST_FIXTURE:-}" == 1 ) ]]; then
    nextest=1
    if ! nextest_tests "$dir" "$label" 2>&1 | tee "$log"; then
      rm -f "$log"
      echo "✗ server-rust: $label cargo nextest failed" >&2
      return 1
    fi
  else
    nextest=0
    if ! (cd "$dir" && "$CARGO" test --locked --offline --workspace --no-fail-fast 2>&1) | tee "$log"; then
      rm -f "$log"
      echo "✗ server-rust: $label cargo test failed" >&2
      return 1
    fi
  fi
  # libtest result lines start at column 0; nextest indents the per-test copies, so in
  # nextest mode these awk sums cover only the `cargo test --doc` part.
  passed="$(awk '/^test result: ok\./ { n += $4 } END { print n + 0 }' "$log")"
  ignored="$(awk '/^test result: / { n += $8 } END { print n + 0 }' "$log")"
  if [[ "$nextest" == 1 ]]; then
    # "Summary [ 12.3s] 12983 tests run: 12983 passed (3 slow), 0 skipped": a test nextest
    # did not run (ignored, filtered) counts as skipped. No summary line is red.
    local summary np nk
    summary="$(grep -E '^ *Summary \[' "$log" | tail -1 || true)"
    if [[ -z "$summary" ]]; then
      rm -f "$log"
      echo "✗ server-rust: $label nextest printed no summary line" >&2
      return 1
    fi
    np="$(sed -nE 's/.* ([0-9]+) passed.*/\1/p' <<<"$summary")"
    nk="$(sed -nE 's/.* ([0-9]+) skipped.*/\1/p' <<<"$summary")"
    # a partition shard counts the other shards' tests as skipped; the build job rejects ignored tests
    [[ -n "${SERVER_RUST_NEXTEST_PARTITION:-}" ]] && nk=0
    passed=$((passed + ${np:-0}))
    ignored=$((ignored + ${nk:-0}))
  fi
  skipped="$(grep -cE '^ *CONFORMANCE-SKIP ' "$log" || true)"
  # Every DB skip marker (`<NAME>-SKIP (reason=…`: CONFORMANCE-SKIP,
  # SETJOIN-PG-DB-SKIP, any later one), counted per marker.
  # Unanchored: libtest can print a "test name ... " prefix on the same line.
  db_skips="$(grep -oE '[A-Z][A-Z0-9-]*-SKIP \(reason=' "$log" | sed 's/ (reason=$//' | sort | uniq -c || true)"
  rm -f "$log"
  if [[ "$passed" -eq 0 ]]; then
    echo "✗ server-rust: $label ran zero tests" >&2
    return 1
  fi
  if [[ "$ignored" -gt 0 ]]; then
    echo "✗ server-rust: $label ignored $ignored test(s)" >&2
    return 1
  fi
  echo "✓ server-rust: $label $passed tests passed"
  if [[ "$skipped" -gt 0 ]]; then
    echo "CONFORMANCE-SKIP (reason=no-db count=$skipped root=$label) — DB-backed oracle cases counted above did NOT run"
  fi
  if [[ -n "$db_skips" ]]; then
    local total=0 count marker
    while read -r count marker; do
      echo "DB-SKIP (marker=$marker count=$count root=$label) — counted as ok above, did NOT run"
      total=$((total + count))
    done <<<"$db_skips"
    if [[ "${REQUIRE_DB:-}" == 1 ]]; then
      echo "✗ server-rust: $label skipped $total DB-backed test(s) under REQUIRE_DB=1" >&2
      return 1
    fi
  fi
}

# cargo deny with a live advisory fetch: retry (3 tries, 30 s apart) only when the output shows a
# fetch/network failure; a real advisory, ban, licence or source finding fails at once.
cargo_deny_retry() {
  local dir="$1" attempt out rc
  for attempt in 1 2 3; do
    out="$(mktemp)"
    if (cd "$dir" && "$CARGO" deny --locked check) >"$out" 2>&1; then rc=0; else rc=$?; fi
    cat "$out"
    if [[ "$rc" -eq 0 ]]; then rm -f "$out"; return 0; fi
    if [[ "$attempt" -lt 3 ]] && grep -qiE 'EAI_AGAIN|failed to (fetch|resolve)|could not resolve|Temporary failure in name resolution|(connection|operation) (reset|refused|timed out)|unable to (fetch|update)|network (error|failure)|failed to fetch advisory' "$out"; then
      echo "cargo deny: fetch/network error (attempt $attempt/3), retrying in 30 s" >&2
      rm -f "$out"
      sleep 30
      continue
    fi
    rm -f "$out"
    return "$rc"
  done
}

check_tree() {
  local base="$ROOT/server-rust" rc=0
  # Static coverage-manifest checks first: seconds, and a stale handler source or selector fails
  # here instead of hours into the lane.
  if ! python3 "$ROOT/scripts/check-gofree-oracle-adequacy.py" --preflight-only; then
    echo "✗ server-rust: oracle coverage manifest preflight failed (nothing was built)" >&2
    return 1
  fi
  # Go-deletion rehearsal (#141): no Go upstream or Go recording variable reaches the lane.
  if ! python3 "$ROOT/scripts/check-gofree-rehearsal.py" env; then
    echo "✗ server-rust: a Go upstream or recording variable is set (rehearsal env guard)" >&2
    return 1
  fi
  # LANE_ADEQUACY_ONLY (workflow_dispatch input): re-run only those adequacy stages, optionally
  # only LANE_ADEQUACY_ENTRIES, and skip the workspace test run. Never a lane result.
  local subset="${LANE_ADEQUACY_ONLY:-}"
  if ! command -v "$CARGO" >/dev/null 2>&1; then
    echo "SERVER-RUST-SKIP (reason=cargo-not-found cargo=$CARGO) — Rust server tests NOT run"
    return 0
  fi
  # SERVER_RUST_STAGES (hosted CI spreads the lane over jobs): static (guards, cargo-deny, guard
  # tests), workspace (nextest), roots (pilot, schema-simulation, bench-mark-read, plus the doc
  # tests when the workspace stage runs elsewhere), adequacy. Default: every stage.
  local stages=",${SERVER_RUST_STAGES:-static,workspace,roots,adequacy},"
  if [[ -z "$subset" ]]; then
    if [[ "$stages" == *,static,* ]]; then
      # The fast static checks abort the lane at once: a red one must not cost the hours of
      # tests after it.
      python3 "$ROOT/scripts/check-rust-family-isolation.py" "$base" || return 1
      python3 "$base/tests/family-isolation/test_guard.py" || return 1
      python3 "$ROOT/scripts/check-rust-license-exceptions.py" "$base" || return 1
      # Every cargo-deny check: licences, sources, bans and RustSec advisories (#388).
      cargo_deny_retry "$base" || return 1
      python3 "$base/tests/license-policy/test_policy.py" || return 1
      python3 "$ROOT/scripts/test-check-gofree-rehearsal.py" || return 1
      python3 "$ROOT/scripts/check-gofree-rehearsal.py" static || return 1
    fi
    if [[ "$stages" == *,workspace,* ]]; then
      run_root "$base" "workspace" auto || rc=1
    fi
    if [[ "$stages" == *,roots,* ]]; then
      if [[ "$stages" != *,workspace,* ]]; then
        run_root "$base" "workspace-doc" auto || rc=1
      fi
      run_root "$base/pilot" "pilot" auto || rc=1
      run_root "$base/tools/schema-simulation" "schema-simulation" offline || rc=1
      run_root "$base/tools/bench-mark-read" "bench-mark-read" offline || rc=1
    fi
  else
    echo "ADEQUACY-SUBSET (stages=$subset entries=${LANE_ADEQUACY_ENTRIES:-all}) — workspace tests NOT run; not a lane result"
  fi
  if [[ "$stages" == *,static,* || -n "$subset" ]]; then
    python3 "$base/tests/conformance/tests/adequacy_guard_test.py" || rc=1
    python3 "$base/tests/conformance/tests/coverage_report_test.py" || rc=1
  fi
  if [[ "$stages" != *,adequacy,* && -z "$subset" ]]; then
    return "$rc"
  fi
  if [[ -n "${TEST_DB_DSN:-${DB_DSN:-}}" || "${REQUIRE_DB:-}" == 1 ]]; then
    # The gate runs every replay and mutant in its own process. On the parallel lane each one gets its own
    # cloned database, like the nextest run, instead of the shared base that the doc tests,
    # pilot and schema-simulation have already written to (a leftover audit row broke the
    # chain check of `saml_oracle::unlink_floor_cross_tenant` there). `cargo test` hands the
    # test binary to the runner, and the runner is the same wrapper nextest uses.
    if [[ -n "${LANE_ADMIN_DSN:-}" && -n "${LANE_TEMPLATE_DB:-}" && -n "${LANE_BASE_DB:-}" ]]; then
      local host_triple runner_var
      host_triple="$("$CARGO" -vV 2>/dev/null | sed -n 's/^host: //p')"
      [[ -n "$host_triple" ]] || host_triple="$(rustc -vV | sed -n 's/^host: //p')"
      runner_var="CARGO_TARGET_$(tr 'a-z-' 'A-Z_' <<<"$host_triple")_RUNNER"
      export "$runner_var=bash $ROOT/scripts/nextest-db-wrapper.sh"
    fi
    lane_clones sweep "the adequacy gate"
    if [[ -n "${LANE_ADMIN_DSN:-}" && -n "${LANE_TEMPLATE_DB:-}" && -n "${LANE_BASE_DB:-}" ]]; then leak_guard on || rc=1; fi
    lane_disk_sampler start
    lane_go_watch start || rc=1
    # On the lane every run costs hours: run all replays and mutants (LANE_ADEQUACY_JOBS, default
    # LANE_JOBS, at a time on per-replay clones) and then coverage, and report every failure at the
    # end (still red). LANE_ADEQUACY_KEEP_GOING=0 restores stop-at-first-failure. LANE_COVERAGE=0
    # (the hosted test shards) skips coverage; the coverage shards run it alone
    # (LANE_ADEQUACY_COVERAGE_ONLY=1).
    local keep_going=() coverage=(--coverage)
    local shard_args=()
    [[ -n "${LANE_ADEQUACY_SHARD:-}" ]] && shard_args+=(--shard "$LANE_ADEQUACY_SHARD")
    [[ -n "${LANE_ADEQUACY_BINARIES:-}" ]] && shard_args+=(--binaries "$LANE_ADEQUACY_BINARIES")
    # the item-level receipt merge-lane-shards.py checks against the manifest
    [[ -n "${LANE_ARTIFACT_DIR:-}" ]] && shard_args+=(--receipt "$LANE_ARTIFACT_DIR/adequacy-receipt.json")
    [[ -n "${LANE_ADMIN_DSN:-}" && "${LANE_ADEQUACY_KEEP_GOING:-1}" != 0 ]] && keep_going=(--keep-going)
    if [[ "${LANE_COVERAGE:-1}" == 0 ]]; then
      coverage=()
      [[ -z "$subset" ]] && echo "ADEQUACY-COVERAGE-NOT-RUN (LANE_COVERAGE=0) — replays and mutants run; coverage runs in the coverage shards"
    fi
    local stage_args=(--execute ${coverage[@]+"${coverage[@]}"})
    [[ "${LANE_ADEQUACY_COVERAGE_ONLY:-}" == 1 ]] && stage_args=(--coverage)
    if [[ -n "$subset" ]]; then
      python3 "$ROOT/scripts/check-gofree-oracle-adequacy.py" --only "$subset" ${LANE_ADEQUACY_ENTRIES:+--entries "$LANE_ADEQUACY_ENTRIES"} --cargo "$CARGO" ${keep_going[@]+"${keep_going[@]}"} || rc=1
    else
      python3 "$ROOT/scripts/check-gofree-oracle-adequacy.py" "${stage_args[@]}" ${shard_args[@]+"${shard_args[@]}"} --cargo "$CARGO" ${keep_going[@]+"${keep_going[@]}"} || rc=1
    fi
    lane_disk_sampler stop
    lane_go_watch stop || rc=1
    leak_guard off || rc=1
    lane_clones report "after the adequacy gate"
  else
    python3 "$ROOT/scripts/check-gofree-oracle-adequacy.py" || rc=1
    echo "ORACLE-ADEQUACY-SKIP (reason=no-db) — replay, mutant and coverage evidence NOT run"
  fi
  return "$rc"
}

# make_crate DIR BODY: a dependency-free throwaway crate whose lib.rs is BODY.
make_crate() {
  mkdir -p "$1/src"
  printf '[package]\nname = "guard-fixture"\nversion = "0.0.0"\nedition = "2021"\n\n[workspace]\n' >"$1/Cargo.toml"
  printf '%s\n' "$2" >"$1/src/lib.rs"
  (cd "$1" && "$CARGO" generate-lockfile --offline >/dev/null 2>&1)
}

self_test() {
  local tmp out ok=1
  if ! command -v "$CARGO" >/dev/null 2>&1; then
    echo "SERVER-RUST-SKIP (reason=cargo-not-found cargo=$CARGO) — self-test NOT run"
    return 0
  fi
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  export CARGO_TARGET_DIR="$tmp/target"

  make_crate "$tmp/red" '#[test] fn broken() { assert_eq!(1 + 1, 3); }'
  if run_root "$tmp/red" "fixture-failing-test" >/dev/null 2>&1; then
    echo "✗ self-test: a failing Rust test did not turn the guard red" >&2
    ok=0
  fi

  make_crate "$tmp/green" '#[test] fn fixed() { assert_eq!(1 + 1, 2); }'
  if ! run_root "$tmp/green" "fixture-passing-test" >/dev/null 2>&1; then
    echo "✗ self-test: a passing Rust test turned the guard red" >&2
    ok=0
  fi

  make_crate "$tmp/ignored" '#[test] fn passing() {} #[test] #[ignore] fn ignored() {}'
  if REQUIRE_DB=1 run_root "$tmp/ignored" "fixture-ignored-test" >/dev/null 2>&1; then
    echo "✗ self-test: an ignored Rust test passed under REQUIRE_DB=1" >&2
    ok=0
  fi

  make_crate "$tmp/empty" 'pub fn untested() {}'
  if run_root "$tmp/empty" "fixture-no-tests" >/dev/null 2>&1; then
    echo "✗ self-test: a root with zero tests passed" >&2
    ok=0
  fi

  # A DB skip marker written past libtest's capture (as every DB-backed
  # test does): counted in the summary, and red under REQUIRE_DB=1.
  make_crate "$tmp/skip" '#[test] fn db_case() { use std::io::Write; let _ = std::io::stderr().lock().write_all(b"SETJOIN-PG-DB-SKIP (reason=no-dsn) test=db_case\n"); }'
  out="$(REQUIRE_DB='' run_root "$tmp/skip" "fixture-db-skip" 2>&1)" || {
    echo "✗ self-test: a DB skip without REQUIRE_DB turned the guard red" >&2
    ok=0
  }
  if ! grep -q '^DB-SKIP (marker=SETJOIN-PG-DB-SKIP count=1 root=fixture-db-skip)' <<<"$out"; then
    echo "✗ self-test: a SETJOIN-PG-DB-SKIP line was not counted in the summary" >&2
    ok=0
  fi
  if REQUIRE_DB=1 run_root "$tmp/skip" "fixture-db-skip-required" >/dev/null 2>&1; then
    echo "✗ self-test: a DB skip under REQUIRE_DB=1 passed" >&2
    ok=0
  fi

  # The same guards through the nextest path (parallel lane, #550).
  # Identical fixture package names collide in one target dir (cargo hashes the package, not
  # its path), so each nextest fixture gets its own.
  nx_root() { CARGO_TARGET_DIR="$tmp/target-$2" run_root "$@"; }
  if "$CARGO" nextest --version >/dev/null 2>&1; then
    export SERVER_RUST_NEXTEST=1 SERVER_RUST_NEXTEST_FIXTURE=1
    if nx_root "$tmp/red" "fixture-nextest-failing" >/dev/null 2>&1; then
      echo "✗ self-test: a failing test did not turn the nextest path red" >&2
      ok=0
    fi
    if ! nx_root "$tmp/green" "fixture-nextest-passing" >/dev/null 2>&1; then
      echo "✗ self-test: a passing test turned the nextest path red" >&2
      ok=0
    fi
    if REQUIRE_DB=1 nx_root "$tmp/ignored" "fixture-nextest-ignored" >/dev/null 2>&1; then
      echo "✗ self-test: an ignored test passed the nextest path" >&2
      ok=0
    fi
    if nx_root "$tmp/empty" "fixture-nextest-no-tests" >/dev/null 2>&1; then
      echo "✗ self-test: zero tests passed the nextest path" >&2
      ok=0
    fi
    out="$(REQUIRE_DB='' nx_root "$tmp/skip" "fixture-nextest-db-skip" 2>&1)" || {
      echo "✗ self-test: a DB skip without REQUIRE_DB turned the nextest path red" >&2
      ok=0
    }
    if ! grep -q '^DB-SKIP (marker=SETJOIN-PG-DB-SKIP count=1 root=fixture-nextest-db-skip)' <<<"$out"; then
      echo "✗ self-test: the nextest path did not count a SETJOIN-PG-DB-SKIP line" >&2
      ok=0
    fi
    if REQUIRE_DB=1 nx_root "$tmp/skip" "fixture-nextest-db-skip-required" >/dev/null 2>&1; then
      echo "✗ self-test: a DB skip under REQUIRE_DB=1 passed the nextest path" >&2
      ok=0
    fi
    unset SERVER_RUST_NEXTEST SERVER_RUST_NEXTEST_FIXTURE
  else
    echo "SERVER-RUST-SKIP (reason=nextest-not-found) — nextest guard self-test NOT run"
  fi

  if run_root "$tmp/absent" "fixture-missing-root" >/dev/null 2>&1; then
    echo "✗ self-test: a missing Cargo root passed" >&2
    ok=0
  fi

  out="$(SERVER_RUST_CARGO="$tmp/no-such-cargo" bash "${BASH_SOURCE[0]}" 2>&1)" || {
    echo "✗ self-test: missing cargo exited non-zero" >&2
    ok=0
  }
  if ! grep -q '^SERVER-RUST-SKIP (reason=cargo-not-found' <<<"$out"; then
    echo "✗ self-test: missing cargo did not print the SERVER-RUST-SKIP line" >&2
    ok=0
  fi

  [[ "$ok" == 1 ]] || return 1
  echo "✓ check-server-rust self-test: failing or ignored test → red, passing → green, zero tests → red, DB skip → counted (red under REQUIRE_DB=1), missing root → red, no cargo → SKIP"
}

case "${1:-}" in
  --self-test) self_test ;;
  "") check_tree ;;
  *)
    echo "usage: check-server-rust.sh [--self-test]" >&2
    exit 2
    ;;
esac

# Workspace includes calendar-format, shared Go ICS bytes (#526); floor remains 1.97.1.
