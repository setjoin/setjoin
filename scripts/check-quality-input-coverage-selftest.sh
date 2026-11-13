#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-quality-input-coverage-selftest.sh — proves the python-lane input
# coverage guard (scripts/check-quality-input-coverage.sh) FIRES and PASSES
# against synthetic trees, never the live repo (fixture-root pattern,
# mirroring the catalog guard's QUALITY_CATALOG/QUALITY_CATALOG_SCHEMA_ONLY
# overrides via the guard's and quality.sh's QUALITY_ROOT).
#
# SAFETY: every git operation in this self-test targets a throwaway fixture
# repo under $TMP. The fixture_git helper REFUSES to run git anywhere else,
# and set -e aborts the run if any fixture setup fails — a half-built fixture
# must never fall through to an operation against the live repo.
#
# Declared-universe cases (manifest test plan):
#   · a planted uncovered tracked file FAILS, named by exact path;
#   · a declared exclusion shadowing an eligible file PASSES;
#   · an extension-classified language with no include universe FAILS;
#   · a rotted evidence exclusion (matches nothing after a file moves) is
#     reported — while exclude_generated sets are exempt (empty is healthy);
#   · a lane with no exclude_generated set FAILS [NO-GENERATED];
#   · root-level zero-directory matching: without a *.py include a tracked
#     root-level file is UNCOVERED (named); with it the file is lane-eligible.
# AR06-1 tracked-admission cases:
#   · a tracked guard executing an UNTRACKED dot-py file FAILS naming guard
#     and path, and the file stays out of the eligible list;
#   · a tracked guard executing a dot-py file the exclude sets removed from
#     the lane FAILS;
#   · a tracked guard executing a covered tracked dot-py file PASSES;
#   · a tracked guard whose stable "$SCRIPT_DIR/" reference names a file that
#     does not exist FAILS [MISSING] — stable references resolve independent
#     of existence and never disappear;
#   · an UNTRACKED guard is outside the reference scan (tracked guards only),
#     so a scratch guard cannot flip the verdict.
# AR06 r3 delta cases:
#   · BRACED stable references ("${SCRIPT_DIR}/x.py", "${ROOT}/x.py") resolve
#     exactly like their unbraced spellings: a missing target FAILS [MISSING]
#     (the scan used to collapse a braced prefix to a bare "/x.py" that
#     silently vanished), and an existing target stays lane-covered with no
#     false [MISSING];
#   · NESTED generated trees (mailserver/webmail/node_modules/probe.py) are
#     excluded like their root-level equivalents — root (dir/**) and nested
#     (**/dir/**) patterns are both declared, and with the set undeclared
#     BOTH depths enter the lane by silence;
#   · a failing `git ls-files` fails the projection and EACH python consumer
#     independently with git's own status — the producer captures git's exit
#     status instead of degrading into a successful "no eligible files" skip.
# Enforced revert regression (AR06-2 honesty check): the python consumers in
# scripts/quality.sh are executed for real (interpreter stubs record their
# actual argv) and each consumer invocation's actual input set — python3
# syntax, `ruff check`, `ruff format --check` SEPARATELY — is diffed against
# the declared inventory. A third planted file must reach ALL THREE
# invocations, removing a file must shrink all three, and each SINGLE
# reversion (pinning exactly one invocation to the old hardcoded path pair
# while the rest stay declared) must be caught: the previous tool-level
# union comparator was blind to a ruff-check-only or ruff-format-only
# reversion. A failing inventory producer must fail the lane loudly, never
# degrade into a successful "no eligible files" skip.
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-quality-input-coverage.sh"

# Isolate fixture git repos from any user/system git configuration.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null

TMP="$(mktemp -d "${TMPDIR:-/tmp}/setjoin-quality-input-coverage-selftest.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail=0
pass() { echo "    ok   $1"; }
bad() {
  echo "    FAIL $1"
  fail=1
}

GEN_EXCL='"node_modules/**","refs/**","build/**","dist/**","test-results/**","**/node_modules/**","**/refs/**","**/build/**","**/dist/**","**/test-results/**"'
CAT_FULL="{\"schemaVersion\":1,\"languages\":[{\"id\":\"python\",\"extensions\":[\"py\"],\"include\":[\"**/*.py\",\"*.py\"],\"exclude\":[\".zcode-security-deep/**\"],\"exclude_generated\":[$GEN_EXCL]}],\"tools\":[]}"
CAT_NOROOT="{\"schemaVersion\":1,\"languages\":[{\"id\":\"python\",\"extensions\":[\"py\"],\"include\":[\"**/*.py\"],\"exclude\":[\".zcode-security-deep/**\"],\"exclude_generated\":[$GEN_EXCL]}],\"tools\":[]}"
CAT_NOGEN="{\"schemaVersion\":1,\"languages\":[{\"id\":\"python\",\"extensions\":[\"py\"],\"include\":[\"**/*.py\",\"*.py\"],\"exclude\":[\".zcode-security-deep/**\"]}],\"tools\":[]}"
CAT_NARROW="{\"schemaVersion\":1,\"languages\":[{\"id\":\"python\",\"extensions\":[\"py\"],\"include\":[\"gen/*.py\"],\"exclude_generated\":[$GEN_EXCL]}],\"tools\":[]}"
CAT_NOINCLUDE='{"schemaVersion":1,"languages":[{"id":"python","extensions":["py"]}],"tools":[]}'
CAT_EXCLREF="{\"schemaVersion\":1,\"languages\":[{\"id\":\"python\",\"extensions\":[\"py\"],\"include\":[\"**/*.py\",\"*.py\"],\"exclude\":[\"evidence/**\"],\"exclude_generated\":[$GEN_EXCL]}],\"tools\":[]}"

assert_fixture() { # $1 = candidate fixture dir
  if [[ -z "$1" || "$1" != "$TMP"/* ]]; then
    echo "selftest internal error: refusing non-fixture target '$1'" >&2
    exit 1
  fi
}

fixture_git() { # $1 = fixture dir, rest = git args
  local fx="$1"
  assert_fixture "$fx"
  shift
  git -C "$fx" "$@"
}

commit_all() { # $1 = fixture dir
  fixture_git "$1" add -A
  fixture_git "$1" -c user.name=selftest -c user.email=selftest@invalid -c commit.gpgsign=false commit -q -m fixture
}

commit_only() { # $1 = fixture dir, rest = paths to commit (everything else stays untracked)
  local fx="$1"
  assert_fixture "$fx"
  shift
  fixture_git "$fx" add "$@"
  fixture_git "$fx" -c user.name=selftest -c user.email=selftest@invalid -c commit.gpgsign=false commit -q -m fixture
}

new_fixture() { # $1 = catalog JSON, $2 = unique fixture name → prints fixture dir
  local fx="$TMP/$2"
  mkdir -p "$fx/config" "$fx/scripts"
  printf '%s' "$1" >"$fx/config/quality-tools.json"
  cp "$GUARD" "$fx/scripts/"
  fixture_git "$fx" init -q
  commit_all "$fx"
  assert_fixture "$fx"
  printf '%s' "$fx"
}

run_guard() { # $1 = fixture; captures combined output in $TMP/out
  assert_fixture "$1"
  QUALITY_ROOT="$1" bash "$GUARD" >"$TMP/out" 2>&1
}

eligible_list() { # $1 = fixture → sorted absolute eligible paths
  assert_fixture "$1"
  QUALITY_ROOT="$1" bash "$GUARD" --eligible-files python 2>/dev/null | LC_ALL=C sort
}

expect_guard_fail() { # $1 = fixture, $2 = case label, rest = required regex substrings
  local fx="$1" label="$2"
  shift 2
  if run_guard "$fx"; then
    bad "$label — guard did NOT fire"
    return
  fi
  local want
  for want in "$@"; do
    if grep -qE -- "$want" "$TMP/out"; then
      pass "$label — named: $want"
    else
      bad "$label — fired but did not name: $want"
      sed 's/^/        /' "$TMP/out"
    fi
  done
}

echo "==> quality-input-coverage guard self-test"

# ── (b) declared exclusion shadows an eligible file → PASS. ─────────────────
# root.py also proves zero-directory matching: the include set declares *.py
# alongside **/*.py because a case pattern containing a slash requires at
# least one directory component.
FX_A="$(new_fixture "$CAT_FULL" fx_a)"
mkdir -p "$FX_A/gen" "$FX_A/tools" "$FX_A/.zcode-security-deep/h"
printf 'x=1\n' >"$FX_A/gen/a.py"
printf 'y=2\n' >"$FX_A/tools/b.py"
printf 'r=1\n' >"$FX_A/root.py"
printf 'EVIDENCE\n' >"$FX_A/.zcode-security-deep/h/ev.py"
commit_all "$FX_A"
if run_guard "$FX_A"; then
  pass "exclusion shadowing evidence — clean tree passes"
else
  bad "exclusion shadowing evidence should pass"
  sed 's/^/        /' "$TMP/out"
fi
expected="$(printf '%s\n%s\n%s\n' "$FX_A/gen/a.py" "$FX_A/root.py" "$FX_A/tools/b.py" | LC_ALL=C sort)"
if [[ "$(eligible_list "$FX_A")" == "$expected" ]]; then
  pass "eligible list is the three lane files (evidence excluded, root-level included)"
else
  bad "eligible list wrong for shadowed exclusion"
  eligible_list "$FX_A" | sed 's/^/        /'
fi
if [[ "$(eligible_list "$FX_A" | grep -cF "$FX_A/root.py" || true)" -eq 1 ]]; then
  pass "root-level dot-py file (zero directories) is lane-eligible"
else
  bad "root-level dot-py file must be lane-eligible (zero-directory matching)"
fi

# ── (d) the evidence exclusion rots when its last file moves → reported. ────
fixture_git "$FX_A" rm -q -r .zcode-security-deep
commit_all "$FX_A"
expect_guard_fail "$FX_A" "rotted evidence exclusion after the file moves" "\[ROTTED\]" ".zcode-security-deep/\*\*"

# ── Zero-directory gap: without *.py the root-level file is UNCOVERED. ──────
FX_ROOT="$(new_fixture "$CAT_NOROOT" fx_root)"
mkdir -p "$FX_ROOT/gen"
printf 'x=1\n' >"$FX_ROOT/gen/a.py"
printf 'r=1\n' >"$FX_ROOT/root.py"
commit_all "$FX_ROOT"
expect_guard_fail "$FX_ROOT" "zero-directory gap (no *.py declared)" "\[UNCOVERED\]" "root.py"

# ── Generated/vendor exclusions declared → PASS and stay out of the lane. ───
# Both depths: the root-level trees AND the same generated directory names
# nested deeper (mailserver/webmail/<dir>/probe.py) must stay excluded — the
# declaration covers dir/** at the root and **/dir/** at any depth.
FX_GEN="$(new_fixture "$CAT_FULL" fx_gen)"
mkdir -p "$FX_GEN/gen" "$FX_GEN/build" "$FX_GEN/node_modules/pkg" "$FX_GEN/.zcode-security-deep/h"
printf 'x=1\n' >"$FX_GEN/gen/a.py"
printf 'generated\n' >"$FX_GEN/build/gen.py"
printf 'vendored\n' >"$FX_GEN/node_modules/pkg/vendor.py"
printf 'EVIDENCE\n' >"$FX_GEN/.zcode-security-deep/h/ev.py"
for gdir in node_modules refs build dist test-results; do
  mkdir -p "$FX_GEN/mailserver/webmail/$gdir"
  printf 'generated\n' >"$FX_GEN/mailserver/webmail/$gdir/probe.py"
done
commit_all "$FX_GEN"
if run_guard "$FX_GEN"; then
  pass "tracked generated/vendor files are declared-excluded (guard passes)"
else
  bad "declared generated/vendor exclusions should pass"
  sed 's/^/        /' "$TMP/out"
fi
if [[ "$(eligible_list "$FX_GEN")" == "$FX_GEN/gen/a.py" ]]; then
  pass "eligible list keeps generated/vendor trees out of the lane (root and nested)"
else
  bad "generated/vendor files leaked into the eligible list (root or nested depth)"
  eligible_list "$FX_GEN" | sed 's/^/        /'
fi
if [[ "$(eligible_list "$FX_GEN" | grep -cF "$FX_GEN/mailserver/webmail/node_modules/probe.py" || true)" -eq 0 ]]; then
  pass "nested generated tree (mailserver/webmail/node_modules) stays out of the lane"
else
  bad "nested generated tree must be excluded like its root-level equivalent"
fi

# ── Generated/vendor exclusions undeclared → [NO-GENERATED]; they would ─────
# enter the lane (the projection is adjudication-free, so it shows exactly
# what silence would admit).
FX_GEN_UD="$(new_fixture "$CAT_NOGEN" fx_genud)"
mkdir -p "$FX_GEN_UD/gen" "$FX_GEN_UD/build" "$FX_GEN_UD/node_modules/pkg" "$FX_GEN_UD/.zcode-security-deep/h"
printf 'x=1\n' >"$FX_GEN_UD/gen/a.py"
printf 'generated\n' >"$FX_GEN_UD/build/gen.py"
printf 'vendored\n' >"$FX_GEN_UD/node_modules/pkg/vendor.py"
printf 'EVIDENCE\n' >"$FX_GEN_UD/.zcode-security-deep/h/ev.py"
mkdir -p "$FX_GEN_UD/mailserver/webmail/node_modules"
printf 'vendored\n' >"$FX_GEN_UD/mailserver/webmail/node_modules/probe.py"
commit_all "$FX_GEN_UD"
expect_guard_fail "$FX_GEN_UD" "undeclared generated/vendor exclusion set" "\[NO-GENERATED\]" "exclude_generated"
el="$(eligible_list "$FX_GEN_UD")"
if grep -qF "$FX_GEN_UD/build/gen.py" <<<"$el" &&
  grep -qF "$FX_GEN_UD/node_modules/pkg/vendor.py" <<<"$el" &&
  grep -qF "$FX_GEN_UD/mailserver/webmail/node_modules/probe.py" <<<"$el"; then
  pass "without exclude_generated the generated/vendor files enter the lane at BOTH depths (declaration is the operative exclusion)"
else
  bad "expected undeclared generated/vendor files to enter the projected lane at both depths"
fi

# ── (a) planted uncovered tracked file → FAIL, named by exact path. ─────────
FX_B="$(new_fixture "$CAT_NARROW" fx_b)"
mkdir -p "$FX_B/gen" "$FX_B/tools"
printf 'x=1\n' >"$FX_B/gen/a.py"
printf 'y=2\n' >"$FX_B/tools/b.py"
commit_all "$FX_B"
expect_guard_fail "$FX_B" "planted uncovered file" "\[UNCOVERED\]" "tools/b.py"

# ── (c) extension-classified language with no include universe → FAIL. ──────
FX_C="$(new_fixture "$CAT_NOINCLUDE" fx_c)"
mkdir -p "$FX_C/gen"
printf 'x=1\n' >"$FX_C/gen/a.py"
commit_all "$FX_C"
expect_guard_fail "$FX_C" "classified language without include universe" "\[NO-INCLUDE\]"
if ! eligible_list "$FX_C" >/dev/null 2>&1; then
  pass "projection refuses a language with no include universe (lane fails loudly)"
else
  bad "projection should refuse a language with no include universe"
fi

# ── AR06-1: tracked guard executes an UNTRACKED dot-py file → FAIL. ─────────
FX_D="$(new_fixture "$CAT_FULL" fx_d)"
mkdir -p "$FX_D/gen" "$FX_D/.zcode-security-deep/h"
printf 'x=1\n' >"$FX_D/gen/a.py"
printf 'EVIDENCE\n' >"$FX_D/.zcode-security-deep/h/ev.py"
printf 'help\n' >"$FX_D/scripts/helper.py" # on disk, deliberately NOT committed
cat >"$FX_D/scripts/check-helper.sh" <<'GUARD'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/helper.py"
GUARD
commit_only "$FX_D" gen/a.py .zcode-security-deep scripts/check-helper.sh # helper.py stays deliberately UNTRACKED
expect_guard_fail "$FX_D" "tracked admission (untracked executed file)" \
  "\[PREREQ\]" "scripts/check-helper.sh" "scripts/helper.py" "does not track"
expected="$FX_D/gen/a.py"
if [[ "$(eligible_list "$FX_D")" == "$expected" ]]; then
  pass "untracked executed file stays out of the eligible list (tracked admission)"
else
  bad "eligible list must not admit an untracked executed file"
  eligible_list "$FX_D" | sed 's/^/        /'
fi

# ── AR06-1: tracked guard executes a file the exclude set removed → FAIL. ───
FX_E="$(new_fixture "$CAT_EXCLREF" fx_e)"
mkdir -p "$FX_E/gen" "$FX_E/evidence"
printf 'x=1\n' >"$FX_E/gen/a.py"
printf 'EVIDENCE\n' >"$FX_E/evidence/helper.py"
cat >"$FX_E/scripts/check-helper.sh" <<'GUARD'
#!/usr/bin/env bash
set -euo pipefail
exec python3 evidence/helper.py
GUARD
commit_all "$FX_E"
expect_guard_fail "$FX_E" "tracked admission (excluded executed file)" \
  "\[PREREQ\]" "scripts/check-helper.sh" "evidence/helper.py" "exclude set"

# ── AR06-1: tracked guard executes a covered tracked file → PASS. ───────────
FX_F="$(new_fixture "$CAT_FULL" fx_f)"
mkdir -p "$FX_F/gen" "$FX_F/.zcode-security-deep/h"
printf 'x=1\n' >"$FX_F/gen/a.py"
printf 'help\n' >"$FX_F/scripts/helper.py"
printf 'EVIDENCE\n' >"$FX_F/.zcode-security-deep/h/ev.py" # keeps the declared exclusion live
cat >"$FX_F/scripts/check-helper.sh" <<'GUARD'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/helper.py"
GUARD
commit_all "$FX_F"
if run_guard "$FX_F"; then
  pass "guard executing a covered tracked file passes"
else
  bad "guard executing a covered tracked file should pass"
  sed 's/^/        /' "$TMP/out"
fi

# ── AR06-1 r2: a STABLE reference to a missing file FAILS [MISSING]. ────────
# "$SCRIPT_DIR/..."-prefixed references resolve to exactly one repo path
# whether or not the target exists; a missing interpreter must be named,
# never silently dropped (the old resolver required existence, so a missing
# target adjudicated to a vacuous PASS).
FX_H="$(new_fixture "$CAT_FULL" fx_h)"
mkdir -p "$FX_H/gen" "$FX_H/.zcode-security-deep/h"
printf 'x=1\n' >"$FX_H/gen/a.py"
printf 'EVIDENCE\n' >"$FX_H/.zcode-security-deep/h/ev.py"
cat >"$FX_H/scripts/check-helper.sh" <<'GUARD'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/missing-interpreter.py"
GUARD
commit_all "$FX_H" # missing-interpreter.py exists NOWHERE (not even untracked)
expect_guard_fail "$FX_H" "missing stable interpreter reference" \
  "\[MISSING\]" "scripts/check-helper.sh" "scripts/missing-interpreter.py"

# ── AR06-1 r2: an UNTRACKED guard is outside the reference scan. ────────────
# The guard loop enumerates tracked guards (git ls-files), not the
# filesystem glob: a scratch guard referencing an untracked file must not
# make the verdict environment-dependent.
FX_I="$(new_fixture "$CAT_FULL" fx_i)"
mkdir -p "$FX_I/gen" "$FX_I/.zcode-security-deep/h"
printf 'x=1\n' >"$FX_I/gen/a.py"
printf 'EVIDENCE\n' >"$FX_I/.zcode-security-deep/h/ev.py"
printf 'rogue=1\n' >"$FX_I/scripts/rogue.py" # untracked, on disk
cat >"$FX_I/scripts/check-rogue.sh" <<'GUARD'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/rogue.py"
GUARD
commit_only "$FX_I" gen/a.py .zcode-security-deep # check-rogue.sh + rogue.py stay UNTRACKED
if run_guard "$FX_I"; then
  pass "untracked guard is outside the tracked-guard reference scan"
else
  bad "guard must not scan untracked guards (verdict must not depend on scratch files)"
  sed 's/^/        /' "$TMP/out"
fi

# ── AR06 r2: BRACED stable references resolve like unbraced ones. ───────────
# "${SCRIPT_DIR}/x.py" and "${ROOT}/x.py" must reach the resolver with their
# variable prefix intact: the path-token scan used to collapse a braced
# prefix to a bare "/x.py" with no stable location, so a MISSING braced
# reference adjudicated to a vacuous PASS.
FX_BRACE_BAD="$(new_fixture "$CAT_FULL" fx_brace_bad)"
mkdir -p "$FX_BRACE_BAD/gen" "$FX_BRACE_BAD/.zcode-security-deep/h"
printf 'x=1\n' >"$FX_BRACE_BAD/gen/a.py"
printf 'EVIDENCE\n' >"$FX_BRACE_BAD/.zcode-security-deep/h/ev.py"
cat >"$FX_BRACE_BAD/scripts/check-helper.sh" <<'GUARD'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
exec python3 "${SCRIPT_DIR}/missing-braced.py" "${ROOT}/scripts/missing-root-braced.py"
GUARD
commit_all "$FX_BRACE_BAD" # both braced targets exist NOWHERE (not even untracked)
expect_guard_fail "$FX_BRACE_BAD" "missing braced stable references" \
  "\[MISSING\]" "scripts/check-helper.sh" "scripts/missing-braced.py" "scripts/missing-root-braced.py"

# Same spellings against an EXISTING tracked file: normalization must land on
# the covered lane file — no false [MISSING], no unadjudicated residue.
FX_BRACE_OK="$(new_fixture "$CAT_FULL" fx_brace_ok)"
mkdir -p "$FX_BRACE_OK/gen" "$FX_BRACE_OK/.zcode-security-deep/h"
printf 'x=1\n' >"$FX_BRACE_OK/gen/a.py"
printf 'help\n' >"$FX_BRACE_OK/scripts/helper.py"
printf 'EVIDENCE\n' >"$FX_BRACE_OK/.zcode-security-deep/h/ev.py"
cat >"$FX_BRACE_OK/scripts/check-helper.sh" <<'GUARD'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
exec python3 "${SCRIPT_DIR}/helper.py" "${ROOT}/scripts/helper.py"
GUARD
commit_all "$FX_BRACE_OK"
if run_guard "$FX_BRACE_OK"; then
  pass "existing braced stable references stay lane-covered (no false MISSING)"
else
  bad "braced references to an existing tracked file must resolve cleanly"
  sed 's/^/        /' "$TMP/out"
fi

# ── Enforced revert regression: consumers' actual inputs vs the inventory. ──
FX_G="$(new_fixture "$CAT_FULL" fx_g)"
mkdir -p "$FX_G/gen" "$FX_G/tools" "$FX_G/extra" "$FX_G/.zcode-security-deep/h"
printf 'x=1\n' >"$FX_G/gen/a.py"
printf 'y=2\n' >"$FX_G/tools/b.py"
printf 'z=3\n' >"$FX_G/extra/c.py"
printf 'EVIDENCE\n' >"$FX_G/.zcode-security-deep/h/ev.py"
commit_all "$FX_G"
printf 'stray\n' >"$FX_G/stray.py" # untracked, never lane-eligible

mkdir -p "$TMP/bin"
for tool in python3 ruff; do
  cat >"$TMP/bin/$tool" <<STUB
#!/bin/sh
printf '$tool %s\n' "\$*" >>"\$STUB_LOG"
exit 0
STUB
  chmod +x "$TMP/bin/$tool"
done

# Driver sources the real quality.sh (-h keeps the dispatch inert) with
# QUALITY_ROOT at the fixture, then runs BOTH python consumers for real.
make_driver() {
  cat >"$TMP/driver.sh" <<DRIVER
set -euo pipefail
: "\${STUB_LOG:?STUB_LOG is required}"
export STUB_LOG
PATH="$TMP/bin:\$PATH"
export PATH
source "$ROOT/scripts/quality.sh" -h
run_python_syntax
run_python_quality
DRIVER
}

# Mutated driver: sources the real quality.sh, then redefines ONE consumer
# invocation to the old hardcoded path pair while every other invocation
# keeps the declared inventory — an in-memory single reversion.
make_mutated_driver() { # $1 = syntax|check|format
  local mutation="$1"
  cat >"$TMP/mutated-driver.sh" <<DRIVER
set -euo pipefail
: "\${STUB_LOG:?STUB_LOG is required}"
export STUB_LOG
PATH="$TMP/bin:\$PATH"
export PATH
source "$ROOT/scripts/quality.sh" -h
INV=()
while IFS= read -r f; do INV+=("\$f"); done < <(python_lane_files)
DRIVER
  case "$mutation" in
    syntax)
      cat >>"$TMP/mutated-driver.sh" <<DRIVER
# Single reversion: the python3 syntax invocation pinned to the old pair.
run_python_syntax() {
  python3 "$FX_G/gen/a.py" "$FX_G/tools/b.py"
}
run_python_syntax
run_python_quality
DRIVER
      ;;
    check)
      cat >>"$TMP/mutated-driver.sh" <<DRIVER
# Single reversion: 'ruff check' pinned to the old pair; format stays declared.
run_python_syntax
run_python_quality() {
  need ruff
  ruff check "$FX_G/gen/a.py" "$FX_G/tools/b.py"
  ruff format --check "\${INV[@]}"
}
run_python_quality
DRIVER
      ;;
    format)
      cat >>"$TMP/mutated-driver.sh" <<DRIVER
# Single reversion: 'ruff format' pinned to the old pair; check stays declared.
run_python_syntax
run_python_quality() {
  need ruff
  ruff check "\${INV[@]}"
  ruff format --check "$FX_G/gen/a.py" "$FX_G/tools/b.py"
}
run_python_quality
DRIVER
      ;;
  esac
}

# Per-invocation comparator: the sorted fixture .py args seen by exactly the
# invocation whose log lines match the given prefix regex. Asserting syntax,
# ruff check, and ruff format SEPARATELY is load-bearing: a tool-level union
# (the previous comparator) cannot see a single-invocation reversion whose
# hardcoded pair is a subset of the inventory.
invocation_inputs() { # $1 = log, $2 = invocation prefix regex
  { grep -E "$2" "$1" || true; } |
    { grep -hoE "$FX_G/[A-Za-z0-9_./-]+\.py" || true; } |
    LC_ALL=C sort -u
}

inventory="$(eligible_list "$FX_G")"
if [[ "$(printf '%s\n' "$inventory" | grep -cF "$FX_G/extra/c.py" || true)" -eq 1 ]]; then
  pass "declared inventory contains the planted third file"
else
  bad "declared inventory must contain the planted third file"
fi

# Round 1: three lane files — ALL THREE invocations must receive the inventory.
make_driver
if QUALITY_ROOT="$FX_G" STUB_LOG="$TMP/stub1.log" bash "$TMP/driver.sh" >"$TMP/driver1.out" 2>&1; then
  pass "python consumers ran on the fixture tree"
else
  bad "python consumers failed on the fixture tree"
  sed 's/^/        /' "$TMP/driver1.out"
fi
for inv in '^python3 ' '^ruff check ' '^ruff format '; do
  actual1="$(invocation_inputs "$TMP/stub1.log" "$inv")"
  if [[ "$actual1" == "$inventory" ]]; then
    pass "inputs of '$inv' equal the declared inventory (3 files)"
  else
    bad "inputs of '$inv' diverge from the declared inventory (3-file round)"
    diff <(printf '%s\n' "$inventory") <(printf '%s\n' "$actual1") | sed 's/^/        /'
  fi
  if [[ "$(printf '%s\n' "$actual1" | grep -cF "$FX_G/stray.py" || true)" -eq 0 ]] &&
    [[ "$(printf '%s\n' "$actual1" | grep -cF "$FX_G/.zcode-security-deep/h/ev.py" || true)" -eq 0 ]]; then
    pass "'$inv' never sees untracked stray or excluded evidence"
  else
    bad "untracked stray or excluded evidence leaked into '$inv' inputs"
  fi
done

# Single-reversion exercises: pin exactly ONE invocation to the old hardcoded
# path pair. Each must diverge under its own per-invocation comparator. For
# the ruff reversions the tool-level union equals the inventory — proving the
# OLD comparator was blind and the per-invocation assert is what catches it.
for mutation in syntax check format; do
  make_mutated_driver "$mutation"
  log="$TMP/stub-mut-$mutation.log"
  if ! QUALITY_ROOT="$FX_G" STUB_LOG="$log" bash "$TMP/mutated-driver.sh" >"$TMP/mut-$mutation.out" 2>&1; then
    bad "mutated driver ($mutation reversion) failed to run"
    sed 's/^/        /' "$TMP/mut-$mutation.out"
    continue
  fi
  case "$mutation" in
    syntax) pin='^python3 ' ;;
    check) pin='^ruff check ' ;;
    format) pin='^ruff format ' ;;
  esac
  mutated="$(invocation_inputs "$log" "$pin")"
  if [[ "$mutated" != "$inventory" ]] &&
    [[ "$(printf '%s\n' "$mutated" | grep -cF "$FX_G/extra/c.py" || true)" -eq 0 ]]; then
    pass "single-reversion ($mutation) diverges from the declared inventory — caught"
  else
    bad "comparator failed to catch the single-$mutation reversion"
  fi
  if [[ "$mutation" != "syntax" ]]; then
    union="$(invocation_inputs "$log" '^ruff ')"
    if [[ "$union" == "$inventory" ]]; then
      pass "single-$mutation reversion is invisible to the tool-level union (per-invocation asserts required)"
    else
      bad "expected the union comparator to be blind to the single-$mutation reversion"
    fi
  fi
done

# Round 2: remove a lane file — all three invocations must shrink together.
# The untracked stray.py is deleted first: it was round-1 scratch, and
# commit_all's `git add -A` would otherwise silently track it.
fixture_git "$FX_G" rm -q extra/c.py
rm -f "$FX_G/stray.py"
commit_all "$FX_G"
inventory2="$(eligible_list "$FX_G")"
make_driver
if QUALITY_ROOT="$FX_G" STUB_LOG="$TMP/stub2.log" bash "$TMP/driver.sh" >"$TMP/driver2.out" 2>&1; then
  pass "python consumers ran after the removal"
else
  bad "python consumers failed after the removal"
  sed 's/^/        /' "$TMP/driver2.out"
fi
for inv in '^python3 ' '^ruff check ' '^ruff format '; do
  actual2="$(invocation_inputs "$TMP/stub2.log" "$inv")"
  if [[ "$actual2" == "$inventory2" ]] &&
    [[ "$(printf '%s\n' "$actual2" | grep -cF "extra/c.py" || true)" -eq 0 ]] &&
    [[ "$(printf '%s\n' "$actual2" | grep -cF "$FX_G/" || true)" -eq 2 ]]; then
    pass "inputs of '$inv' shrank exactly with the declared inventory (2 files)"
  else
    bad "inputs of '$inv' must shrink exactly with the declared inventory (2-file round)"
    diff <(printf '%s\n' "$inventory2") <(printf '%s\n' "$actual2") | sed 's/^/        /'
  fi
done

# Inventory-failure propagation: with a fixture whose projection REFUSES (no
# include universe), the consumers must fail the lane loudly — never degrade
# into a successful "no eligible files" skip.
FX_K="$(new_fixture "$CAT_NOINCLUDE" fx_k)"
mkdir -p "$FX_K/gen"
printf 'x=1\n' >"$FX_K/gen/a.py"
commit_all "$FX_K"
make_driver
if QUALITY_ROOT="$FX_K" STUB_LOG="$TMP/stub-fail.log" bash "$TMP/driver.sh" >"$TMP/driverfail.out" 2>&1; then
  bad "python consumers silently skipped a failing inventory (exit 0)"
  sed 's/^/        /' "$TMP/driverfail.out"
else
  pass "failing inventory fails the python lane loudly (no successful skip)"
fi
if grep -q "inventory failed" "$TMP/driverfail.out"; then
  pass "lane failure names the failed inventory producer"
else
  bad "expected the lane failure to name the failed inventory producer"
  sed 's/^/        /' "$TMP/driverfail.out"
fi

# ── AR06 r2: a failing `git ls-files` fails the projection and EACH ─────────
# consumer independently with git's own status. The producer captures git's
# exit status; the old `done < <(git ls-files)` shape swallowed it, so a
# failing enumeration degraded into a successful "no eligible files" skip in
# every consumer.
FX_L="$(new_fixture "$CAT_FULL" fx_l)"
mkdir -p "$FX_L/gen" "$FX_L/.zcode-security-deep/h"
printf 'x=1\n' >"$FX_L/gen/a.py"
printf 'EVIDENCE\n' >"$FX_L/.zcode-security-deep/h/ev.py"
commit_all "$FX_L"
mkdir -p "$TMP/bin-failgit"
printf '#!/bin/sh\necho "injected git ls-files failure" >&2\nexit 42\n' >"$TMP/bin-failgit/git"
chmod +x "$TMP/bin-failgit/git"

# Consumer 0 — the projection itself (what quality.sh's python_lane_files calls).
projection_status=0
QUALITY_ROOT="$FX_L" PATH="$TMP/bin-failgit:$PATH" \
  bash "$GUARD" --eligible-files python >"$TMP/out" 2>&1 || projection_status=$?
if [[ "$projection_status" -eq 42 ]] &&
  grep -q "git ls-files inventory failed (status 42)" "$TMP/out"; then
  pass "projection propagates the git ls-files failure (status 42, named)"
else
  bad "projection must propagate git's failure status, not skip (got $projection_status)"
  sed 's/^/        /' "$TMP/out"
fi

# Consumers 1 and 2 — each python consumer of quality.sh runs ALONE against
# the failing producer and must fail the lane with git's status.
make_consumer_driver() { # $1 = consumer function to run alone
  cat >"$TMP/consumer-driver.sh" <<DRIVER
set -euo pipefail
: "\${STUB_LOG:?STUB_LOG is required}"
export STUB_LOG
PATH="$TMP/bin:\$PATH"
export PATH
source "$ROOT/scripts/quality.sh" -h
$1
DRIVER
}
for consumer in run_python_syntax run_python_quality; do
  make_consumer_driver "$consumer"
  consumer_status=0
  QUALITY_ROOT="$FX_L" STUB_LOG="$TMP/stub-gitfail.log" PATH="$TMP/bin-failgit:$PATH" \
    bash "$TMP/consumer-driver.sh" >"$TMP/gitfail.out" 2>&1 || consumer_status=$?
  if [[ "$consumer_status" -eq 42 ]] &&
    grep -q "inventory failed (status 42)" "$TMP/gitfail.out"; then
    pass "$consumer fails loudly on a failing git ls-files inventory (status 42)"
  else
    bad "$consumer must fail with git's status, not skip (got $consumer_status)"
    sed 's/^/        /' "$TMP/gitfail.out"
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo "==> quality-input-coverage guard self-test FAILED."
  exit 1
fi
echo "    quality-input-coverage guard self-test: PASS"
