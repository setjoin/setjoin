#!/usr/bin/env bash
# check-cargo-supply-chain.sh — clients Rust registry + lockfile + toolchain
# supply-chain guard (D-CLIENTS--CARGO-001/002, CWE-494/CWE-426).
#
# Enforces, offline and without invoking cargo:
#   1. clients/.cargo/config.toml pins the default registry to the canonical
#      sparse crates.io endpoint; no [source.*] mirrors, no [patch.*], no
#      replace-with.
#   2. clients/deny.toml [sources] denies unknown registries and git
#      dependencies, allowing exactly the pinned registry spellings.
#   3. clients/Cargo.lock matches the pinned known-good checksum catalog
#      scripts/cargo-lock-pins.json: whole-file sha256 plus every
#      (name, version, source, checksum) tuple — a substituted artifact, a
#      typosquat addition, a checksum tamper, or a dependency-edge rewrite all
#      fail with a named cause. The guard polices the COMMITTED bytes (git
#      HEAD) when run inside a checkout: mid-job tooling (cargo refreshing the
#      lock with platform-specific entries on a runner) must not mask or fake
#      the reviewable artifact — such worktree drift prints an explicit
#      WORKTREE-DIFF note instead of failing. Outside git (fixture drills) it
#      reads the file directly.
#   4. The OHOS SDK toolchain binaries referenced by clients/.cargo/config.toml
#      ([env] OHOS_NDK_HOME/CC_*/CXX_*, [target.*] linker/ar) match the
#      basename+sha256 pins in cargo-lock-pins.json's sdk section, keyed by
#      path relative to the SDK root so machine-specific prefixes don't churn.
#      A machine with the SDK hash-verifies every pinned binary (hashing only
#      — SDK executables are never executed); a machine WITHOUT the SDK prints
#      an explicit `SDK-SKIP (reason=…)` line — greppable so CI can require or
#      allow it deliberately, never a silent pass.
#
# Wiring: scripts/run-guards.sh globs every check-*.sh, so this guard runs in
# the xinchuang-ci.yml structural-guards step automatically (adding a guard =
# dropping a file) and in the local merge gate via scripts/test.sh.
#
# Dependency updates: run `node scripts/cargo-lock-catalog.mjs refresh` after a
# reviewed lockfile change — the pins diff is the review artifact. Never
# refresh to silence this guard without reading the lock diff.
#
# --self-test proves the guard still fires: it runs the clean-tree check
# (green) and then injects deterministic corruptions into TEMP COPIES
# (checksum tamper, typosquat addition, git dependency, dropped checksum,
# dependency-edge rewrite, evil mirror registry, extra source table, quoted
# [patch."…"] override, plain-table/array-table kind collision, syntax the
# parser must reject, weakened deny policy) asserting each one goes red —
# plus an SDK fixture round (fake SDK under a temp dir: green, escaped-path
# spelling green, tampered fixture pin → DRIFT in both the plain and the
# escaped-spelling config — proving the decoded-value rebase still bites when
# root paths carry \uXXXX escapes — tampered binary → DRIFT, absent SDK →
# explicit SDK-SKIP) and the refresh re-arm path. Every SDK
# drill runs against the fixture, so the self-test never depends on the real
# OHOS SDK being installed. The real tree is never mutated.
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"

CATALOG="$ROOT/scripts/cargo-lock-catalog.mjs"
PINS="$ROOT/scripts/cargo-lock-pins.json"
LOCK="$ROOT/clients/Cargo.lock"
CONFIG="$ROOT/clients/.cargo/config.toml"
DENY="$ROOT/clients/deny.toml"

for file in "$CATALOG" "$PINS" "$LOCK" "$CONFIG" "$DENY"; do
  [[ -f "$file" ]] || {
    echo "E_CARGO_SUPPLY_MISSING problem=cargo_supply_chain cause=\"required file missing: $file\"" >&2
    exit 1
  }
done

# Polices the COMMITTED lock bytes (git HEAD) inside a checkout so mid-job
# tooling (e.g. cargo rewriting the lock with platform-specific entries) can
# neither mask nor fake the reviewable artifact; worktree divergence prints an
# explicit WORKTREE-DIFF note. Outside git, reads the file directly (the
# self-test's fixture drills and non-git temp fixtures keep file semantics).
# $1 = repo root, $2 = writable temp file path for the committed bytes.
resolve_committed_lock() {
  local root="$1" sink="$2"
  if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1 &&
    git -C "$root" cat-file -e "HEAD:clients/Cargo.lock" 2>/dev/null &&
    git -C "$root" show "HEAD:clients/Cargo.lock" >"$sink" 2>/dev/null; then
    cmp -s "$sink" "$root/clients/Cargo.lock" ||
      echo "WORKTREE-DIFF (informational): worktree clients/Cargo.lock differs from HEAD — policing the committed lock (the reviewable artifact); worktree drift from mid-job tooling is not a violation." >&2
    printf '%s\n' "$sink"
  else
    printf '%s\n' "$root/clients/Cargo.lock"
  fi
}

real_check() {
  local root="$1" sink="$2" lockfile
  lockfile="$(resolve_committed_lock "$root" "$sink")"
  node "$CATALOG" check "$lockfile" "$root/clients/.cargo/config.toml" "$root/clients/deny.toml" "$PINS"
}

selftest() {
  # Global on purpose: the EXIT trap below fires after this function returns.
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  echo "self-test: clean tree must stay green"
  if ! real_check "$ROOT" "$(mktemp "${tmp}/committed-lock.XXXXXX")"; then
    echo "self-test: FAIL — clean tree check did not pass" >&2
    return 1
  fi

  # Committed-state semantics: worktree lock mutation must NOT fail the guard
  # (it polices HEAD) but must print the explicit WORKTREE-DIFF note, while a
  # mutated COMMITTED lock still fires DRIFT.
  echo "self-test: worktree-only lock drift is a note, not a failure"
  local gitdrill="$tmp/gitdrill"
  mkdir -p "$gitdrill/clients/.cargo" "$gitdrill/scripts"
  cp "$LOCK" "$gitdrill/clients/Cargo.lock"
  cp "$CONFIG" "$gitdrill/clients/.cargo/config.toml"
  cp "$DENY" "$gitdrill/clients/deny.toml"
  cp "$PINS" "$gitdrill/scripts/cargo-lock-pins.json"
  git -C "$gitdrill" init -q &&
    git -C "$gitdrill" -c user.email=guard@local -c user.name=guard add -A &&
    git -C "$gitdrill" -c user.email=guard@local -c user.name=guard commit -qm base
  node "$CATALOG" mutate add-package "$gitdrill/clients/Cargo.lock"
  local note_out
  if ! note_out="$(real_check "$gitdrill" "$(mktemp "${tmp}/committed-lock.XXXXXX")" 2>&1)"; then
    echo "self-test: FAIL — worktree-only lock drift failed the guard (must police HEAD):" >&2
    printf '%s\n' "$note_out" >&2
    return 1
  fi
  if ! printf '%s\n' "$note_out" | grep -q "WORKTREE-DIFF"; then
    echo "self-test: FAIL — worktree-only lock drift produced no WORKTREE-DIFF note (silent divergence)" >&2
    printf '%s\n' "$note_out" >&2
    return 1
  fi
  echo "self-test: committed lock tamper must still fire E_CARGO_SUPPLY_DRIFT"
  node "$CATALOG" mutate rewire-dep "$gitdrill/clients/Cargo.lock"
  git -C "$gitdrill" -c user.email=guard@local -c user.name=guard add -A
  git -C "$gitdrill" -c user.email=guard@local -c user.name=guard commit -qm tampered
  if out="$(real_check "$gitdrill" "$(mktemp "${tmp}/committed-lock.XXXXXX")" 2>&1)"; then
    echo "self-test: FAIL — committed tampered lock did NOT fail the guard (guard is blind)" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  if ! printf '%s' "$out" | grep -q "E_CARGO_SUPPLY_DRIFT"; then
    echo "self-test: FAIL — committed tampered lock failed with the wrong cause:" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi

  # Red drills. kind=file-mutated expected-violation-code
  # (tamper-sdk-pin lives in the SDK fixture section below: it must run
  # against the fixture's pins + config, not the real tree, so it fires
  # regardless of whether this machine has the OHOS SDK.)
  local drills=(
    "tamper-checksum lock E_CARGO_SUPPLY_UNPINNED"
    "add-package lock E_CARGO_SUPPLY_UNPINNED"
    "add-git-package lock E_CARGO_SUPPLY_SOURCE"
    "drop-checksum lock E_CARGO_SUPPLY_CHECKSUM"
    "rewire-dep lock E_CARGO_SUPPLY_DRIFT"
    "evil-mirror config E_CARGO_SUPPLY_CONFIG"
    "extra-source config E_CARGO_SUPPLY_CONFIG"
    "quoted-patch-override config E_CARGO_SUPPLY_CONFIG"
    "evil-kind-collision config E_CARGO_SUPPLY_SYNTAX"
    "unsupported-syntax config E_CARGO_SUPPLY_SYNTAX"
    "weaken-deny deny E_CARGO_SUPPLY_DENY"
  )
  local drill kind file want out mutated
  for drill in "${drills[@]}"; do
    kind="${drill%% *}"
    want="${drill##* }"
    case "$kind" in
      evil-mirror | extra-source | quoted-patch-override | evil-kind-collision | unsupported-syntax) file="$CONFIG" ;;
      weaken-deny) file="$DENY" ;;
      *) file="$LOCK" ;;
    esac
    mutated="$tmp/$(basename "$file")"
    cp "$file" "$mutated"
    if ! node "$CATALOG" mutate "$kind" "$mutated"; then
      echo "self-test: FAIL — mutation $kind could not be applied" >&2
      return 1
    fi
    # The mutated file must go in its own positional slot: check <lock> <config> <deny> <pins>.
    case "$kind" in
      evil-mirror | extra-source | quoted-patch-override | evil-kind-collision | unsupported-syntax) check_args=("$LOCK" "$mutated" "$DENY" "$PINS") ;;
      weaken-deny) check_args=("$LOCK" "$CONFIG" "$mutated" "$PINS") ;;
      *) check_args=("$mutated" "$CONFIG" "$DENY" "$PINS") ;;
    esac
    echo "self-test: injected '$kind' must fire $want"
    if out="$(node "$CATALOG" check "${check_args[@]}" 2>&1)"; then
      echo "self-test: FAIL — injected '$kind' did NOT fail the guard (guard is blind)" >&2
      printf '%s\n' "$out" >&2
      return 1
    fi
    if ! printf '%s' "$out" | grep -q "$want"; then
      echo "self-test: FAIL — injected '$kind' failed with the wrong cause, wanted $want:" >&2
      printf '%s\n' "$out" >&2
      return 1
    fi
  done

  # SDK toolchain guard: a fixture SDK (fake binaries — hashed, never
  # executed) inside $tmp, with the real config rebased onto it and matching
  # pins. Green first, plus the escaped-\uXXXX spelling of the same root
  # (parsing must decode it — never silently SKIP an SDK that exists), then a
  # tampered fixture PIN must fire DRIFT against both the plain and the
  # escaped-spelling config, a tampered fixture binary must fire DRIFT, and an
  # absent SDK root must print an explicit SDK-SKIP. Every SDK drill
  # runs on the fixture, so none depends on the real OHOS SDK being installed.
  echo "self-test: SDK fixture must hash-verify green"
  node "$CATALOG" sdk-fixture "$tmp/sdk" "$tmp/absent-sdk" >/dev/null
  local sdk_args=("$LOCK" "$tmp/sdk/config.toml" "$DENY" "$tmp/sdk/pins.json")
  if ! out="$(node "$CATALOG" check "${sdk_args[@]}" 2>&1)" || ! printf '%s' "$out" | grep -q "SDK-OK"; then
    echo "self-test: FAIL — SDK fixture did not verify green with SDK-OK:" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  echo "self-test: escaped-spelling SDK paths must hash-verify, not silently skip"
  if ! out="$(node "$CATALOG" check "$LOCK" "$tmp/sdk/config-escaped.toml" "$DENY" "$tmp/sdk/pins.json" 2>&1)" ||
    ! printf '%s' "$out" | grep -q "SDK-OK"; then
    echo "self-test: FAIL — escaped-path config did not hash-verify (wrongly skipped, drifted or aborted):" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  echo "self-test: tampered fixture SDK pin must fire E_CARGO_SUPPLY_SDK_DRIFT"
  cp "$tmp/sdk/pins.json" "$tmp/sdk/pins-tampered.json"
  if ! node "$CATALOG" mutate tamper-sdk-pin "$tmp/sdk/pins-tampered.json"; then
    echo "self-test: FAIL — tamper-sdk-pin mutation could not be applied" >&2
    return 1
  fi
  if out="$(node "$CATALOG" check "$LOCK" "$tmp/sdk/config.toml" "$DENY" "$tmp/sdk/pins-tampered.json" 2>&1)"; then
    echo "self-test: FAIL — tampered SDK pin did NOT fail the guard (guard is blind)" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  if ! printf '%s' "$out" | grep -q "E_CARGO_SUPPLY_SDK_DRIFT"; then
    echo "self-test: FAIL — tampered SDK pin failed with the wrong cause, wanted E_CARGO_SUPPLY_SDK_DRIFT:" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  echo "self-test: tampered fixture pin must fire DRIFT through the escaped-spelling config too"
  if out="$(node "$CATALOG" check "$LOCK" "$tmp/sdk/config-escaped.toml" "$DENY" "$tmp/sdk/pins-tampered.json" 2>&1)"; then
    echo "self-test: FAIL — tampered SDK pin behind escaped root spellings did NOT fail the guard (fixture rebase leaked the real SDK)" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  if ! printf '%s' "$out" | grep -q "E_CARGO_SUPPLY_SDK_DRIFT"; then
    echo "self-test: FAIL — escaped-spelling tampered pin failed with the wrong cause, wanted E_CARGO_SUPPLY_SDK_DRIFT:" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  echo "self-test: tampered SDK binary must fire E_CARGO_SUPPLY_SDK_DRIFT"
  printf 'x' >>"$tmp/sdk/native/llvm/bin/aarch64-unknown-linux-ohos-clang"
  if out="$(node "$CATALOG" check "${sdk_args[@]}" 2>&1)"; then
    echo "self-test: FAIL — tampered SDK binary did NOT fail the guard (guard is blind)" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  if ! printf '%s' "$out" | grep -q "E_CARGO_SUPPLY_SDK_DRIFT"; then
    echo "self-test: FAIL — tampered SDK binary failed with the wrong cause, wanted E_CARGO_SUPPLY_SDK_DRIFT:" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  echo "self-test: absent SDK must print an explicit SDK-SKIP line"
  if ! out="$(node "$CATALOG" check "$LOCK" "$tmp/sdk/config-absent.toml" "$DENY" "$tmp/sdk/pins.json" 2>&1)"; then
    echo "self-test: FAIL — absent SDK must be an explicit skip, not a failure:" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi
  if ! printf '%s' "$out" | grep -q "SDK-SKIP"; then
    echo "self-test: FAIL — absent SDK produced no SDK-SKIP line (silent pass)" >&2
    printf '%s\n' "$out" >&2
    return 1
  fi

  # Refresh path: a consciously refreshed catalog must accept the mutated
  # lock again (proves the dependency-update workflow functions end to end).
  echo "self-test: refresh must re-arm the guard after a sanctioned change"
  local tmp_pins="$tmp/cargo-lock-pins.json"
  if ! node "$CATALOG" mutate add-package "$LOCK" "$tmp/lock" ||
    ! node "$CATALOG" refresh "$tmp/lock" "$tmp_pins" ||
    ! node "$CATALOG" check "$tmp/lock" "$CONFIG" "$DENY" "$tmp_pins" >/dev/null; then
    echo "self-test: FAIL — refresh workflow did not re-arm the guard" >&2
    return 1
  fi

  echo "self-test: PASS (1 green + ${#drills[@]} injected violations fired + committed-state drills (worktree-diff note, committed tamper) + SDK fixture green/escaped/pin-drift/escaped-pin-drift/binary-drift/skip + refresh re-armed)"
}

case "${1:-}" in
  --self-test)
    selftest
    ;;
  "")
    real_check "$ROOT" "$(mktemp -t committed-lock)"
    ;;
  *)
    echo "usage: $0 [--self-test]" >&2
    exit 2
    ;;
esac
