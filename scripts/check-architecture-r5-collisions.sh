#!/usr/bin/env bash
# Architecture R5 admin collision release is read-only. It never edits or stashes.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

REGISTRY="${ARCH_R5_REGISTRY:-$ROOT/docs/verification/architecture-r5-cases.json}"
RESULTS_ROOT="${ARCH_R5_COLLISION_RESULTS_ROOT:-$ROOT/test-results/architecture-r5/collisions}"
NODE_BIN="${ARCH_R5_NODE_BIN:-$(command -v node || true)}"
FINGERPRINT_TOOL="$ROOT/scripts/lib/source-fingerprint.mjs"

usage() {
  cat <<'EOF'
Usage: bash scripts/check-architecture-r5-collisions.sh admin [--self-test]

Read-only source-bound collision release check for the R5 admin candidate.
PASS means no owner-released path since the registered baseline intersects a
candidate path. HOLD is exit 3. The script never edits, stages, stashes, or resets.
EOF
}

diagnostic() {
  local code="$1" problem="$2" cause="$3" location="$4" artifact="$5" fix="$6" rerun="$7"
  printf '%s\n' "$code" >&2
  printf 'problem: %s\n' "$problem" >&2
  printf 'cause: %s\n' "$cause" >&2
  printf 'location: %s\n' "$location" >&2
  printf 'artifact: %s\n' "$artifact" >&2
  printf 'fix: %s\n' "$fix" >&2
  printf 'rerun: %s\n' "$rerun" >&2
  printf 'docs: retired-docs:superpowers/plans/archive/2026-08-24-architecture-deepening-round-5.md\n' >&2
}

source_fingerprint() {
  "$NODE_BIN" "$FINGERPRINT_TOOL" compute --root "$ROOT"
}

parse_source_fingerprint() {
  "$NODE_BIN" "$FINGERPRINT_TOOL" parse --value "$1"
}

publish() {
  local status="$1" base="$2" released_ref="$3" released_commit="$4" current_fingerprint="$5" candidate_file="$6" released_file="$7" intersection_file="$8"
  local tmp run_id final
  mkdir -p "$RESULTS_ROOT"
  tmp="$(mktemp -d "$RESULTS_ROOT/.tmp.XXXXXX")"
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-${current_commit:0:8}-$$-admin"
  final="$RESULTS_ROOT/$run_id"
  ARCH_R5_COLLISION_STATUS="$status" ARCH_R5_COLLISION_BASE="$base" \
  ARCH_R5_COLLISION_RELEASED_REF="$released_ref" ARCH_R5_COLLISION_RELEASED_COMMIT="$released_commit" \
  ARCH_R5_COLLISION_SOURCE_JSON="$(parse_source_fingerprint "$current_fingerprint")" \
  ARCH_R5_COLLISION_CANDIDATES="$candidate_file" ARCH_R5_COLLISION_RELEASED="$released_file" \
  ARCH_R5_COLLISION_INTERSECTION="$intersection_file" "$NODE_BIN" >"$tmp/receipt.json.tmp" <<'NODE'
const fs = require('node:fs');
const lines = (filename) => fs.readFileSync(filename, 'utf8').split('\n').filter(Boolean);
const source = JSON.parse(process.env.ARCH_R5_COLLISION_SOURCE_JSON);
const receipt = {
  schemaVersion: 1,
  candidate: 'R5-6',
  lane: 'admin',
  status: process.env.ARCH_R5_COLLISION_STATUS,
  source: {
    baseCommit: process.env.ARCH_R5_COLLISION_BASE,
    releasedRef: process.env.ARCH_R5_COLLISION_RELEASED_REF,
    releasedCommit: process.env.ARCH_R5_COLLISION_RELEASED_COMMIT,
    currentFingerprint: source.value,
    currentCommit: source.commit,
    dirtyDigest: source.digest,
  },
  candidatePaths: lines(process.env.ARCH_R5_COLLISION_CANDIDATES),
  ownerReleasedPaths: lines(process.env.ARCH_R5_COLLISION_RELEASED),
  intersection: lines(process.env.ARCH_R5_COLLISION_INTERSECTION),
};
process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
NODE
  mv "$tmp/receipt.json.tmp" "$tmp/receipt.json"
  mv "$tmp" "$final"
  printf '{"schemaVersion":1,"runId":"%s"}\n' "$run_id" >"$RESULTS_ROOT/.latest.$$"
  mv "$RESULTS_ROOT/.latest.$$" "$RESULTS_ROOT/latest.json"
  printf '%s\n' "$final/receipt.json"
}

run_admin() {
  local base released_ref released_commit current_fingerprint current_source_json current_commit tmp receipt status
  [[ -n "$NODE_BIN" ]] || {
    diagnostic E_ARCH_R5_COLLISION_PREREQUISITE "admin collision status is unknown" "node is not installed" "scripts/check-architecture-r5-collisions.sh" "none" "install the repository Node toolchain" "bash scripts/check-architecture-r5-collisions.sh admin"
    return 3
  }
  ARCH_R5_REGISTRY="$REGISTRY" "$NODE_BIN" "$ROOT/scripts/check-architecture-r5-cases.mjs" validate >/dev/null || {
    diagnostic E_ARCH_R5_COLLISION_REGISTRY "admin collision status is unknown" "the Round 5 registry is malformed" "$REGISTRY" "none" "repair the exact 14-case registry" "node scripts/check-architecture-r5-cases.mjs validate"
    return 3
  }
  base="$("$NODE_BIN" -e 'const r=require(process.argv[1]);process.stdout.write(r.collisionBaselines.admin.baseCommit)' "$REGISTRY")"
  released_ref="$("$NODE_BIN" -e 'const r=require(process.argv[1]);process.stdout.write(r.collisionBaselines.admin.releasedRef)' "$REGISTRY")"
  base_absent=0
  git -C "$ROOT" cat-file -e "$base^{commit}" 2>/dev/null || base_absent=1
  if ! released_commit="$(git -C "$ROOT" rev-parse --verify "$released_ref^{commit}" 2>/dev/null)"; then
    # PR checkouts carry the released branch only as refs/remotes/origin/<ref>
    # (no local branch). Same commit, same contract — accept the remote-tracking
    # spelling before declaring the owner-released ref unavailable.
    if ! released_commit="$(git -C "$ROOT" rev-parse --verify "origin/$released_ref^{commit}" 2>/dev/null)"; then
      diagnostic E_ARCH_R5_COLLISION_RELEASED_REF "admin collision status is unknown" "owner-released ref is unavailable" "$REGISTRY" "ref=$released_ref" "fetch or restore the registered local ref without changing worktree files" "bash scripts/check-architecture-r5-collisions.sh admin"
      return 3
    fi
    released_ref="origin/$released_ref"
  fi
  if ((base_absent)); then
    # One-commit public history never contains the private registered baseline.
    # Compare against the repository root commit instead (candidate paths are still
    # intersected with the owner-released range; the range is empty when the
    # released ref IS the root commit). This is a loud fallback, not a skip.
    root_commit="$(git -C "$ROOT" rev-list --max-parents=0 "$released_commit" | tail -n 1)"
    [[ -n "$root_commit" ]] || {
      diagnostic E_ARCH_R5_COLLISION_BASE "admin collision status is unknown" "registered base commit is unavailable and no root commit was found" "$REGISTRY" "base=$base" "restore repository history" "bash scripts/check-architecture-r5-collisions.sh admin"
      return 3
    }
    echo "architecture-r5 collision: BASELINE-ABSENT registered base $base is not in this repository; using root commit $root_commit as the comparison baseline (candidate/released path intersection still evaluated)" >&2
    base="$root_commit"
  fi
  if ! git -C "$ROOT" merge-base --is-ancestor "$base" "$released_commit"; then
    diagnostic E_ARCH_R5_COLLISION_DIVERGED "admin collision status is unknown" "registered base is not an ancestor of the owner-released ref" "$REGISTRY" "base=$base released=$released_commit" "rebase and re-audit candidate paths before updating the baseline" "bash scripts/check-architecture-r5-collisions.sh admin"
    return 3
  fi
  current_fingerprint="$(source_fingerprint)"
  current_source_json="$(parse_source_fingerprint "$current_fingerprint")"
  current_commit="$("$NODE_BIN" -e 'process.stdout.write(JSON.parse(process.argv[1]).commit)' "$current_source_json")"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  "$NODE_BIN" -e 'const r=require(process.argv[1]);for(const p of r.collisionBaselines.admin.candidatePaths)console.log(p)' "$REGISTRY" | LC_ALL=C sort -u >"$tmp/candidates"
  git -C "$ROOT" diff --name-only "$base..$released_commit" -- | LC_ALL=C sort -u >"$tmp/released"
  "$NODE_BIN" - "$tmp/candidates" "$tmp/released" >"$tmp/intersection" <<'NODE'
const fs = require('node:fs');
const read = (filename) => fs.readFileSync(filename, 'utf8').split('\n').filter(Boolean);
const candidates = read(process.argv[2]);
const released = read(process.argv[3]);
const collides = (left, right) => left === right || left.startsWith(`${right}/`) || right.startsWith(`${left}/`);
for (const candidate of candidates) for (const ownerPath of released) if (collides(candidate, ownerPath)) console.log(ownerPath);
NODE
  status=pass
  [[ ! -s "$tmp/intersection" ]] || status=hold
  receipt="$(publish "$status" "$base" "$released_ref" "$released_commit" "$current_fingerprint" "$tmp/candidates" "$tmp/released" "$tmp/intersection")"
  if [[ "$status" == hold ]]; then
    diagnostic E_ARCH_R5_COLLISION_HOLD "admin architecture work remains collision-held" "owner-released paths intersect the registered candidate paths" "$REGISTRY" "$receipt" "rebase, inspect every intersecting path, and update the candidate map only after source review" "bash scripts/check-architecture-r5-collisions.sh admin"
    return 3
  fi
  echo "architecture-r5 collision: PASS lane=admin receipt=${receipt#"$ROOT"/}"
}

case "${1:-admin}" in
  --help|-h) [[ $# -eq 1 ]] || exit 2; usage ;;
  --self-test)
    [[ $# -eq 1 ]] || exit 2
    bash "$ROOT/scripts/check-architecture-r5-collisions.test.sh"
    ;;
  admin)
    if [[ "${2:-}" == "--self-test" ]]; then
      [[ $# -eq 2 ]] || exit 2
      bash "$ROOT/scripts/check-architecture-r5-collisions.test.sh"
    else
      [[ $# -le 1 ]] || { usage >&2; exit 2; }
      run_admin
    fi
    ;;
  *) usage >&2; exit 2 ;;
esac
