#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-quality-input-coverage.sh — file-level drift guard for the PYTHON
# lane's input universe (AR-06; Python-only scope).
#
# The catalog (config/quality-tools.json) python entry declares the lane's
# input universe once, as include/exclude path globs over TRACKED files:
#   include: **/*.py + *.py            every tracked dot-py file at any depth,
#                                      including root level (zero directories),
#                                      is eligible
#   exclude: (none)                    no retained-evidence tree remains (#555)
#   exclude_generated: node_modules/**, refs/**, build/**,
#                                      dist/**, test-results/** at the
#                                      repository root plus the same names
#                                      nested at any depth (**/node_modules/**
#                                      etc.) — vendor and generated trees,
#                                      declared defensively at BOTH depths:
#                                      nothing tracked beneath them is their
#                                      healthy state, so they are exempt from
#                                      the rot check by construction
# scripts/quality.sh's Python consumers take their inputs ONLY from this
# declared universe (via --eligible-files below) — never from a re-hardcoded
# path list. One declared universe, both consumers.
#
# This guard fails when:
#   · tracked dot-py files exist but the catalog declares no python lane, or
#     the lane is extension-classified with no include universe;
#   · the lane declares no exclude_generated set — vendor/generated trees
#     would enter the lane by silence instead of a declared exclusion;
#   · a tracked dot-py file is matched by neither the include nor the exclude
#     sets (eligible-but-uncovered), named by exact path;
#   · a declared evidence exclusion has silently rotted (matches no tracked
#     file); exclude_generated sets are never rot-checked — empty is healthy;
#   · AR06-1 tracked admission: a tracked scripts/check-*.sh guard references
#     a dot-py file that git does not track, or one that the declared exclude
#     sets removed from the lane. The exact guard and path are named — an
#     untracked executed file is a reported violation, never silently
#     invisible; it becomes lane-covered when the owning workflow commits it;
#   · a tracked guard makes a stable reference to a dot-py file that does not
#     exist in the tree ([MISSING]) — a "$SCRIPT_DIR/" / "${SCRIPT_DIR}/" or
#     "$ROOT/" / "${ROOT}/" prefix, braced or unbraced, must resolve.
#
# Modes:
#   (no args)              full adjudication; exit non-zero on any finding
#   --eligible-files LANG  projection only: print LANG's declared eligible
#                          list as absolute paths, one per line. This is what
#                          quality.sh's Python consumers call.
#   -h | --help            usage
#
# Matching semantics: catalog globs match repo-relative paths with bash case
# semantics, where * and ** span directory separators. A pattern containing a
# slash (like **/*.py) requires at least one directory component, so the
# catalog also declares *.py to admit root-level dot-py files with zero
# directories. The eligible universe is TRACKED-ONLY by design: CI sees only
# tracked files, and selecting nonignored untracked files would make the
# universe environment-dependent (AR-06 r2 amendment item 1).
#
# Reference scan: syntactic, restricted to TRACKED scripts/check-*.sh guards
# (selftest companions excluded) — an untracked scratch guard must not make
# the verdict environment-dependent. It collects path-like tokens ending in
# .py from each guard, keeping the braces of "${SCRIPT_DIR}/"- and
# "${ROOT}/"-style prefixes intact so both spellings of a stable reference
# tokenize (a braced prefix used to collapse to a bare "/x.py" and vanish).
# Stable references — tokens carrying an explicit "$SCRIPT_DIR/" or "$ROOT/"
# prefix, braced or unbraced — resolve to exactly one repo path whether or
# not the file exists; a missing target is a [MISSING] finding, never
# silence. Bare tokens resolve only when an existing root-relative or
# guard-dir-relative file matches; anything else is not a path this tree
# provably executes and is ignored.
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${QUALITY_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
CATALOG="${QUALITY_CATALOG:-$ROOT/config/quality-tools.json}"
LANG_ID="python"

usage() {
  cat <<'EOF'
Usage: bash scripts/check-quality-input-coverage.sh [--eligible-files <language>]

  (no args)                adjudicate the python lane's declared input universe
  --eligible-files <lang>  print the declared eligible file list (consumed by
                           scripts/quality.sh; projection only, no adjudication)

Overrides: QUALITY_ROOT (repo root), QUALITY_CATALOG (catalog path).
EOF
}

die() { # $1 message, $2 optional exit status (default 1)
  echo "quality-input-coverage: $1" >&2
  exit "${2:-1}"
}

lane_globs() { # $1 = field (include|exclude); globs for $LANG_ID, one per line
  jq -r --arg id "$LANG_ID" --arg field "$1" \
    '(.languages[]? | select(.id == $id) | (.[$field] // []))[]' "$CATALOG"
}

has_language() {
  jq -e --arg id "$LANG_ID" 'any(.languages[]?; .id == $id)' "$CATALOG" >/dev/null
}

# Match one repo-relative path against the newline-separated glob list read
# on stdin. The unquoted "$pat" inside case IS the pattern — intentional.
match_any() {
  local file="$1" pat
  while IFS= read -r pat; do
    [[ -z "$pat" ]] && continue
    # shellcheck disable=SC2254
    case "$file" in
      $pat) return 0 ;;
    esac
  done
  return 1
}

is_tracked() { # $1 = repo-relative path
  git -C "$ROOT" ls-files -- "$1" | grep -q .
}

# Resolve a syntactic .py reference token from a guard to a repo-relative
# path. Tries root-relative, then guard-directory-relative (stripping the
# variable prefixes guards write before the path). Both spellings of a stable
# prefix normalize to the same repo path: the unbraced "$SCRIPT_DIR/" /
# "$ROOT/" arrives from the token scan without its "$", the braced
# "${SCRIPT_DIR}/" / "${ROOT}/" arrives with the braces intact — the scan
# deliberately keeps braces so the prefix survives tokenization instead of
# collapsing to a bare "/x.py" that no stable location can be determined
# for. A STABLE reference — either spelling — resolves to exactly one repo
# path independent of existence: when the target is missing, prints
# "missing:<repo-rel-path>" so the caller can report it instead of silently
# dropping it. Bare tokens resolve only to an existing root- or
# guard-dir-relative file; prints nothing when no stable location can be
# determined.
resolve_ref() { # $1 = token, $2 = scanned guard's absolute directory
  local tok="$1" cand
  if [[ -f "$ROOT/$tok" ]]; then
    printf '%s' "$tok"
    return 0
  fi
  case "$tok" in
    SCRIPT_DIR/*) cand="$2/${tok#SCRIPT_DIR/}" ;;
    ROOT/*) cand="$ROOT/${tok#ROOT/}" ;;
    "{SCRIPT_DIR}"/*) cand="$2/${tok#'{SCRIPT_DIR}/'}" ;;
    "{ROOT}"/*) cand="$ROOT/${tok#'{ROOT}/'}" ;;
    *)
      cand="$2/$tok"
      if [[ -f "$cand" ]]; then
        printf '%s' "${cand#"$ROOT"/}"
      fi
      return 0
      ;;
  esac
  if [[ -f "$cand" ]]; then
    printf '%s' "${cand#"$ROOT"/}"
  else
    printf 'missing:%s' "${cand#"$ROOT"/}"
  fi
}

# The lane's full declared exclusion set: retained evidence (rot-checked)
# plus vendor/generated trees (declared defensively, never rot-checked).
all_excludes() {
  printf '%s\n%s' "$(lane_globs exclude)" "$(lane_globs exclude_generated)"
}

# Print every tracked file admitted by the declared universe (absolute paths).
# The tracked-file enumeration captures git's exit status (command
# substitution, not a process substitution, which loses it): a failing
# `git ls-files` must fail the projection with git's status — never degrade
# into a silently-empty lane that every consumer reads as "no eligible files".
eligible_files() {
  local include exclude tracked file status=0
  include="$(lane_globs include)"
  exclude="$(all_excludes)"
  if [[ -z "$include" ]]; then
    die "language '$LANG_ID' declares no include universe ($CATALOG); refusing to emit a silently-empty lane"
  fi
  tracked="$(git -C "$ROOT" ls-files)" || status=$?
  if [[ "$status" -ne 0 ]]; then
    die "git ls-files inventory failed (status $status); refusing to emit a silently-empty lane" "$status"
  fi
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    if match_any "$file" <<<"$include" && ! match_any "$file" <<<"$exclude"; then
      printf '%s/%s\n' "$ROOT" "$file"
    fi
  done <<<"$tracked"
}

findings=0
report() {
  findings=$((findings + 1))
  echo "quality-input-coverage: $1" >&2
}

adjudicate() {
  local include exclude generated all_excludes extensions tracked_all file pat ext rel guard tok ignored match guard_dir
  local covered=0 excluded=0

  # Existence + classification contract.
  if ! has_language; then
    if [[ -n "$(git -C "$ROOT" ls-files '*.py')" ]]; then
      report "[NO-LANE] tracked dot-py files exist but the catalog declares no '$LANG_ID' language ($CATALOG)"
      exit 1
    fi
    echo "quality input coverage: PASS (no '$LANG_ID' lane declared, no tracked dot-py files to cover)"
    return
  fi
  extensions="$(jq -r --arg id "$LANG_ID" \
    '(.languages[]? | select(.id == $id) | .extensions // [])[]' "$CATALOG")"
  if [[ -z "$extensions" ]]; then
    report "[NO-INCLUDE] language '$LANG_ID' declares no extensions; its input universe is undeclared"
    exit 1
  fi
  include="$(lane_globs include)"
  exclude="$(lane_globs exclude)"
  generated="$(lane_globs exclude_generated)"
  all_excludes="$(printf '%s\n%s' "$exclude" "$generated")"
  if [[ -z "$include" ]]; then
    report "[NO-INCLUDE] language '$LANG_ID' is extension-classified but declares no include universe ($CATALOG)"
    exit 1
  fi
  if [[ -z "$generated" ]]; then
    report "[NO-GENERATED] language '$LANG_ID' declares no exclude_generated set ($CATALOG); vendor and generated trees would enter the lane by silence instead of a declared exclusion"
    exit 1
  fi
  tracked_all="$(git -C "$ROOT" ls-files)"

  # Every tracked file of a classified extension must be include-matched or
  # exclusion-matched; anything else is silently uncovered.
  while IFS= read -r ext; do
    [[ -z "$ext" ]] && continue
    while IFS= read -r file; do
      [[ -z "$file" ]] && continue
      if match_any "$file" <<<"$include"; then
        covered=$((covered + 1))
      elif match_any "$file" <<<"$all_excludes"; then
        excluded=$((excluded + 1))
      else
        report "[UNCOVERED] tracked file '$file' is matched by neither the include nor the exclude sets of language '$LANG_ID'"
      fi
    done < <(git -C "$ROOT" ls-files "*.$ext")
  done <<<"$extensions"

  # A declared EVIDENCE exclusion that matches nothing has silently rotted.
  # exclude_generated patterns are exempt: nothing tracked beneath vendor and
  # generated trees is their healthy state, so an empty match is by design.
  while IFS= read -r pat; do
    [[ -z "$pat" ]] && continue
    match=0
    while IFS= read -r file; do
      [[ -z "$file" ]] && continue
      if match_any "$file" <<<"$pat"; then
        match=1
        break
      fi
    done <<<"$tracked_all"
    if [[ "$match" -eq 0 ]]; then
      report "[ROTTED] exclude pattern '$pat' of language '$LANG_ID' matches no tracked file"
    fi
  done <<<"$exclude"

  # AR06-1 tracked admission: TRACKED guard scripts must not execute files
  # git does not track, nor files the declaration removed from the lane, and
  # every stable reference must resolve. The scan enumerates tracked guards
  # (git ls-files), not the filesystem glob — an untracked scratch guard must
  # not make the verdict environment-dependent.
  while IFS= read -r guard; do
    [[ -z "$guard" ]] && continue
    case "$guard" in *-selftest.sh) continue ;; esac
    guard="$ROOT/$guard"
    guard_dir="$(dirname "$guard")"
    while IFS= read -r tok; do
      [[ -z "$tok" ]] && continue
      rel="$(resolve_ref "$tok" "$guard_dir")"
      case "$rel" in
        "")
          continue # no stable location — nothing provably executed to adjudicate
          ;;
        missing:*)
          report "[MISSING] tracked guard '${guard#"$ROOT"/}' references '${rel#missing:}' which does not exist in the tree — a stable interpreter reference must resolve"
          continue
          ;;
      esac
      if ! is_tracked "$rel"; then
        ignored="(untracked, not ignored)"
        if git -C "$ROOT" check-ignore -q "$rel"; then
          ignored="(untracked and git-ignored)"
        fi
        report "[PREREQ] tracked guard '${guard#"$ROOT"/}' executes '$rel' which git does not track $ignored — tracked admission is the prerequisite for lane eligibility; commit it (owning workflow) to admit it to the '$LANG_ID' lane"
      elif ! match_any "$rel" <<<"$include"; then
        report "[PREREQ] tracked guard '${guard#"$ROOT"/}' executes '$rel' which is outside the '$LANG_ID' lane's declared include set"
      elif match_any "$rel" <<<"$all_excludes"; then
        report "[PREREQ] tracked guard '${guard#"$ROOT"/}' executes '$rel' which the '$LANG_ID' lane's declared exclude sets removed from the lane"
      fi
    done < <(grep -hoE '[A-Za-z0-9_./{}-]+\.py' "$guard" | sort -u)
  done < <(git -C "$ROOT" ls-files 'scripts/check-*.sh')

  if [[ "$findings" -eq 0 ]]; then
    echo "quality input coverage: PASS ($covered tracked '$LANG_ID' lane files, $excluded declared-excluded)"
  else
    exit 1
  fi
}

case "${1:-}" in
  --eligible-files)
    [[ -n "${2:-}" ]] || die "--eligible-files requires a language id" 2
    LANG_ID="$2"
    has_language || die "catalog declares no language '$LANG_ID' ($CATALOG)" 2
    eligible_files
    ;;
  -h | --help)
    usage
    ;;
  "")
    adjudicate
    ;;
  *)
    usage >&2
    die "unknown mode: $1" 2
    ;;
esac
