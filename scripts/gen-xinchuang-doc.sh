#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# gen-xinchuang-doc.sh — single-source renderer for the Xinchuang matrix.
#
# Every per-engine verdict cell in mailserver/sql/xinchuang/README.md is
# GENERATED from two machine sources plus the reducer sources themselves:
#
#   compatibility_matrix.csv  per-function, per-engine FUNCTIONAL verdicts.
#       Cell grammar: `untested` | `pass@<ref>` | `partial@<ref>` |
#       `fail@<ref>`, where <ref> is a repo-relative path[:line] that must
#       resolve to a regular FILE inside the repo — `..` traversal escapes,
#       directory targets, and SYMLINK escapes are rejected: the ref's fully
#       resolved real path must sit strictly under the CANONICAL repo root,
#       so a link whose target lies outside the repo never counts as
#       evidence (r2.1(6)). Legacy ✅/⚠️/❌ cells
#       were migrated to `untested` — a checkmark is not evidence, and the
#       generator never emits a bare one.
#   engine_capabilities.csv   per-engine feature/security grid — the SOLE
#       source for the README's engine-capability table (r2.1). Structured
#       schema: `status` is bare pass|partial|fail|untested and the separate
#       evidence column carries the ref; a legacy inline `status@<ref>`
#       status cell is parsed into that same pair at validation. Validation
#       and rendering share one parser, so a cell the validator accepts can
#       never render as `untested`.
#   mailserver/sql/reducers/*.sql  the live function universe. Counting unit
#       is the function NAME; declaration counts are reported separately and
#       overloads are never attested by name-level coverage (r2.3).
#
# Outputs (all byte-deterministic; regenerate twice and nothing changes):
#   - the README block between `<!-- BEGIN GENERATED: xinchuang-matrix -->`
#     and `<!-- END GENERATED -->` sentinels (feature/security grid,
#     functional coverage with attested/unattested counts, critical-path
#     per-name per-engine statuses, unattested families),
#   - compatibility_matrix.csv rewritten canonically — ONLY `uses_digest` is
#     recomputed. `uses_digest` is SOURCE-DERIVED USAGE (a non-comment
#     `digest(` call in the defining file), never a parity verdict (r2.1(4));
#   - unattested_functions.csv — the canonical complement
#     inventory = live_names \ csv_live_names, one `function,defined_in` row
#     per name, sorted (r2.3).
#
# Fail-closed: extraction aborts non-zero on zero reducer files, an unparsable
# declaration, or an empty name set — a failed extraction must never produce a
# vacuously true complement (r2.3(2)). Normal mode additionally rejects dead /
# duplicate CSV rows, invalid enum or evidence cells, incomplete
# engine×dimension coverage, and critical-path names that are not live and
# CSV-covered. XINCHUANG_MATRIX_FIXTURES=1 bypasses ONLY those row-source
# validations (for check-xinchuang-matrix.sh's isolated self-test fixtures,
# r2.4) — extraction fail-closedness is never bypassed, and rendered cells are
# always emitted (an unsupported cell renders `untested`, never omitted,
# r2.1(6)).
#
# Environment overrides (self-test fixtures only):
#   XINCHUANG_MATRIX_CSV, XINCHUANG_CAPS_CSV, XINCHUANG_README,
#   XINCHUANG_INVENTORY, XINCHUANG_REDUCERS_DIR, XINCHUANG_ROOT,
#   XINCHUANG_MATRIX_FIXTURES
#
# Usage:
#   scripts/gen-xinchuang-doc.sh                 # regenerate in place
#   scripts/gen-xinchuang-doc.sh --check <dir>   # render into <dir> only:
#                                                #   README.block
#                                                #   compatibility_matrix.csv
#                                                #   unattested_functions.csv
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
export LC_ALL=C

ROOT="${XINCHUANG_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
XDIR="$ROOT/mailserver/sql/xinchuang"
REDUCERS_DIR="${XINCHUANG_REDUCERS_DIR:-$ROOT/mailserver/sql/reducers}"
MATRIX_CSV="${XINCHUANG_MATRIX_CSV:-$XDIR/compatibility_matrix.csv}"
CAPS_CSV="${XINCHUANG_CAPS_CSV:-$XDIR/engine_capabilities.csv}"
README="${XINCHUANG_README:-$XDIR/README.md}"
INVENTORY="${XINCHUANG_INVENTORY:-$XDIR/unattested_functions.csv}"
FIXTURE_MODE="${XINCHUANG_MATRIX_FIXTURES:-}"

MATRIX_HEADER="function,description,polardb,opengauss,gaussdb,kingbase,dameng,oceanbase_pg,oceanbase_oracle,uses_digest,notes"
CAPS_HEADER="engine,dimension,status,evidence"
ENGINES=(polardb opengauss gaussdb kingbase dameng oceanbase_pg oceanbase_oracle)
DIMENSIONS=(plpgsql listen_notify jsonb pg_trgm pgcrypto_digest_parity rls_semantics grants_role_separation security_definer tls_fips sm_crypto_module)
DIM_LABELS=("PL/pgSQL" "LISTEN/NOTIFY" "JSONB" "pg_trgm" "pgcrypto digest parity" "RLS / tenant isolation" "grants / role separation" "SECURITY DEFINER context" "TLS / FIPS" "SM crypto module (CCRC)")
CRITICAL_PATH=(startup_recovery deliver send jmap_email_get jmap_email_query jmap_email_set_create jmap_email_set_destroy jmap_mailbox_get set_message_location check_quota message_schedule apply_rules)

OUT_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check)
      [ $# -ge 2 ] || {
        echo "gen-xinchuang-doc: --check requires a directory" >&2
        exit 2
      }
      OUT_DIR="$2"
      shift 2
      ;;
    *)
      echo "usage: gen-xinchuang-doc.sh [--check DIR]" >&2
      exit 2
      ;;
  esac
done

die() {
  echo "gen-xinchuang-doc: ✗ $*" >&2
  exit 1
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/gen-xinchuang.XXXXXX")" || exit 1
trap 'rm -rf "$WORK"' EXIT

# ── live universe extraction (fail-closed, never bypassed) ──────────────────
# One line per declaration: `name<TAB>defining file basename`.
extract_universe() {
  local f count=0
  : >"$WORK/decls.tsv"
  for f in "$REDUCERS_DIR"/*.sql; do
    [ -f "$f" ] || continue
    count=$((count + 1))
    if ! awk -v file="$(basename "$f")" '
      /^[[:space:]]*CREATE (OR REPLACE )?FUNCTION[[:space:]]+/ {
        name = $0
        sub(/^[[:space:]]*CREATE (OR REPLACE )?FUNCTION[[:space:]]+/, "", name)
        sub(/\(.*/, "", name)
        gsub(/[[:space:]]/, "", name)
        if (name == "") {
          printf "unparsable CREATE FUNCTION declaration: %s:%d\n", file, FNR > "/dev/stderr"
          exit 1
        }
        print name "\t" file
      }' "$f" >>"$WORK/decls.tsv"; then
      die "reducer extraction failed (see the unparsable declaration above)."
    fi
  done
  [ "$count" -gt 0 ] || die "reducer extraction found zero .sql files under $REDUCERS_DIR — refusing to render a vacuous matrix."
  sort -u "$WORK/decls.tsv" >"$WORK/name_file_map.tsv"
  # Deduplicate the NAME universe independently of its (name,file) pairs
  # (r2.3): a name overloaded across two different files is still ONE unique
  # name — cutting the pair-mapped names without a second dedup counted it
  # twice and could emit duplicate inventory entries. name_map.tsv retains
  # the defining-file mapping (first sorted defining file per name).
  awk -F'\t' '!seen[$1]++' "$WORK/name_file_map.tsv" >"$WORK/name_map.tsv"
  cut -f1 "$WORK/name_map.tsv" >"$WORK/universe_names.txt"
  [ -s "$WORK/universe_names.txt" ] || die "reducer extraction yielded an empty function-name set — refusing to render a vacuous matrix."
  FILE_COUNT="$count"
  DECL_COUNT="$(wc -l <"$WORK/decls.tsv" | tr -d ' ')"
  UNIVERSE_COUNT="$(wc -l <"$WORK/universe_names.txt" | tr -d ' ')"
  # Overloaded names: declaration count > 1 (r2.3(3) — overload notes).
  cut -f1 "$WORK/decls.tsv" | sort | uniq -c | awk '$1 > 1 {print $2 "\t" $1}' | sort >"$WORK/overloads.tsv"
}

# ── files whose digest( usage is source-real (non-comment call sites) ───────
extract_digest_files() {
  local f
  : >"$WORK/digest_files.txt"
  for f in "$REDUCERS_DIR"/*.sql; do
    [ -f "$f" ] || continue
    # \bdigest( equivalent, portable: the call is not part of a longer name,
    # and commented-out examples are not call sites.
    if grep -E '([^A-Za-z0-9_]|^)digest\(' "$f" 2>/dev/null |
      grep -qvE '^[[:space:]]*--'; then
      basename "$f" >>"$WORK/digest_files.txt"
    fi
  done
  sort -u -o "$WORK/digest_files.txt" "$WORK/digest_files.txt"
  DIGEST_FILE_COUNT="$(wc -l <"$WORK/digest_files.txt" | tr -d ' ')"
  DIGEST_CALL_SITES="$(grep -hE '([^A-Za-z0-9_]|^)digest\(' "$REDUCERS_DIR"/*.sql 2>/dev/null | grep -cvE '^[[:space:]]*--')"
}

# ── canonical path resolution (symlink-escape containment) ───────────────────
# Prints the canonical absolute path of an EXISTING $1 with every symlink
# component resolved. Prefers `readlink -f` / `realpath`; the pure-bash
# fallback resolves component by component (so symlinked INTERMEDIATE
# directories are resolved too). An ABSOLUTE symlink target RESTARTS
# resolution at the target — the prefix accumulated so far is only the link's
# directory and is dropped, never folded into the result (folding it in once
# fabricated an apparently contained path like /<root>/docs/etc/hosts for a
# ref that really resolved to /etc/hosts — Astra L2-C5 r3); a RELATIVE target
# resolves against the link's directory. Loops fail CLOSED — a path that
# cannot be canonicalized can never be certified as contained.
#
# CERTIFICATION IS THE WALK ITSELF, ON THE ORIGINAL SEQUENCE (Astra L2-C5
# r6): the r4/r5 shape certified only the walk's FINISHED result, so a `..`
# could ERASE a component already observed to be invalid — a dangling link,
# a nonexistent intermediate, a file used as a directory — and the
# certification of the surviving path then fabricated a success (e.g.
# `docs/nope.md/../real.md` came back exit-0 for the existing
# `docs/real.md` while native canonicalization refuses it). The fallback
# therefore certifies every component the moment it is consumed, BEFORE any
# later `..` can discard it: a nonexistent component, a non-directory the
# walk must descend through, a `..` that would climb above the root, or a
# dangling splice target fails the whole canonicalization in-walk. `..`
# itself pops the physical stack — it can only ever drop components that
# already passed certification, so it can never erase an observed violation;
# a pop from a ONE-component (slash-free) stack empties it (native X/.. == /,
# Astra L2-C5 r7) so later components re-root at / instead of being certified
# against the wrong directory, and only a `..` already AT the empty root
# fails closed.
# The same original-sequence certification GATES the host `realpath` branch,
# which on some systems (FreeBSD/macOS) folds `..` lexically and would
# otherwise certify the surviving path of an erased violation; `readlink -f`
# resolves kernel-style and needs no gate. The finished result is still
# re-verified component by component (_canonical_path_verify) as
# defense-in-depth; it adds rejections only and can no longer mask anything.
canonical_path() { # $1 = existing path
  local p="$1" out walked
  if out="$(readlink -f -- "$p" 2>/dev/null)" && [ -n "$out" ]; then
    printf '%s\n' "$out"
    return 0
  fi
  if out="$(realpath -- "$p" 2>/dev/null)" && [ -n "$out" ]; then
    # GATE (Astra L2-C5 r6): a host realpath can fold `..` LEXICALLY
    # (FreeBSD/macOS do), erasing an invalid component a true walk would
    # have tripped over and certifying only the surviving path. Its result
    # is accepted only when the strict original-sequence walk succeeds and
    # agrees; anything else fails closed. readlink -f needs no gate — it
    # resolves kernel-style and refuses those shapes.
    walked="$(_canonical_path_bash "$p")" || return 1
    [ "$walked" = "$out" ] || return 1
    printf '%s\n' "$out"
    return 0
  fi
  _canonical_path_bash "$p"
}

_canonical_path_bash() { # $1 = absolute existing path
  local pending="$1" base="" comp target cand depth=0 result
  case "$pending" in
    /*) pending="${pending#/}" ;;
    *) return 1 ;;
  esac
  while [ -n "$pending" ]; do
    comp="${pending%%/*}"
    case "$pending" in
      */*) pending="${pending#*/}" ;;
      *) pending="" ;;
    esac
    case "$comp" in
      "" | ".") continue ;;
      "..")
        # `..` pops the PHYSICAL stack — it can only ever discard components
        # already certified at consumption time (below), so normalization can
        # never erase an observed violation (Astra L2-C5 r6). A pop from a
        # MULTI-component base drops the last component; a pop from a
        # ONE-component (slash-free) base EMPTIES the stack — native X/.. == /
        # (Astra L2-C5 r7: the r6 walker handled `*/*` and `""` but left a
        # slash-free base such as `Users` UNCHANGED, so every later component
        # was certified against the wrong directory). A `..` already AT the
        # empty root still fails CLOSED; native /.. == / is deliberately not
        # replicated — certification never certifies a walk that left the
        # root.
        case "$base" in
          */*) base="${base%/*}" ;;
          "") return 1 ;;
          *) base="" ;;
        esac
        continue
        ;;
    esac
    if [ -n "$base" ]; then cand="/$base/$comp"; else cand="/$comp"; fi
    if [ -L "$cand" ]; then
      depth=$((depth + 1))
      [ "$depth" -gt 40 ] && return 1
      target="$(readlink "$cand" 2>/dev/null)" || return 1
      case "$target" in
        # absolute target: the link's directory prefix must never survive
        # into the result — restart resolution at the target itself.
        /*) base="" pending="${target#/}/$pending" ;;
        # relative target: resolves against the link's directory ($base).
        *) pending="$target/$pending" ;;
      esac
      continue
    fi
    # IN-WALK CERTIFICATION (Astra L2-C5 r6): each component of the ORIGINAL
    # sequence is certified the moment it is consumed, before any later `..`
    # could erase it. A nonexistent component (including a dangling splice
    # target) or a non-directory the walk must descend through fails the
    # whole canonicalization HERE — normalization never gets to discard the
    # evidence and certify the surviving path.
    [ -e "$cand" ] || return 1
    if [ -n "$pending" ] && [ ! -d "$cand" ]; then return 1; fi
    if [ -n "$base" ]; then base="$base/$comp"; else base="$comp"; fi
  done
  result="/$base"
  _canonical_path_verify "$result" || return 1
  printf '%s\n' "$result"
}

# Defense-in-depth re-verification of the walk's finished result (Astra
# L2-C5 r5/r6): component-walk WITHOUT following any symlink. The load-
# bearing certification now happens IN the walk on the original component
# sequence (see _canonical_path_bash), so a `..` can no longer erase an
# observed violation before anything examines it; this independent pass
# remains as a belt-and-braces invariant over the fully resolved path —
# every component must EXIST, none may still be a symlink, and every
# non-final component must be a real directory. It adds rejections only.
_canonical_path_verify() { # $1 = the finished absolute result of the walk
  local rest="" comp="" prefix="/"
  case "$1" in
    /*) rest="${1#/}" ;;
    *) return 1 ;;
  esac
  [ -e "$1" ] || return 1
  while [ -n "$rest" ]; do
    comp="${rest%%/*}"
    case "$rest" in
      */*) rest="${rest#*/}" ;;
      *) rest="" ;;
    esac
    [ -n "$comp" ] || continue
    if [ -L "$prefix$comp" ] || { [ -n "$rest" ] && [ ! -d "$prefix$comp" ]; }; then
      return 1
    fi
    prefix="$prefix$comp/"
  done
  return 0
}

# The canonical root is a per-run constant: resolve once, then reuse.
CANONICAL_ROOT=""
_canonical_root() {
  if [ -z "$CANONICAL_ROOT" ]; then
    CANONICAL_ROOT="$(canonical_path "$ROOT")" || return 1
    [ -n "$CANONICAL_ROOT" ] || return 1
  fi
  printf '%s\n' "$CANONICAL_ROOT"
}

# ── evidence-ref resolver (r2.1(1)/(6), fail-closed) ─────────────────────────
# THE shared resolver for every evidence-bearing cell in BOTH artifacts
# (compatibility_matrix.csv engine cells and engine_capabilities.csv rows).
# A ref is `path[:line]`, repo-relative, with no `..` path component, and
# must resolve to an existing regular file STRICTLY INSIDE the canonical
# repo root. Directory targets (`pass@.`), traversal escapes
# (`pass@../../../etc/hosts`), and SYMLINK escapes are all rejected: the
# containment boundary is the CANONICAL root (ROOT itself may be reached
# through a symlinked directory, e.g. /tmp -> /private/tmp), and containment
# is enforced on the ref's fully resolved real path — a ref like
# `etc/localtime` whose real path lands outside the root never resolves,
# even though `[ -f "$ROOT/$ref" ]` would follow the link and succeed.
# Returns 0 only when the ref is canonically contained.
resolve_evidence_ref() { # $1 = ref (path[:line])
  local ref="$1" path rest comp real_root real_target
  path="$ref"
  if [[ "$ref" =~ ^(.+):[0-9]+$ ]]; then path="${BASH_REMATCH[1]}"; fi
  [ -n "$path" ] || return 1
  case "$path" in
    /*) return 1 ;;
  esac
  [[ "$path" =~ ^[A-Za-z0-9._/-]+$ ]] || return 1
  rest="$path"
  while [ -n "$rest" ]; do
    comp="${rest%%/*}"
    [ "$comp" = ".." ] && return 1
    [ "$rest" = "$comp" ] && break
    rest="${rest#*/}"
  done
  [ -f "$ROOT/$path" ] || return 1
  real_root="$(_canonical_root)" || return 1
  real_target="$(canonical_path "$ROOT/$path")" || return 1
  case "$real_target" in
    "$real_root"/*) return 0 ;;
    *) return 1 ;;
  esac
}

# ── engine_capabilities.csv structured status/evidence schema (r2.1) ─────────
# Parses one row's status cell + evidence column into the canonical pair in
# P_STATUS / P_EVIDENCE (P_PARSE_ERROR carries the reason on failure):
#   untested            the evidence column must be empty  -> (untested, "")
#   pass|partial|fail   the evidence column carries the ref -> (status, ref)
#   status@ref (inline) parsed into status + evidence; the evidence column
#                       must be empty or repeat the SAME ref — a conflicting
#                       second ref is rejected, never guessed.
parse_status_pair() { # $1 = status cell, $2 = evidence column
  P_STATUS="" P_EVIDENCE="" P_PARSE_ERROR=""
  local cell="$1" col="$2"
  if [ -z "$cell" ]; then
    P_PARSE_ERROR="empty status cell (must be pass|partial|fail|untested)"
    return 1
  fi
  if [ "$cell" = "untested" ]; then
    if [ -n "$col" ]; then
      P_PARSE_ERROR="untested must not carry an evidence ref (clear the evidence column)"
      return 1
    fi
    P_STATUS="untested"
    return 0
  fi
  case "$cell" in
    pass | partial | fail)
      if [ -z "$col" ]; then
        P_PARSE_ERROR="bare $cell requires an evidence ref in the evidence column"
        return 1
      fi
      P_STATUS="$cell" P_EVIDENCE="$col"
      return 0
      ;;
    pass@?* | partial@?* | fail@?*)
      P_STATUS="${cell%%@*}"
      P_EVIDENCE="${cell#*@}"
      if [ -n "$col" ] && [ "$col" != "$P_EVIDENCE" ]; then
        P_PARSE_ERROR="status cell and evidence column disagree (status ref $P_EVIDENCE vs evidence column $col)"
        return 1
      fi
      return 0
      ;;
    *)
      P_PARSE_ERROR="status $cell is outside the pass@|partial@|fail@|untested grammar"
      return 1
      ;;
  esac
}

# ── compatibility_matrix.csv: parse + (normal mode) row-source validation ───
load_matrix() {
  [ -r "$MATRIX_CSV" ] || die "compatibility matrix is missing or unreadable: $MATRIX_CSV"
  head -n 1 "$MATRIX_CSV" | grep -qxF "$MATRIX_HEADER" ||
    die "$MATRIX_CSV header drifted — want: $MATRIX_HEADER"
  awk -F, '
    NR > 1 && NF != 11 {
      printf "row %d (function %s): expected 11 comma-separated fields, found %d — notes must use ; not ,\n", NR, $1, NF
      bad = 1
    }
    NR > 1 && $0 ~ /"/ {
      printf "row %d (function %s): double quotes are not canonical — write plain ; -separated text\n", NR, $1
      bad = 1
    }
    NR > 1 && ($1 == "" || $2 == "") {
      printf "row %d: function and description cells must be non-empty\n", NR
      bad = 1
    }
    END { exit bad ? 1 : 0 }
  ' "$MATRIX_CSV" || die "compatibility_matrix.csv does not parse (see offending rows above)."
  tail -n +2 "$MATRIX_CSV" | cut -d, -f1 | sort >"$WORK/csv_names.txt"
  sort -u -o "$WORK/csv_names.uniq" "$WORK/csv_names.txt"
  CSV_ROW_COUNT="$(grep -c . < <(tail -n +2 "$MATRIX_CSV"))"
  CSV_NAME_COUNT="$(wc -l <"$WORK/csv_names.uniq" | tr -d ' ')"
  [ -n "$FIXTURE_MODE" ] && return 0
  # ── normal-mode row-source validation only from here ───────────────────────
  local dead dups n
  dead="$(comm -23 "$WORK/csv_names.uniq" "$WORK/universe_names.txt")"
  if [ -n "$dead" ]; then
    echo "compatibility_matrix.csv has row(s) resolving to no live reducer function:" >&2
    while IFS= read -r n; do echo "  dead row: $n" >&2; done <<<"$dead"
    die "remove the dead row(s) or restore the function."
  fi
  dups="$(uniq -d "$WORK/csv_names.txt")"
  if [ -n "$dups" ]; then
    echo "compatibility_matrix.csv has duplicate row(s) for live function(s):" >&2
    while IFS= read -r n; do echo "  duplicate: $n" >&2; done <<<"$dups"
    die "de-duplicate the matrix (representation is once-per-name)."
  fi
  # enum grammar on every engine cell (r2.1(1)). CSV engine columns are 3–9;
  # col[] is engine-indexed 1–7, so the diagnostic name is col[i - 2] —
  # naming the ACTUAL engine the offending cell belongs to.
  local badcells
  badcells="$(awk -F, '
    NR > 1 {
      for (i = 3; i <= 9; i++) {
        cell = $i
        if (cell == "untested") continue
        if (cell !~ /^(pass|partial|fail)@.+/) {
          printf "row %s engine %s: cell %s is outside the pass@|partial@|fail@|untested grammar\n", $1, col[i - 2], cell
          bad = 1
        }
      }
      if ($10 != "yes" && $10 != "no") {
        printf "row %s: uses_digest must be yes|no\n", $1
        bad = 1
      }
    }
    BEGIN { split("polardb opengauss gaussdb kingbase dameng oceanbase_pg oceanbase_oracle", col, " ") }
    END { exit bad ? 1 : 0 }
  ' "$MATRIX_CSV")" || {
    printf '%s\n' "$badcells" >&2
    die "compatibility_matrix.csv cell grammar violations."
  }
  # evidence refs must resolve inside the repo through the shared resolver
  # (r2.1(6)): repo-relative file path[:line], no `..` escapes, no dirs.
  badcells="$(tail -n +2 "$MATRIX_CSV" | awk -F, '
    {
      for (i = 3; i <= 9; i++) {
        cell = $i
        if (cell == "untested") continue
        ref = cell
        sub(/^[^@]*@/, "", ref)
        print $1 "\t" col[i - 2] "\t" ref
      }
    }
    BEGIN { split("polardb opengauss gaussdb kingbase dameng oceanbase_pg oceanbase_oracle", col, " ") }
  ' | while IFS=$'\t' read -r fn eng ref; do
    if ! resolve_evidence_ref "$ref"; then
      echo "$fn engine $eng: evidence ref $ref does not resolve inside the repo"
    fi
  done)"
  if [ -n "$badcells" ]; then
    echo "compatibility_matrix.csv evidence refs that do not resolve:" >&2
    printf '%s\n' "$badcells" >&2
    die "attach a resolvable repo-relative path[:line] or drop the cell to untested."
  fi
  # critical-path names must be live and CSV-covered (normal mode)
  local cpname
  for cpname in "${CRITICAL_PATH[@]}"; do
    grep -qxF "$cpname" "$WORK/universe_names.txt" ||
      die "critical-path function $cpname no longer resolves to a live reducer definition."
    grep -qxF "$cpname" "$WORK/csv_names.uniq" ||
      die "critical-path function $cpname has no compatibility_matrix.csv row to render a status from."
  done
  return 0
}

# ── engine_capabilities.csv: parse + (normal mode) grammar + completeness ───
load_caps() {
  [ -r "$CAPS_CSV" ] || die "engine_capabilities.csv is missing or unreadable: $CAPS_CSV"
  head -n 1 "$CAPS_CSV" | grep -qxF "$CAPS_HEADER" ||
    die "$CAPS_CSV header drifted — want: $CAPS_HEADER"
  awk -F, '
    NR > 1 && NF != 4 {
      printf "row %d: expected 4 fields (engine,dimension,status,evidence), found %d\n", NR, NF
      bad = 1
    }
    NR > 1 && $0 ~ /"/ {
      printf "row %d: double quotes are not canonical\n", NR
      bad = 1
    }
    END { exit bad ? 1 : 0 }
  ' "$CAPS_CSV" || die "engine_capabilities.csv does not parse."
  tail -n +2 "$CAPS_CSV" >"$WORK/caps_rows.csv"
  [ -n "$FIXTURE_MODE" ] && return 0
  # ── normal-mode validation ──────────────────────────────────────────────────
  # One pass over EVERY capability row: unknown engine/dimension, the
  # structured status/evidence schema (parse_status_pair), and the shared
  # fail-closed evidence resolver. No row escapes the scan (r2.1(6)).
  local eng dim status evidence bad=""
  while IFS=$'\t' read -r eng dim status evidence; do
    case " ${ENGINES[*]} " in
      *" $eng "*) ;;
      *)
        echo "engine_capabilities.csv row $eng,$dim: unknown engine $eng" >&2
        bad=1
        ;;
    esac
    case " ${DIMENSIONS[*]} " in
      *" $dim "*) ;;
      *)
        echo "engine_capabilities.csv row $eng,$dim: unknown dimension $dim" >&2
        bad=1
        ;;
    esac
    if parse_status_pair "$status" "$evidence"; then
      if [ "$P_STATUS" != "untested" ] && ! resolve_evidence_ref "$P_EVIDENCE"; then
        echo "engine_capabilities.csv row $eng,$dim: evidence ref $P_EVIDENCE does not resolve inside the repo (repo-relative path[:line] to a file)" >&2
        bad=1
      fi
    else
      echo "engine_capabilities.csv row $eng,$dim: $P_PARSE_ERROR" >&2
      bad=1
    fi
  done < <(awk -F, '{OFS="\t"; print $1, $2, $3, $4}' "$WORK/caps_rows.csv")
  [ -z "$bad" ] || die "engine_capabilities.csv grammar violations (see rows above)."
  # completeness: exactly one row per engine x dimension, gaussdb included
  # (r2.1(2)/(6)) — never a missing engine row.
  cut -d, -f1,2 "$WORK/caps_rows.csv" | sort >"$WORK/caps_pairs.txt"
  local dups expected
  dups="$(uniq -d "$WORK/caps_pairs.txt")"
  [ -z "$dups" ] || die "engine_capabilities.csv duplicate engine,dimension row(s): $(echo "$dups" | tr '\n' ' ')"
  : >"$WORK/caps_expected.txt"
  for eng in "${ENGINES[@]}"; do
    for dim in "${DIMENSIONS[@]}"; do
      echo "$eng,$dim" >>"$WORK/caps_expected.txt"
    done
  done
  sort -o "$WORK/caps_expected.txt" "$WORK/caps_expected.txt"
  expected="$(comm -23 "$WORK/caps_expected.txt" "$WORK/caps_pairs.txt")"
  if [ -n "$expected" ]; then
    echo "engine_capabilities.csv is missing engine,dimension row(s) (every engine x dimension must be present):" >&2
    printf '%s\n' "$expected" >&2
    die "add the missing row(s) as untested — never omit a cell (r2.1(6))."
  fi
  return 0
}

# ── canonical CSV render: only uses_digest is recomputed ────────────────────
render_matrix_csv() { # $1 = destination
  awk -F, -v dfile="$WORK/digest_files.txt" -v mfile="$WORK/name_map.tsv" '
    FILENAME == dfile { dig[$1] = 1; next }
    FILENAME == mfile { n = split($0, a, "\t"); fmap[a[1]] = a[2]; next }
    FNR == 1 { print; next }
    { ud = "no"; if (($1 in fmap) && (fmap[$1] in dig)) ud = "yes"; $10 = ud; print }
  ' OFS="," "$WORK/digest_files.txt" "$WORK/name_map.tsv" "$MATRIX_CSV" >"$1"
}

# ── canonical complement inventory render (r2.3) ─────────────────────────────
render_inventory() { # $1 = destination
  comm -23 "$WORK/universe_names.txt" "$WORK/csv_names.uniq" >"$WORK/unatt_names.txt"
  {
    echo "function,defined_in"
    # name_map.tsv carries exactly one defining file per unique name (the
    # first sorted one for a cross-file overload), so the inventory can
    # never gain duplicate entries for an overloaded name (r2.3).
    awk -F'\t' '
      NR == FNR { n = split($0, a, "\t"); fmap[a[1]] = a[2]; next }
      { print $0 "," fmap[$1] }
    ' "$WORK/name_map.tsv" "$WORK/unatt_names.txt"
  } >"$1"
}

# ── README generated-block render ────────────────────────────────────────────
engine_attested_count() { # $1 = engine id -> rows whose cell is non-untested
  local eng="$1" idx=0 i
  for i in "${!ENGINES[@]}"; do
    if [ "${ENGINES[$i]}" = "$eng" ]; then
      idx=$((i + 3))
      break
    fi
  done
  awk -F, -v c="$idx" 'FNR > 1 && $c != "untested" { x++ } END { print x + 0 }' "$MATRIX_CSV"
}

matrix_cell() { # $1 function, $2 engine id -> CSV cell (as-is), untested if absent
  local fn="$1" eng="$2" idx=0 i cell
  for i in "${!ENGINES[@]}"; do
    if [ "${ENGINES[$i]}" = "$eng" ]; then
      idx=$((i + 3))
      break
    fi
  done
  cell="$(awk -F, -v n="$fn" -v c="$idx" '$1 == n { print $c; found = 1 } END { if (!found) print "untested" }' "$MATRIX_CSV" | head -n 1)"
  [ -n "$cell" ] || cell="untested"
  printf '%s' "$cell"
}

render_block() { # $1 = destination
  local out="$1" eng dim i name cell status evidence
  local attested_any digest_rows unattested_count col_attested total_families cov cnt
  attested_any="$(awk -F, 'FNR > 1 && ($3 != "untested" || $4 != "untested" || $5 != "untested" || $6 != "untested" || $7 != "untested" || $8 != "untested" || $9 != "untested") { print $1 }' "$MATRIX_CSV" | sort -u | wc -l | tr -d ' ')"
  digest_rows="$(awk -F, -v dfile="$WORK/digest_files.txt" -v mfile="$WORK/name_map.tsv" '
    FILENAME == dfile { dig[$1] = 1; next }
    FILENAME == mfile { n = split($0, a, "\t"); fmap[a[1]] = a[2]; next }
    FNR > 1 && ($1 in fmap) && (fmap[$1] in dig) { c++ }
    END { print c + 0 }
  ' "$WORK/digest_files.txt" "$WORK/name_map.tsv" "$MATRIX_CSV")"
  unattested_count=$((UNIVERSE_COUNT - CSV_NAME_COUNT))

  {
    echo "## Engine capabilities"
    echo
    echo "Sole source: \`engine_capabilities.csv\` (engine x dimension). Status enum everywhere on this page: \`pass | partial | fail | untested\` — the first three require a resolvable repo-relative evidence ref, rendered as \`status@ref\`. A cell with no evidence reads \`untested\`: it is never omitted and never guessed (representation is not attestation)."
    echo
    echo "Engines: polardb = PolarDB for PostgreSQL · opengauss = openGauss · gaussdb = GaussDB · kingbase = KingbaseES · dameng = DM8/Dameng · oceanbase_pg = OceanBase (PG mode) · oceanbase_oracle = OceanBase (Oracle mode)."
    echo
    printf '| Dimension |'
    for eng in "${ENGINES[@]}"; do printf ' %s |' "$eng"; done
    echo
    printf '|---|'
    for eng in "${ENGINES[@]}"; do printf -- '---|'; done
    echo
    for i in "${!DIMENSIONS[@]}"; do
      dim="${DIMENSIONS[$i]}"
      printf '| %s (%s) |' "$dim" "${DIM_LABELS[$i]}"
      for eng in "${ENGINES[@]}"; do
        # Validation and rendering share parse_status_pair: a (status,
        # evidence) pair the validator accepted renders as `status@evidence`
        # — an accepted cell can never silently degrade to `untested`.
        cell="untested"
        IFS=$'\t' read -r status evidence < <(
          awk -F, -v e="$eng" -v d="$dim" '$1 == e && $2 == d { print $3 "\t" $4; exit }' "$WORK/caps_rows.csv"
        )
        if parse_status_pair "$status" "$evidence" &&
          [ "$P_STATUS" != "untested" ] && [ -n "$P_EVIDENCE" ]; then
          cell="${P_STATUS}@${P_EVIDENCE}"
        fi
        # unsupported cell: render untested, never omit
        printf ' %s |' "$cell"
      done
      echo
    done
    echo
    echo "## Functional coverage"
    echo
    echo "Counting unit: the function NAME. Live universe extracted from \`mailserver/sql/reducers/*.sql\`:"
    echo
    echo "- Reducer files: $FILE_COUNT · declarations: $DECL_COUNT · unique names: $UNIVERSE_COUNT"
    echo "- Represented in \`compatibility_matrix.csv\`: $CSV_NAME_COUNT names ($CSV_ROW_COUNT rows) — representation is not attestation"
    echo "- Names with any evidence-bearing cell (attested anywhere): $attested_any"
    echo "- Canonical complement (no CSV row): $unattested_count → \`unattested_functions.csv\`"
    echo
    echo "Per-engine attestation against the full $UNIVERSE_COUNT-name universe (a name is attested-for-engine iff its cell is non-\`untested\`):"
    echo
    echo "| Engine | Attested | Not attested |"
    echo "|---|---|---|"
    for eng in "${ENGINES[@]}"; do
      col_attested="$(engine_attested_count "$eng")"
      printf '| %s | %s | %s |\n' "$eng" "$col_attested" "$((UNIVERSE_COUNT - col_attested))"
    done
    echo
    echo "\`uses_digest\` is SOURCE-DERIVED USAGE — a non-comment \`digest(\` call exists in the defining file ($DIGEST_FILE_COUNT files / $DIGEST_CALL_SITES call sites repo-wide). It is never a parity attestation; pgcrypto parity is attested (or not) per engine via \`pgcrypto_digest_parity\` above. Covered rows with \`uses_digest\`: $digest_rows of $CSV_ROW_COUNT."
    echo
    if [ -s "$WORK/overloads.tsv" ]; then
      echo "Overloaded names (coverage is name-level and never attests every overload):"
      echo
      while IFS=$'\t' read -r name cnt; do
        cov="unattested"
        grep -qxF "$name" "$WORK/csv_names.uniq" && cov="covered in compatibility_matrix.csv"
        echo "- \`$name\` — $cnt declarations — $cov"
      done <"$WORK/overloads.tsv"
      echo
    fi
    echo "## Certification critical path"
    echo
    echo "The reducers below are the certification critical path for the primary combination (Kunpeng x Kylin x PolarDB for PostgreSQL). Membership is policy, NOT evidence: per-name, per-engine status renders from \`compatibility_matrix.csv\`, and every member reads \`untested\` until an evidence-bearing cell says otherwise."
    echo
    printf '| Function |'
    for eng in "${ENGINES[@]}"; do printf ' %s |' "$eng"; done
    echo
    printf '|---|'
    for eng in "${ENGINES[@]}"; do printf -- '---|'; done
    echo
    for name in "${CRITICAL_PATH[@]}"; do
      printf "| \`%s\` |" "$name"
      for eng in "${ENGINES[@]}"; do
        cell="$(matrix_cell "$name" "$eng")"
        printf ' %s |' "$cell"
      done
      echo
    done
    echo
    echo "## Unattested families"
    echo
    echo "\`unattested_functions.csv\` is the exact canonical complement of live CSV coverage: every live function name with no CSV row, with its defining file. Families aggregate by defining-file prefix. This list makes no compatibility claim — these are the functions any per-engine certification still has to cover."
    echo
    echo "| Family | Unattested names |"
    echo "|---|---|"
    total_families=0
    while IFS=$'\t' read -r family cnt; do
      printf '| %s | %s |\n' "$family" "$cnt"
      total_families=$((total_families + 1))
    done < <(awk -F, 'FNR > 1 { fam = $2; sub(/\.sql$/, "", fam); sub(/_.*$/, "", fam); cnt[fam]++ } END { for (f in cnt) printf "%s\t%d\n", f, cnt[f] }' "$WORK/unattested_functions.csv" | sort)
    printf '| Total | %s across %s families |\n' "$unattested_count" "$total_families"
    echo
  } >"$out"
}

# ── README assembly (in-place mode) ──────────────────────────────────────────
replace_readme_block() {
  local begin_count end_count
  begin_count="$(grep -cF '<!-- BEGIN GENERATED: xinchuang-matrix -->' "$README")"
  end_count="$(grep -cxF '<!-- END GENERATED -->' "$README")"
  [ "$begin_count" = "1" ] || die "$README must contain exactly one '<!-- BEGIN GENERATED: xinchuang-matrix -->' sentinel line (found $begin_count)."
  [ "$end_count" = "1" ] || die "$README must contain exactly one '<!-- END GENERATED -->' sentinel line (found $end_count)."
  awk -v block="$WORK/README.block" '
    /<!-- BEGIN GENERATED: xinchuang-matrix -->/ {
      print
      while ((getline line < block) > 0) print line
      skip = 1
      next
    }
    skip && /<!-- END GENERATED -->/ { skip = 0; print; next }
    skip { next }
    { print }
  ' "$README" >"$WORK/README.new"
  mv "$WORK/README.new" "$README"
}

# ── main ─────────────────────────────────────────────────────────────────────
extract_universe
extract_digest_files
load_matrix
load_caps

render_matrix_csv "$WORK/compatibility_matrix.csv"
render_inventory "$WORK/unattested_functions.csv"
render_block "$WORK/README.block"

if [ -n "$OUT_DIR" ]; then
  mkdir -p "$OUT_DIR"
  cp "$WORK/README.block" "$OUT_DIR/README.block"
  cp "$WORK/compatibility_matrix.csv" "$OUT_DIR/compatibility_matrix.csv"
  cp "$WORK/unattested_functions.csv" "$OUT_DIR/unattested_functions.csv"
  echo "gen-xinchuang-doc: rendered matrix artifacts into $OUT_DIR"
  exit 0
fi

cp "$WORK/compatibility_matrix.csv" "$MATRIX_CSV"
cp "$WORK/unattested_functions.csv" "$INVENTORY"
replace_readme_block
echo "gen-xinchuang-doc: regenerated $MATRIX_CSV"
echo "gen-xinchuang-doc: regenerated $INVENTORY"
echo "gen-xinchuang-doc: regenerated the generated block in $README"
