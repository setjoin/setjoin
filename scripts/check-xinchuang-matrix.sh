#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-xinchuang-matrix.sh — the Xinchuang certification-matrix tripwire.
#
# mailserver/sql/xinchuang/ attests per-engine reducer compatibility, but its
# artifacts used to be hand-maintained in two directions at once: the README
# claimed coverage the CSV never carried (and a "108/108" completeness claim
# with a false denominator), while the CSV carried rows for functions that no
# longer exist. This guard makes the CSVs, the README's generated block, and
# the live reducer sources ONE consistent set, fail-closed (r1 WP-2 + binding
# r2 amendment):
#
#   1. Inputs exist and parse; sentinels present exactly once.
#   2. Engine cells / capability statuses sit in the r2.1 enum —
#      `pass|partial|fail|untested` — and every non-`untested` cell carries a
#      repo-relative path[:line] evidence ref that RESOLVES inside the repo
#      through one shared fail-closed resolver: no `..` traversal escapes,
#      regular-file targets only (directories like `pass@.` fail), and no
#      symlink escapes — the ref's fully resolved real path must sit strictly
#      under the CANONICAL repo root, so a link pointing outside the repo
#      never counts as evidence. EVERY capability row is scanned — no row
#      skips the evidence check. engine_capabilities.csv must carry exactly
#      one row per engine x dimension (gaussdb included; a missing engine row
#      fails).
#   3. SET CONSISTENCY (the mutation-stubbed step): every CSV row resolves to
#      a live `CREATE FUNCTION` in mailserver/sql/reducers/; no duplicate
#      rows; and unattested_functions.csv is the EXACT canonical complement —
#      disjoint from the CSV, duplicate-free, live, universe-covering, and
#      byte-identical to a regeneration (r2.3).
#   4. Byte-identical regeneration: the README generated block and the CSV
#      canonical form must equal the generator's output (regen-diff).
#   5. Prose outside the sentinels asserts NO engine compatibility and NO
#      numeric literals — verdicts and counts live only in generated output
#      (r2.2). Verdict-bearing phrases are named line-by-line.
#
# Counting unit is the function NAME (r2.3(3)); declaration counts and
# overload notes are generated, never hand-asserted.
#
# Self-test (repo standard: check-openapi-visibility.sh pattern + the r2.4
# mutation contract): fixtures are independent, non-empty derivatives of the
# real artifacts in a mktemp dir, each asserted to carry its planted content
# before the guard runs; every planted-drift case must FIRE and `grep -qF`
# NAME the planted content (no bare nonzero-exit acceptance); row-set
# fixtures are OTHERWISE CONSISTENT triples rendered by the real generator in
# fixture mode, so stubbing only check_set_consistency makes the guard ACCEPT
# them — rejections attributable to that check alone. A full self-test run
# under the mutation must FAIL at that expected assertion.
#   XINCHUANG_MATRIX_SELFTEST_SKIP_MUTATION keeps the mutated copy from
#   re-running this block (mirrors OPENAPI_VIS_SELFTEST_SKIP_MUTATION).
#
# Environment overrides (self-test fixtures only): XINCHUANG_MATRIX_CSV,
#   XINCHUANG_CAPS_CSV, XINCHUANG_README, XINCHUANG_INVENTORY,
#   XINCHUANG_REDUCERS_DIR, XINCHUANG_ROOT.
#
# Usage:
#   scripts/check-xinchuang-matrix.sh              # the guard (exit 1 on drift)
#   scripts/check-xinchuang-matrix.sh --self-test  # prove the guard FIRES
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
export LC_ALL=C

ROOT="${XINCHUANG_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
GEN="$ROOT/scripts/gen-xinchuang-doc.sh"
REDUCERS_DIR="${XINCHUANG_REDUCERS_DIR:-$ROOT/mailserver/sql/reducers}"
MATRIX_CSV="${XINCHUANG_MATRIX_CSV:-$ROOT/mailserver/sql/xinchuang/compatibility_matrix.csv}"
CAPS_CSV="${XINCHUANG_CAPS_CSV:-$ROOT/mailserver/sql/xinchuang/engine_capabilities.csv}"
README="${XINCHUANG_README:-$ROOT/mailserver/sql/xinchuang/README.md}"
INVENTORY="${XINCHUANG_INVENTORY:-$ROOT/mailserver/sql/xinchuang/unattested_functions.csv}"

MATRIX_HEADER="function,description,polardb,opengauss,gaussdb,kingbase,dameng,oceanbase_pg,oceanbase_oracle,uses_digest,notes"
CAPS_HEADER="engine,dimension,status,evidence"
ENGINES=(polardb opengauss gaussdb kingbase dameng oceanbase_pg oceanbase_oracle)
DIMENSIONS=(plpgsql listen_notify jsonb pg_trgm pgcrypto_digest_parity rls_semantics grants_role_separation security_definer tls_fips sm_crypto_module)
BEGIN_SENTINEL='<!-- BEGIN GENERATED: xinchuang-matrix -->'
END_SENTINEL='<!-- END GENERATED -->'

WORK="$(mktemp -d "${TMPDIR:-/tmp}/check-xinchuang-matrix.XXXXXX")" || exit 1
trap 'rm -rf "$WORK"' EXIT

# ── canonical path resolution (symlink-escape containment; mirrors
#    gen-xinchuang-doc.sh) ─────────────────────────────────────────────────────
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

# ── evidence-ref resolver (fail-closed; mirrors gen-xinchuang-doc.sh) ────────
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

# ── engine_capabilities.csv structured status/evidence schema (r2.1; mirrors
#    gen-xinchuang-doc.sh so validation and rendering can never disagree) ────
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

# ── live universe extraction (fail-closed; mirrors gen-xinchuang-doc.sh) ────
extract_universe() {
  local f count=0
  : >"$WORK/universe_names.txt"
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
      }' "$f" >>"$WORK/universe_decls.tsv"; then
      echo "  ✗ reducer extraction failed (see the unparsable declaration above)." >&2
      return 1
    fi
  done
  if [ "$count" -eq 0 ]; then
    echo "  ✗ reducer extraction found zero .sql files under $REDUCERS_DIR — refusing a vacuous matrix check." >&2
    return 1
  fi
  cut -f1 "$WORK/universe_decls.tsv" | sort -u >"$WORK/universe_names.txt"
  if [ ! -s "$WORK/universe_names.txt" ]; then
    echo "  ✗ reducer extraction yielded an empty function-name set — refusing a vacuous matrix check." >&2
    return 1
  fi
  return 0
}

# ── the README's generated block (between the sentinels) ────────────────────
extract_block() {
  awk -v b="$BEGIN_SENTINEL" -v e="$END_SENTINEL" '
    $0 == b { inblk = 1; next }
    $0 == e { inblk = 0; next }
    inblk { print }
  ' "$README"
}

# ── CSV row checks: enum grammar, evidence resolvability, canonical form ────
check_matrix_rows() {
  local r=0 out first_diff
  if ! head -n 1 "$MATRIX_CSV" | grep -qxF "$MATRIX_HEADER"; then
    echo "  ✗ $MATRIX_CSV header drifted — want: $MATRIX_HEADER" >&2
    r=1
  fi
  out="$(awk -F, '
    NR > 1 {
      if (NF != 11) {
        printf "  ✗ compatibility_matrix.csv row %d (function %s): expected 11 comma-separated fields, found %d\n", NR, $1, NF
        bad = 1
      }
      if ($0 ~ /"/) {
        printf "  ✗ compatibility_matrix.csv row %d (function %s): double quotes are not canonical\n", NR, $1
        bad = 1
      }
      if ($1 == "" || $2 == "") {
        printf "  ✗ compatibility_matrix.csv row %d: function and description cells must be non-empty\n", NR
        bad = 1
      }
      if ($10 != "yes" && $10 != "no") {
        printf "  ✗ compatibility_matrix.csv row %s: uses_digest must be yes|no\n", $1
        bad = 1
      }
    }
    END { exit bad ? 1 : 0 }
  ' "$MATRIX_CSV")" || {
    printf '%s\n' "$out" >&2
    r=1
  }
  # Engine-cell grammar + evidence resolvability. CSV engine columns are
  # 3–9 while col[] is engine-indexed 1–7, so diagnostics use col[i - 2] —
  # the ACTUAL engine the offending cell belongs to, never a shifted name.
  out="$(awk -F, '
    NR > 1 {
      for (i = 3; i <= 9; i++) {
        cell = $i
        if (cell == "untested") continue
        if (cell !~ /^(pass|partial|fail)@.+/) {
          printf "  ✗ compatibility_matrix.csv row %s engine %s: cell %s is outside the pass@|partial@|fail@|untested grammar\n", $1, col[i - 2], cell
          bad = 1
        }
      }
    }
    BEGIN { split("polardb opengauss gaussdb kingbase dameng oceanbase_pg oceanbase_oracle", col, " ") }
    END { exit bad ? 1 : 0 }
  ' "$MATRIX_CSV")" || {
    printf '%s\n' "$out" >&2
    r=1
  }
  out="$(tail -n +2 "$MATRIX_CSV" | awk -F, '
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
  ' | while IFS="$(printf '\t')" read -r fn eng ref; do
    if ! resolve_evidence_ref "$ref"; then
      echo "  ✗ compatibility_matrix.csv row $fn engine $eng: evidence ref $ref does not resolve inside the repo"
    fi
  done)"
  if [ -n "$out" ]; then
    printf '%s\n' "$out" >&2
    r=1
  fi
  # canonical form: committed CSV must equal the regeneration (the generator
  # recomputes ONLY uses_digest; verdict cells pass through unchanged).
  if ! cmp -s "$MATRIX_CSV" "$WORK/out/compatibility_matrix.csv"; then
    first_diff="$(awk -F, '
      NR == FNR { committed[FNR] = $0; n = FNR; next }
      FNR > n || committed[FNR] != $0 {
        split(committed[FNR], c, ",")
        printf "row %d (%s)", FNR, c[1]
        exit 1
      }
    ' "$MATRIX_CSV" "$WORK/out/compatibility_matrix.csv")"
    echo "  ✗ compatibility_matrix.csv drifted from the regenerated canonical form (uses_digest is source-derived usage) — run scripts/gen-xinchuang-doc.sh; first drift at ${first_diff:-end-of-file}." >&2
    r=1
  fi
  return "$r"
}

# ── engine_capabilities.csv: grammar + evidence + engine x dimension set ────
check_caps() {
  local r=0 eng dim status evidence bad=""
  if ! head -n 1 "$CAPS_CSV" | grep -qxF "$CAPS_HEADER"; then
    echo "  ✗ $CAPS_CSV header drifted — want: $CAPS_HEADER" >&2
    r=1
  fi
  # One pass over EVERY capability row (awk NR > 1 skips ONLY the header —
  # never combine a header strip with FNR > 1, which used to let the first
  # capability row escape the evidence scan): unknown engine/dimension, the
  # structured status/evidence schema (parse_status_pair), and the shared
  # fail-closed evidence resolver (r2.1(6)).
  while IFS="$(printf '\t')" read -r eng dim status evidence; do
    case " ${ENGINES[*]} " in
      *" $eng "*) ;;
      *)
        echo "  ✗ engine_capabilities.csv row $eng,$dim: unknown engine $eng" >&2
        bad=1
        ;;
    esac
    case " ${DIMENSIONS[*]} " in
      *" $dim "*) ;;
      *)
        echo "  ✗ engine_capabilities.csv row $eng,$dim: unknown dimension $dim" >&2
        bad=1
        ;;
    esac
    if parse_status_pair "$status" "$evidence"; then
      if [ "$P_STATUS" != "untested" ] && ! resolve_evidence_ref "$P_EVIDENCE"; then
        echo "  ✗ engine_capabilities.csv row $eng,$dim: evidence ref $P_EVIDENCE does not resolve inside the repo" >&2
        bad=1
      fi
    else
      echo "  ✗ engine_capabilities.csv row $eng,$dim: $P_PARSE_ERROR" >&2
      bad=1
    fi
  done < <(awk -F, 'NR > 1 {OFS="\t"; print $1, $2, $3, $4}' "$CAPS_CSV")
  [ -z "$bad" ] || r=1
  # completeness: exactly one row per engine x dimension, gaussdb included.
  cut -d, -f1,2 "$CAPS_CSV" | tail -n +2 | sort >"$WORK/caps_pairs.txt"
  local dups expected
  dups="$(uniq -d "$WORK/caps_pairs.txt")"
  if [ -n "$dups" ]; then
    echo "  ✗ engine_capabilities.csv duplicate engine,dimension row(s): $(echo "$dups" | tr '\n' ' ')" >&2
    r=1
  fi
  : >"$WORK/caps_expected.txt"
  for eng in "${ENGINES[@]}"; do
    for dim in "${DIMENSIONS[@]}"; do
      echo "$eng,$dim" >>"$WORK/caps_expected.txt"
    done
  done
  sort -o "$WORK/caps_expected.txt" "$WORK/caps_expected.txt"
  expected="$(comm -23 "$WORK/caps_expected.txt" "$WORK/caps_pairs.txt")"
  if [ -n "$expected" ]; then
    echo "  ✗ engine_capabilities.csv is missing engine,dimension row(s) (every engine x dimension must be present, gaussdb included):" >&2
    printf '%s\n' "$expected" | sed 's/^/      /' >&2
    r=1
  fi
  return "$r"
}

# ── SET CONSISTENCY (r2.3) — the mutation-stubbed step ───────────────────────
# CSV rows live + unique; the committed inventory is the EXACT canonical
# complement inventory = live_names \ csv_live_names: disjoint from the CSV,
# duplicate-free, live, universe-covering, byte-identical to regeneration.
emit_named() { # $1 = message prefix ending right before the name; names on stdin
  local n total=0
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    total=$((total + 1))
    [ "$total" -le 5 ] && echo "  ✗ $1$n" >&2
  done
  if [ "$total" -gt 5 ]; then
    echo "  ✗ $1…and $((total - 5)) more" >&2
  fi
  # return 0 when there was nothing to report, 1 when violations were emitted
  [ "$total" -eq 0 ]
}

check_set_consistency() {
  local r=0 names
  # (1) CSV liveness — dead rows named
  names="$(tail -n +2 "$MATRIX_CSV" | cut -d, -f1 | sort -u | comm -23 - "$WORK/universe_names.txt")"
  emit_named "compatibility_matrix.csv dead row: " <<<"$names" || r=1
  # (2) CSV uniqueness — duplicates of LIVE names named
  names="$(tail -n +2 "$MATRIX_CSV" | cut -d, -f1 | sort | uniq -d)"
  if [ -n "$names" ]; then
    echo "  ✗ compatibility_matrix.csv duplicate function row(s): $(echo "$names" | tr '\n' ' ')" >&2
    r=1
  fi
  # (3) inventory shape + uniqueness
  if ! head -n 1 "$INVENTORY" | grep -qxF 'function,defined_in'; then
    echo "  ✗ $INVENTORY header drifted — want: function,defined_in" >&2
    r=1
  fi
  names="$(tail -n +2 "$INVENTORY" | cut -d, -f1 | sort | uniq -d)"
  if [ -n "$names" ]; then
    echo "  ✗ unattested_functions.csv duplicate inventory entry/entries: $(echo "$names" | tr '\n' ' ')" >&2
    r=1
  fi
  tail -n +2 "$INVENTORY" | cut -d, -f1 | sort >"$WORK/inv_names.txt"
  # (4) disjointness — a name in BOTH corrupts the attested/unattested split
  names="$(comm -12 "$WORK/csv_names.uniq" "$WORK/inv_names.txt")"
  emit_named "name present in BOTH compatibility_matrix.csv and unattested_functions.csv: " <<<"$names" || r=1
  # (5) inventory liveness — dead inventory entries named
  names="$(comm -23 "$WORK/inv_names.txt" "$WORK/universe_names.txt")"
  emit_named "unattested_functions.csv dead inventory entry: " <<<"$names" || r=1
  # (6) complement exactness — a live name in NEITHER corrupts the split
  sort -u "$WORK/csv_names.uniq" "$WORK/inv_names.txt" >"$WORK/union_names.txt"
  names="$(comm -23 "$WORK/universe_names.txt" "$WORK/union_names.txt")"
  emit_named "name present in NEITHER compatibility_matrix.csv nor unattested_functions.csv: " <<<"$names" || r=1
  # (7) regeneration comparison — the committed inventory must be the
  # byte-identical canonical complement
  if ! cmp -s "$INVENTORY" "$WORK/out/unattested_functions.csv"; then
    echo "  ✗ unattested_functions.csv is not the canonical complement of the matrix — regeneration differs; run scripts/gen-xinchuang-doc.sh" >&2
    r=1
  fi
  return "$r"
}

# ── prose contract (r2.2): no compatibility verdicts, no numbers, outside ───
check_prose() {
  local r=0 hit
  awk -v b="$BEGIN_SENTINEL" -v e="$END_SENTINEL" '
    $0 == b { inblk = 1; print NR "\t" $0; next }
    $0 == e { inblk = 0; print NR "\t" $0; next }
    inblk { next }
    { print NR "\t" $0 }
  ' "$README" >"$WORK/prose.txt"
  hit="$(grep -inE 'works? as-is|unmodified|no translation needed|all pass|all reducers|reducers pass|fully compatible|native|zero[- ]migration' "$WORK/prose.txt")"
  if [ -n "$hit" ]; then
    while IFS= read -r line; do
      echo "  ✗ README prose carries a verdict-bearing compatibility phrase outside the generated block: $line" >&2
    done <<<"$hit"
    r=1
  fi
  hit="$(awk -F'\t' '$2 ~ /[0-9][0-9]/ { print }' "$WORK/prose.txt")"
  if [ -n "$hit" ]; then
    while IFS= read -r line; do
      echo "  ✗ README prose carries a numeric literal (counts and coverage belong to the generated block): $line" >&2
    done <<<"$hit"
    r=1
  fi
  return "$r"
}

run_guard() {
  local rc=0 f begin_count end_count
  # ── fail-closed inputs ──────────────────────────────────────────────────────
  for f in "$MATRIX_CSV" "$CAPS_CSV" "$README" "$INVENTORY"; do
    if [ ! -r "$f" ]; then
      echo "  ✗ missing/unreadable xinchuang matrix input: $f" >&2
      rc=1
    fi
  done
  [ "$rc" -eq 0 ] || return 1
  begin_count="$(grep -cxF "$BEGIN_SENTINEL" "$README")"
  end_count="$(grep -cxF "$END_SENTINEL" "$README")"
  if [ "$begin_count" != "1" ] || [ "$end_count" != "1" ]; then
    echo "  ✗ $README must carry exactly one '$BEGIN_SENTINEL' and one '$END_SENTINEL' line (found $begin_count / $end_count)." >&2
    return 1
  fi
  # ── fail-closed source extraction ──────────────────────────────────────────
  extract_universe || return 1
  tail -n +2 "$MATRIX_CSV" | cut -d, -f1 | sort >"$WORK/csv_names.txt"
  sort -u -o "$WORK/csv_names.uniq" "$WORK/csv_names.txt"
  # ── regeneration render (fixture mode = pure render; the checks below own
  #    every rejection so the mutation proof is attributable) ────────────────
  if ! XINCHUANG_MATRIX_FIXTURES=1 \
    XINCHUANG_MATRIX_CSV="$MATRIX_CSV" \
    XINCHUANG_CAPS_CSV="$CAPS_CSV" \
    XINCHUANG_README="$README" \
    XINCHUANG_INVENTORY="$INVENTORY" \
    XINCHUANG_REDUCERS_DIR="$REDUCERS_DIR" \
    bash "$GEN" --check "$WORK/out" >"$WORK/gen.log" 2>&1; then
    sed 's/^/    /' "$WORK/gen.log" >&2
    echo "  ✗ matrix regeneration failed while rendering (see generator output above)." >&2
    return 1
  fi
  check_matrix_rows || rc=1
  check_caps || rc=1
  # ── THE set-comparison step: stubbing exactly this function in a mutation
  #    copy must make the row-set fixtures pass (r2.4(1)) ────────────────────
  check_set_consistency || rc=1
  # ── README block byte-identical to regeneration ────────────────────────────
  extract_block >"$WORK/committed_block.txt"
  if ! cmp -s "$WORK/committed_block.txt" "$WORK/out/README.block"; then
    echo "  ✗ README generated block drifted from the regenerated output — run scripts/gen-xinchuang-doc.sh; first drift:" >&2
    diff "$WORK/committed_block.txt" "$WORK/out/README.block" | head -n 4 | sed 's/^/      /' >&2
    rc=1
  fi
  check_prose || rc=1
  return "$rc"
}

case "${1:-}" in
  --self-test)
    # Every fixture below is an independent, non-empty derivative of the REAL
    # artifacts, written to its own mktemp dir, and asserted to carry the
    # planted content BEFORE the guard runs. Every rejection must be asserted
    # with grep -qF on the named offender — never a bare nonzero exit.
    real_csv="$ROOT/mailserver/sql/xinchuang/compatibility_matrix.csv"
    real_caps="$ROOT/mailserver/sql/xinchuang/engine_capabilities.csv"
    real_readme="$ROOT/mailserver/sql/xinchuang/README.md"
    real_inv="$ROOT/mailserver/sql/xinchuang/unattested_functions.csv"
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT
    guard_log="$tmpdir/guard.log"
    fail() {
      echo "  ✗ SELF-TEST FAILED: $*" >&2
      exit 1
    }
    setup_fail() {
      echo "  ✗ SELF-TEST SETUP FAILED: $*" >&2
      exit 1
    }
    # Run the guard against a fixture dir holding matrix.csv, caps.csv,
    # README.md, inventory.csv.
    run_on_dir() { # $1 = fixture dir, $2 = log path
      XINCHUANG_MATRIX_CSV="$1/matrix.csv" \
        XINCHUANG_CAPS_CSV="$1/caps.csv" \
        XINCHUANG_README="$1/README.md" \
        XINCHUANG_INVENTORY="$1/inventory.csv" \
        bash "$0" >"$2" 2>&1
    }
    assert_named() { # $1 = log, $2 = expected literal, $3 = case label
      if ! grep -qF "$2" "$1"; then
        echo "  ✗ SELF-TEST FAILED: $3: rejection did not name the planted content (wanted: $2); it did not come from the expected check:" >&2
        sed 's/^/      /' "$1" >&2
        exit 1
      fi
    }
    # produce_triple SRC_CSV DEST_DIR [SRC_INVENTORY] [SRC_CAPS] — render an
    # otherwise consistent fixture triple with the REAL generator in fixture
    # mode (r2.4(1)); row-source validation is bypassed ONLY inside that
    # render.
    produce_triple() {
      local src="$1" dest="$2" inv="${3:-$real_inv}" caps="${4:-$real_caps}"
      mkdir -p "$dest"
      cp "$src" "$dest/matrix.csv"
      cp "$real_readme" "$dest/README.md"
      cp "$inv" "$dest/inventory.csv"
      cp "$caps" "$dest/caps.csv"
      XINCHUANG_MATRIX_FIXTURES=1 \
        XINCHUANG_MATRIX_CSV="$dest/matrix.csv" \
        XINCHUANG_README="$dest/README.md" \
        XINCHUANG_INVENTORY="$dest/inventory.csv" \
        XINCHUANG_CAPS_CSV="$caps" \
        bash "$GEN" >"$dest/render.log" 2>&1 || setup_fail "fixture render failed for $dest: $(cat "$dest/render.log")"
    }

    echo "==> xinchuang-matrix guard self-test (pristine artifacts must pass)"
    for artifact in "$real_csv" "$real_caps" "$real_readme" "$real_inv"; do
      [ -s "$artifact" ] || setup_fail "real artifact is empty: $artifact"
    done
    grep -qF 'startup_recovery,Crash recovery on startup,untested' "$real_csv" || setup_fail "real matrix lacks the startup_recovery row — fixture seed invalid."
    grep -qF 'polardb,plpgsql,untested,' "$real_caps" || setup_fail "real engine_capabilities lacks the polardb/plpgsql row — fixture seed invalid."
    grep -qxF "$BEGIN_SENTINEL" "$real_readme" || setup_fail "real README lacks the begin sentinel — fixture seed invalid."
    grep -qxF 'function,defined_in' "$real_inv" || setup_fail "real inventory lacks its header — fixture seed invalid."
    if ! bash "$0" >"$guard_log" 2>&1; then
      sed 's/^/      /' "$guard_log" >&2
      fail "the guard rejects the pristine repo at HEAD (false positive)."
    fi
    echo "  ✓ guard passes on the pristine repo (no false positive)."

    echo "==> xinchuang-matrix guard self-test (fail-closed on missing inputs and empty extraction)"
    for missing in matrix.csv caps.csv README.md inventory.csv; do
      d="$tmpdir/missing-$missing"
      mkdir -p "$d"
      cp "$real_csv" "$d/matrix.csv"
      cp "$real_caps" "$d/caps.csv"
      cp "$real_readme" "$d/README.md"
      cp "$real_inv" "$d/inventory.csv"
      rm -f "$d/$missing"
      if run_on_dir "$d" "$guard_log"; then
        fail "guard accepted a missing input ($missing)."
      fi
      assert_named "$guard_log" "missing/unreadable xinchuang matrix input" "missing $missing"
    done
    echo "  ✓ guard fails closed on every missing input, naming it."
    empty_dir="$tmpdir/empty-reducers"
    mkdir -p "$empty_dir"
    if XINCHUANG_REDUCERS_DIR="$empty_dir" bash "$0" >"$guard_log" 2>&1; then
      fail "guard accepted an empty reducer extraction."
    fi
    assert_named "$guard_log" "zero .sql files" "empty extraction"
    echo "  ✓ guard fails closed when reducer extraction yields zero files."

    echo "==> xinchuang-matrix guard self-test (r2.4 isolated row-set fixtures: dead row, duplicate live row)"
    dead_dir="$tmpdir/dead-row"
    {
      cat "$real_csv"
      printf 'adjust_folder_counters,Adjust folder counters,untested,untested,untested,untested,untested,untested,untested,no,Standard UPDATE\n'
    } >"$tmpdir/dead.csv"
    produce_triple "$tmpdir/dead.csv" "$dead_dir"
    grep -qF 'adjust_folder_counters,Adjust folder counters' "$dead_dir/matrix.csv" || setup_fail "dead-row fixture does not carry the planted row."
    [ -s "$dead_dir/README.md" ] || setup_fail "dead-row fixture README is empty."
    if run_on_dir "$dead_dir" "$guard_log"; then
      sed 's/^/      /' "$guard_log" >&2
      fail "guard accepted a planted dead CSV row — the set-comparison check did not fire: adjust_folder_counters."
    fi
    assert_named "$guard_log" "dead row: adjust_folder_counters" "dead-row fixture"
    echo "  ✓ guard fires on a planted dead row and names it."
    dup_dir="$tmpdir/dup-live-row"
    # the planted duplicate carries uses_digest=yes (check_quota.sql really
    # has a non-comment digest( call) so the canonical render keeps its bytes.
    {
      cat "$real_csv"
      printf 'check_quota,Check mailbox quota fixture duplicate,untested,untested,untested,untested,untested,untested,untested,yes,planted duplicate of a live row\n'
    } >"$tmpdir/dup.csv"
    produce_triple "$tmpdir/dup.csv" "$dup_dir"
    c="$(grep -cF 'check_quota,Check mailbox quota fixture duplicate' "$dup_dir/matrix.csv")"
    [ "$c" = "1" ] || setup_fail "duplicate-live-row fixture does not carry the planted second check_quota row."
    if run_on_dir "$dup_dir" "$guard_log"; then
      sed 's/^/      /' "$guard_log" >&2
      fail "guard accepted a planted duplicate live row — the set-comparison check did not fire: check_quota."
    fi
    assert_named "$guard_log" "duplicate function row(s): check_quota" "duplicate-live-row fixture"
    echo "  ✓ guard fires on a planted duplicate LIVE row (liveness and uniqueness tested apart) and names it."

    echo "==> xinchuang-matrix guard self-test (regeneration byte-equality, grammar, prose)"
    regen_dir="$tmpdir/regen-diff"
    produce_triple "$real_csv" "$regen_dir"
    awk '/\| jsonb \(JSONB\) \|/ { sub(/untested/, "uNtested", $0); print; next } { print }' "$regen_dir/README.md" >"$regen_dir/README.md.new" &&
      mv "$regen_dir/README.md.new" "$regen_dir/README.md"
    grep -qF '| jsonb (JSONB) | uNtested' "$regen_dir/README.md" || setup_fail "regen-diff fixture does not carry the mutated byte inside the generated block."
    if run_on_dir "$regen_dir" "$guard_log"; then
      fail "guard accepted a mutated generated README block."
    fi
    assert_named "$guard_log" "generated block drifted" "regen-diff fixture"
    echo "  ✓ guard fires on one mutated byte inside the generated block."
    enum_dir="$tmpdir/enum-blank"
    produce_triple "$real_csv" "$enum_dir"
    sed 's/^polardb,plpgsql,untested,$/polardb,plpgsql,,/' "$real_caps" >"$enum_dir/caps.csv"
    grep -q '^polardb,plpgsql,,$' "$enum_dir/caps.csv" || setup_fail "enum fixture does not carry the blanked status cell."
    if run_on_dir "$enum_dir" "$guard_log"; then
      fail "guard accepted a blank engine-capabilities status cell."
    fi
    assert_named "$guard_log" "row polardb,plpgsql: empty status cell" "blank status fixture"
    echo "  ✓ guard fires on a blank security/status cell, naming row and column."
    ev_dir="$tmpdir/evidence"
    # The bogus ref is planted on the GAUSSDB column (CSV col 5): engine-cell
    # diagnostics used CSV indices 3–9 against an engine array indexed 1–7,
    # so corrupting one engine named its LEFT-SHIFTED neighbour (corrupting
    # polardb reported gaussdb). The rejection must name the actual engine.
    {
      grep -v '^check_quota,' "$real_csv"
      printf 'check_quota,Check mailbox quota,untested,untested,pass@docs/no-such-evidence-ref.md,untested,untested,untested,untested,no,Standard SQL with aggregates\n'
    } >"$tmpdir/ev.csv"
    produce_triple "$tmpdir/ev.csv" "$ev_dir"
    grep -qF 'untested,untested,pass@docs/no-such-evidence-ref.md,untested' "$ev_dir/matrix.csv" || setup_fail "evidence fixture does not carry the planted bogus evidence ref on the gaussdb column."
    if run_on_dir "$ev_dir" "$guard_log"; then
      fail "guard accepted a pass cell whose evidence ref does not resolve."
    fi
    assert_named "$guard_log" "row check_quota engine gaussdb: evidence ref docs/no-such-evidence-ref.md does not resolve" "evidence fixture"
    echo "  ✓ guard fires on an evidence ref that does not resolve, naming row and the actual engine (gaussdb)."
    prose_dir="$tmpdir/prose-phrase"
    produce_triple "$real_csv" "$prose_dir"
    printf '\nThe reducers all pass unmodified on every engine.\n' >>"$prose_dir/README.md"
    grep -qF 'all pass unmodified' "$prose_dir/README.md" || setup_fail "prose fixture does not carry the planted verdict phrase."
    if run_on_dir "$prose_dir" "$guard_log"; then
      fail "guard accepted verdict-bearing compatibility prose outside the sentinels."
    fi
    assert_named "$guard_log" "all pass unmodified" "prose-phrase fixture"
    echo "  ✓ guard fires on verdict-bearing prose outside the sentinels and names the line."
    digit_dir="$tmpdir/prose-digit"
    produce_triple "$real_csv" "$digit_dir"
    printf '\nHistorical note: the matrix once claimed 108 reducers.\n' >>"$digit_dir/README.md"
    grep -qF '108 reducers' "$digit_dir/README.md" || setup_fail "digit fixture does not carry the planted numeric literal."
    if run_on_dir "$digit_dir" "$guard_log"; then
      fail "guard accepted a numeric reducer-count literal in prose."
    fi
    assert_named "$guard_log" "numeric literal" "prose-digit fixture"
    echo "  ✓ guard fires on numeric literals in prose (the 108/108-form completeness claim cannot return)."

    echo "==> xinchuang-matrix guard self-test (structured status/evidence: pass|partial|fail all validate AND render)"
    caps_ref="mailserver/sql/xinchuang/README.md"
    capsok_dir="$tmpdir/caps-statuses"
    sed -e "s|^polardb,plpgsql,untested,\$|polardb,plpgsql,pass@$caps_ref,|" \
      -e "s|^polardb,listen_notify,untested,\$|polardb,listen_notify,partial,$caps_ref|" \
      -e "s|^polardb,jsonb,untested,\$|polardb,jsonb,fail@$caps_ref:1,|" \
      "$real_caps" >"$tmpdir/caps-statuses.csv"
    grep -qF "polardb,plpgsql,pass@$caps_ref," "$tmpdir/caps-statuses.csv" || setup_fail "status fixture does not carry the inline pass@ row."
    grep -qxF "polardb,listen_notify,partial,$caps_ref" "$tmpdir/caps-statuses.csv" || setup_fail "status fixture does not carry the structured partial row."
    grep -qF "polardb,jsonb,fail@$caps_ref:1," "$tmpdir/caps-statuses.csv" || setup_fail "status fixture does not carry the inline fail@:line row."
    produce_triple "$real_csv" "$capsok_dir" "$real_inv" "$tmpdir/caps-statuses.csv"
    # The re-rendered fixture README must carry all three evidence-bearing
    # statuses as status@evidence links (each in the polardb column of its
    # dimension row) — validation and rendering agree.
    grep -qF "| plpgsql (PL/pgSQL) | pass@$caps_ref | untested | untested | untested | untested | untested | untested |" "$capsok_dir/README.md" ||
      setup_fail "fixture render did not emit the accepted pass@ cell as a status@evidence link."
    grep -qF "| listen_notify (LISTEN/NOTIFY) | partial@$caps_ref | untested | untested | untested | untested | untested | untested |" "$capsok_dir/README.md" ||
      setup_fail "fixture render did not emit the structured partial + evidence-column pair as a status@evidence link."
    grep -qF "| jsonb (JSONB) | fail@$caps_ref:1 | untested | untested | untested | untested | untested | untested |" "$capsok_dir/README.md" ||
      setup_fail "fixture render did not emit the accepted fail@:line cell as a status@evidence link."
    if ! run_on_dir "$capsok_dir" "$guard_log"; then
      sed 's/^/      /' "$guard_log" >&2
      fail "guard rejected valid evidence-bearing capability rows (pass@ inline, structured partial, fail@:line) — validation and rendering disagree."
    fi
    echo "  ✓ guard accepts all three evidence-bearing statuses (inline and structured) and renders status@evidence links."

    echo "==> xinchuang-matrix guard self-test (evidence scan is fail-closed: first row, traversal escapes, directories)"
    capsbad_dir="$tmpdir/caps-bad-evidence"
    sed -e 's|^polardb,plpgsql,untested,$|polardb,plpgsql,pass@docs/no-such-evidence-ref.md,|' \
      -e 's|^polardb,listen_notify,untested,$|polardb,listen_notify,pass@../../../etc/hosts,|' \
      -e 's|^polardb,jsonb,untested,$|polardb,jsonb,fail@.,|' \
      "$real_caps" >"$tmpdir/caps-bad-evidence.csv"
    grep -qF 'polardb,plpgsql,pass@docs/no-such-evidence-ref.md,' "$tmpdir/caps-bad-evidence.csv" || setup_fail "bad-evidence fixture does not carry the planted first-row ref."
    grep -qF 'polardb,listen_notify,pass@../../../etc/hosts,' "$tmpdir/caps-bad-evidence.csv" || setup_fail "bad-evidence fixture does not carry the planted traversal escape."
    grep -qF 'polardb,jsonb,fail@.,' "$tmpdir/caps-bad-evidence.csv" || setup_fail "bad-evidence fixture does not carry the planted directory target."
    produce_triple "$real_csv" "$capsbad_dir" "$real_inv" "$tmpdir/caps-bad-evidence.csv"
    if run_on_dir "$capsbad_dir" "$guard_log"; then
      fail "guard accepted capability rows whose evidence escapes the repo (unresolved first row, ../ traversal, directory target)."
    fi
    assert_named "$guard_log" "row polardb,plpgsql: evidence ref docs/no-such-evidence-ref.md does not resolve" "first-capability-row evidence fixture"
    assert_named "$guard_log" "row polardb,listen_notify: evidence ref ../../../etc/hosts does not resolve" "traversal-escape evidence fixture"
    assert_named "$guard_log" "row polardb,jsonb: evidence ref . does not resolve" "directory-target evidence fixture"
    echo "  ✓ guard scans the FIRST capability row too and rejects ../ escapes and directory targets."

    # ── symlink-escape canonical-containment regression (Astra L2-C5 item 2) ──
    # The resolver used to stop at `[ -f "$ROOT/$path" ]`, which follows
    # symlinks: with ROOT=/etc the ref `localtime` "resolved" even though its
    # real path (/private/var/db/timezone/…) lies outside the root. The arms
    # below are RED against that pre-fix check: the guard ACCEPTED the escape
    # fixtures, and the generator failed for the WRONG reason (missing
    # critical-path functions) instead of naming the escaping ref.
    build_escape_fixture() { # $1 = fixture root, $2 = matrix evidence ref
      local root="$1" ref="$2" eng dim
      mkdir -p "$root/scripts" "$root/mailserver/sql/reducers" "$root/mailserver/sql/xinchuang" "$root/docs"
      # shellcheck disable=SC2016  # plpgsql body is literal; $$ must not expand
      printf 'CREATE OR REPLACE FUNCTION fixture_symlink_probe(p_id bigint)\nLANGUAGE plpgsql AS $$BEGIN RETURN; END$$;\n' >"$root/mailserver/sql/reducers/fixture_probe.sql"
      cp "$GEN" "$root/scripts/gen-xinchuang-doc.sh"
      printf 'real evidence file that lives inside the fixture root\n' >"$root/docs/real-evidence.md"
      printf 'real evidence file for the retained Astra r6 erasure fixtures\n' >"$root/docs/real.md"
      ln -s /etc/hosts "$root/docs/escape-link.md"
      ln -s /etc "$root/escape-dir"
      # Astra r5 probe classes, planted in EVERY fixture root: a system
      # absolute-target link whose target itself traverses symlinks
      # (/etc/localtime; /etc/hosts where no zoneinfo link exists — the
      # native-canonicalized escape class), a fixture-retained RELATIVE-
      # target file link that climbs out of the root, a dangling link
      # (native canonicalization refuses it — the fallback must fail closed
      # too), and a genuine RELATIVE in-root link (positive control:
      # legitimate links must keep resolving through every fix).
      # Astra r6 probe classes: docs/real.md (the retained fixture target
      # whose `..`-erased walk certified exit-0) and a RELATIVE-target
      # dangling link (dangle-rel.md) — the dangling component a `..` can
      # erase regardless of how the link target was spelled.
      if [ -e /etc/localtime ]; then
        ln -s /etc/localtime "$root/docs/localtime-link"
      else
        ln -s /etc/hosts "$root/docs/localtime-link"
      fi
      printf 'outside secret the relative file escape must reach\n' >"$tmpdir/outside-secret.md"
      ln -s ../../outside-secret.md "$root/docs/rel-file-escape.md"
      ln -s /nonexistent-xinchuang-selftest-target "$root/docs/dangle-escape.md"
      ln -s ./nonexistent-xinchuang-rel-target "$root/docs/dangle-rel.md"
      ln -s real-evidence.md "$root/docs/inroot-link.md"
      {
        printf '%s\n' "$MATRIX_HEADER"
        printf 'fixture_symlink_probe,Symlink escape probe,pass@%s,untested,untested,untested,untested,untested,untested,no,probe\n' "$ref"
      } >"$root/mailserver/sql/xinchuang/compatibility_matrix.csv"
      {
        printf '%s\n' "$CAPS_HEADER"
        for eng in "${ENGINES[@]}"; do
          for dim in "${DIMENSIONS[@]}"; do printf '%s,%s,untested,\n' "$eng" "$dim"; done
        done
      } >"$root/mailserver/sql/xinchuang/engine_capabilities.csv"
      {
        echo "Symlink escape probe fixture."
        echo
        echo "$BEGIN_SENTINEL"
        echo "placeholder"
        echo "$END_SENTINEL"
      } >"$root/mailserver/sql/xinchuang/README.md"
      : >"$root/mailserver/sql/xinchuang/unattested_functions.csv"
      # The fixture render is fixture-mode: row-source validation (including
      # the resolver) is bypassed, so the planted cell survives the render and
      # the GUARD's checks own every rejection (r2.4 attribution shape).
      XINCHUANG_MATRIX_FIXTURES=1 XINCHUANG_ROOT="$root" \
        bash "$root/scripts/gen-xinchuang-doc.sh" >"$root/render.log" 2>&1 ||
        setup_fail "symlink fixture render failed for $root: $(cat "$root/render.log")"
      grep -qF "pass@$ref" "$root/mailserver/sql/xinchuang/compatibility_matrix.csv" ||
        setup_fail "symlink fixture does not carry the planted evidence ref $ref."
      if grep -qF 'fixture_symlink_probe' "$root/mailserver/sql/xinchuang/unattested_functions.csv"; then
        setup_fail "symlink fixture inventory unexpectedly carries fixture_symlink_probe (it is CSV-covered; the complement must be empty)."
      fi
    }
    run_on_root() { # $1 = fixture root (passed as XINCHUANG_ROOT), $2 = log path
      XINCHUANG_ROOT="$1" bash "$0" >"$2" 2>&1
    }

    echo "==> xinchuang-matrix guard self-test (symlink escapes: canonical containment under the resolved root)"
    # (a) Unit probe of the resolver itself, with ROOT reached THROUGH a
    #     symlinked alias — the Astra probe used ROOT=/etc, itself a symlink.
    unit_dir="$tmpdir/symlink-unit-root"
    build_escape_fixture "$unit_dir" "docs/real-evidence.md"
    ln -s "$unit_dir" "$tmpdir/symlink-unit-alias"
    saved_root="$ROOT"
    ROOT="$tmpdir/symlink-unit-alias"
    if resolve_evidence_ref "docs/escape-link.md"; then
      ROOT="$saved_root"
      fail "resolver accepted docs/escape-link.md, a symlink whose real path (/etc/hosts) resolves outside the root."
    fi
    if resolve_evidence_ref "escape-dir/hosts"; then
      ROOT="$saved_root"
      fail "resolver accepted escape-dir/hosts, a path through a symlinked directory that leaves the root."
    fi
    if ! resolve_evidence_ref "docs/real-evidence.md"; then
      ROOT="$saved_root"
      fail "resolver rejected a genuine in-root file after the containment fix (over-blocking regression)."
    fi
    ROOT="$saved_root"
    echo "  ✓ resolver rejects symlink escapes (file link and link-traversed directory) and still resolves genuine in-root files through a symlinked ROOT."
    # (b) End-to-end guard arms on an otherwise-consistent fixture root.
    escA_dir="$tmpdir/symlink-escape-file"
    build_escape_fixture "$escA_dir" "docs/escape-link.md"
    if run_on_root "$escA_dir" "$guard_log"; then
      fail "guard accepted a pass cell whose evidence ref is a symlink escaping the root (docs/escape-link.md -> /etc/hosts)."
    fi
    assert_named "$guard_log" "evidence ref docs/escape-link.md does not resolve inside the repo" "symlink-escape-file fixture"
    echo "  ✓ guard rejects an evidence ref that is a symlink to a file outside the root, naming it."
    escB_dir="$tmpdir/symlink-escape-dir"
    build_escape_fixture "$escB_dir" "escape-dir/hosts"
    if run_on_root "$escB_dir" "$guard_log"; then
      fail "guard accepted an evidence ref that traverses a symlinked directory outside the root (escape-dir -> /etc)."
    fi
    assert_named "$guard_log" "evidence ref escape-dir/hosts does not resolve inside the repo" "symlink-escape-dir fixture"
    echo "  ✓ guard rejects an evidence ref that traverses a symlinked directory out of the root, naming it."
    escC_dir="$tmpdir/symlink-inroot-ok"
    build_escape_fixture "$escC_dir" "docs/real-evidence.md"
    if ! run_on_root "$escC_dir" "$guard_log"; then
      sed 's/^/      /' "$guard_log" >&2
      fail "guard rejected an otherwise-consistent fixture whose evidence ref is a REAL file inside the root — containment over-blocks."
    fi
    echo "  ✓ guard still accepts a real in-root evidence file (no over-blocking)."
    # (c) The generator's own normal-mode validation rejects the escape too —
    #     for the RIGHT reason (the shared resolver, not a downstream
    #     critical-path failure, which is how the pre-fix code failed).
    escG_dir="$tmpdir/symlink-escape-generator"
    build_escape_fixture "$escG_dir" "docs/escape-link.md"
    if XINCHUANG_ROOT="$escG_dir" bash "$escG_dir/scripts/gen-xinchuang-doc.sh" >"$escG_dir/gen.log" 2>&1; then
      fail "generator accepted a matrix cell whose evidence ref is a symlink escaping the root."
    fi
    assert_named "$escG_dir/gen.log" "evidence ref docs/escape-link.md does not resolve inside the repo" "generator symlink-escape diagnostic"
    echo "  ✓ generator evidence validation rejects the symlink escape through the same shared resolver."

    # (d0) `..`-ERASURE certification, native-handoff (Astra L2-C5 r6): the
    #      r5 shape certified only the walk's FINISHED result, so a `..`
    #      ERASED a component already observed to be invalid — a dangling
    #      link, a nonexistent intermediate, a file used as a directory —
    #      and the surviving path certified exit-0 (e.g.
    #      `docs/nope.md/../real.md` came back exit-0 for the existing
    #      `docs/real.md` while native canonicalization refuses the shape).
    #      Certification must consume the ORIGINAL component sequence. With
    #      readlink -f made unavailable here, the host realpath + the
    #      fallback must still reject every retained erasure shape — on
    #      hosts whose realpath folds `..` lexically (FreeBSD/macOS) the
    #      host tool itself would erase, so this arm RED against the r4/r5
    #      code on BOTH host classes and pins the realpath gate. A genuine
    #      `..` path must keep resolving byte-equal to native.
    readlink() {
      if [ "${1:-}" = "-f" ]; then return 1; fi
      command readlink "$@"
    }
    for erasure_ref in "docs/real.md/../real.md" "docs/nope.md/../real.md" \
      "docs/dangle-rel.md/../real.md" "docs/real.md/../../docs/real.md" \
      "docs/dangle-escape.md/../docs/real.md"; do
      if canonical_path "$unit_dir/$erasure_ref" >/dev/null 2>&1; then
        unset -f readlink
        fail "canonical_path SUCCEEDED on $erasure_ref — its .. erased the invalid component and certified the surviving path (Astra L2-C5 r6)."
      fi
    done
    g_want="$(command readlink -f -- "$unit_dir/docs/../docs/real.md")"
    g_out=""
    if ! g_out="$(canonical_path "$unit_dir/docs/../docs/real.md")" || [ "$g_out" != "$g_want" ]; then
      unset -f readlink
      fail "canonical_path broke a genuine .. path (docs/../docs/real.md): got ${g_out:-<failed>}, wanted $g_want."
    fi
    unset -f readlink
    echo "  ✓ ..-erasure of a real file, a nonexistent intermediate, a dangling relative link, and a dangling absolute link all fail closed through the native-handoff gate; a genuine .. path stays byte-equal to native."

    # (d0b) SINGLE-COMPONENT STACK POP (Astra L2-C5 r7): the r6 walker handled
    #       a `..` against a MULTI-component base (`*/*` → pop) and against an
    #       EMPTY base ("" → fail closed at the root) but left a SLASH-FREE
    #       base such as `Users` UNCHANGED — a `..` never popped a
    #       one-component stack, so every later component was certified
    #       against the WRONG directory (Astra reproduced exit-0 for
    #       /Users/../cat/setjoin/AGENTS.md). The pop must reach the empty
    #       stack (native X/.. == /) while a `..` already AT the root stays
    #       fail-closed (native /.. == / is deliberately not replicated —
    #       that pin lives in the forced-fallback block below, where the
    #       walker, not the host resolver, decides). The probes need a REAL
    #       one-component directory: TMPDIR fixtures are always
    #       multi-component and can never reach the shape by popping.
    one_comp=""
    for d0b_cand in /usr /opt /etc /var /tmp /private /home; do
      if [ -d "$d0b_cand" ] && [ ! -L "$d0b_cand" ]; then
        one_comp="$d0b_cand"
        break
      fi
    done
    [ -n "$one_comp" ] || setup_fail "no real one-component directory under / for the single-component pop arms."
    d0b_name="${one_comp#/}"
    wrong_mid=""
    for d0b_sub in share/zoneinfo share/man lib/locale etc/hosts; do
      if [ -e "$one_comp/$d0b_sub" ] && [ ! -e "/${d0b_sub%%/*}" ]; then
        wrong_mid="$d0b_sub"
        break
      fi
    done
    [ -n "$wrong_mid" ] || setup_fail "no subtree under $one_comp whose root-level counterpart is absent — the wrong-directory probes cannot be planted."
    for d0b_shape in "$one_comp/../$wrong_mid" "$one_comp/../../$wrong_mid"; do
      if command readlink -f -- "$d0b_shape" >/dev/null 2>&1; then
        setup_fail "native canonicalization unexpectedly resolves $d0b_shape — the wrong-directory probe premise is broken on this host."
      fi
      if d0b_out="$(canonical_path "$d0b_shape")"; then
        fail "canonical_path SUCCEEDED on $d0b_shape (fabricated: $d0b_out) — its .. left the one-component stack unchanged, so $wrong_mid was certified against $one_comp instead of / (Astra L2-C5 r7)."
      fi
    done
    d0b_want="$(command readlink -f -- "$one_comp/..")"
    [ -n "$d0b_want" ] || setup_fail "native readlink -f could not resolve $one_comp/.. — the pop-to-root byte-equality probe cannot run."
    if ! d0b_out="$(canonical_path "$one_comp/..")" || [ "$d0b_out" != "$d0b_want" ]; then
      fail "canonical_path broke the genuine path $one_comp/.. (got ${d0b_out:-<failed>}, wanted $d0b_want)."
    fi
    d0b_want="$(command readlink -f -- "$one_comp/../$d0b_name")"
    [ -n "$d0b_want" ] || setup_fail "native readlink -f could not resolve $one_comp/../$d0b_name — the pop-then-descend byte-equality probe cannot run."
    if ! d0b_out="$(canonical_path "$one_comp/../$d0b_name")" || [ "$d0b_out" != "$d0b_want" ]; then
      fail "canonical_path broke the genuine path $one_comp/../$d0b_name (got ${d0b_out:-<failed>}, wanted $d0b_want) — after the single-component pop, later components must re-root at /."
    fi
    echo "  ✓ a .. against a one-component stack pops to the root byte-equal to native and later components re-root at /; re-rooted wrong-directory .. shapes fail closed (Astra L2-C5 r7)."

    # (d) FORCED-FALLBACK arms: the arms above run on the native resolvers,
    #     which can hide a bug in the pure-bash fallback. The fallback used to
    #     keep the accumulated `base` when a symlink target was ABSOLUTE,
    #     fabricating an apparently contained path (/<root>/docs/etc/hosts)
    #     for a ref that really resolved to /etc/hosts — every arm below
    #     FORCES the fallback branch by making `readlink -f` and `realpath`
    #     unavailable (PATH shim for subprocess arms, function override for
    #     the in-process probes; plain `readlink` must keep working because
    #     the fallback itself reads each link with it) and proves the escapes
    #     are rejected THERE too, alongside a positive control proving the
    #     fallback still RESOLVES rather than failing closed.
    #     r5 extension: Astra's three probe classes are each exercised
    #     exactly — the native-canonicalized escape (docs/localtime-link, a
    #     system link whose target itself traverses symlinks), the retained
    #     file-link escape (docs/rel-file-escape.md, a RELATIVE-target link
    #     climbing out of the root), and the directory-link escape (escape-
    #     dir/hosts) — at resolver, guard, and generator levels; and the
    #     containment-soundness fix's own class is pinned: the walk used to
    #     fabricate exit-0 "canonical" paths for inputs native canonicali-
    #     zation refuses (dangling link, nonexistent final, through-a-file
    #     path) — those arms are RED against r4.
    #     r6 extension: Astra's `..`-erasure fixtures (docs/real.md,
    #     docs/nope.md, docs/dangle-escape.md + a `..` that erases the
    #     invalid component) are pinned at the forced-fallback level (d1c)
    #     and at the native-handoff level (d0, including the lexically-
    #     folding realpath branch) — RED against the r4/r5 result-only
    #     certification.
    fallback_shim="$tmpdir/fallback-shim"
    mkdir -p "$fallback_shim"
    real_readlink="$(command -v readlink)" || setup_fail "no readlink binary to build the forced-fallback shim from."
    # shellcheck disable=SC2016  # the shim must carry the literal ${1:-} test, unexpanded
    {
      printf '#!/bin/sh\n'
      printf 'if [ "${1:-}" = "-f" ]; then\n'
      printf '  echo "readlink: illegal option -- f (forced-fallback shim)" >&2\n'
      printf '  exit 1\n'
      printf 'fi\n'
      printf 'exec "%s" "$@"\n' "$real_readlink"
    } >"$fallback_shim/readlink"
    chmod +x "$fallback_shim/readlink"
    printf '#!/bin/sh\nexit 127\n' >"$fallback_shim/realpath"
    chmod +x "$fallback_shim/realpath"
    if PATH="$fallback_shim:$PATH" readlink -f -- / >/dev/null 2>&1; then
      setup_fail "forced-fallback shim did not disable readlink -f."
    fi
    fb_alias="$tmpdir/symlink-unit-alias-fb"
    ln -s "$unit_dir" "$fb_alias"
    saved_root="$ROOT"
    ROOT="$fb_alias"
    # In-process function override: same forcing as the shim, no subprocess.
    readlink() {
      if [ "${1:-}" = "-f" ]; then return 1; fi
      command readlink "$@"
    }
    realpath() { return 127; }
    # (d1) the fallback must canonicalize EXACTLY like the native resolvers —
    #      the fabricated path could never pass this equality probe. The r5
    #      list adds every Astra probe class and a genuine relative in-root
    #      link (the verification pass must not over-block real links).
    for fb_probe in "$unit_dir/docs/escape-link.md" "$unit_dir/docs/localtime-link" \
      "$unit_dir/docs/rel-file-escape.md" "$unit_dir/docs/inroot-link.md" \
      "$fb_alias" "$unit_dir/docs/real-evidence.md"; do
      if ! fb_out="$(canonical_path "$fb_probe")" ||
        [ "$fb_out" != "$(command readlink -f -- "$fb_probe")" ]; then
        unset -f readlink realpath
        ROOT="$saved_root"
        fail "forced-fallback canonical_path of $fb_probe disagrees with the native canonical path (got ${fb_out:-<failed>})."
      fi
    done
    echo "  ✓ forced-fallback canonicalization is byte-equal to native canonicalization (root alias, absolute-target escape links incl. the /etc/localtime class, relative-target escape, genuine relative in-root link, real file)."
    # (d1b) containment-soundness: the walk used to return fabricated SUCCESSES
    #       for exactly the inputs native canonicalization refuses — RED
    #       against the r4 code, which printed exit-0 paths for all three.
    if fb_out="$(canonical_path "$unit_dir/docs/dangle-escape.md")"; then
      unset -f readlink realpath
      ROOT="$saved_root"
      fail "forced-fallback canonical_path SUCCEEDED on a dangling escape link (fabricated: $fb_out) — the fallback must fail closed."
    fi
    if fb_out="$(canonical_path "$unit_dir/docs/no-such-file.md")"; then
      unset -f readlink realpath
      ROOT="$saved_root"
      fail "forced-fallback canonical_path SUCCEEDED on a nonexistent path (fabricated: $fb_out) — the fallback must fail closed."
    fi
    if fb_out="$(canonical_path "$unit_dir/docs/real-evidence.md/through-a-file")"; then
      unset -f readlink realpath
      ROOT="$saved_root"
      fail "forced-fallback canonical_path SUCCEEDED on a through-a-file path (fabricated: $fb_out) — the fallback must fail closed."
    fi
    echo "  ✓ forced-fallback canonicalization fails CLOSED on dangling links, nonexistent finals, and through-a-file paths (no fabricated successes)."
    # (d1c) `..`-ERASURE under the FORCED fallback (Astra L2-C5 r6): the
    #       r4/r5 certification ran only on the walk's finished result, so
    #       a `..` erased an already-observed violation and the surviving
    #       path certified exit-0 — every probe below was RED against that
    #       code (the last one additionally fabricated an OUTSIDE-root
    #       path). The fixed walk certifies each ORIGINAL component at
    #       consumption, so normalization can never discard the evidence;
    #       a `..` that would climb above the root fails closed, while
    #       genuine `..`/`.` paths stay byte-equal to native.
    for erasure_ref in "docs/real.md/../real.md" "docs/nope.md/../real.md" \
      "docs/dangle-rel.md/../real.md" "docs/real.md/../../docs/real.md" \
      "docs/dangle-escape.md/../docs/real.md" "docs/../../etc/hosts"; do
      if fb_out="$(canonical_path "$unit_dir/$erasure_ref")"; then
        unset -f readlink realpath
        ROOT="$saved_root"
        fail "forced-fallback canonical_path SUCCEEDED on $erasure_ref (fabricated: $fb_out) — its .. erased the invalid component and certified the surviving path."
      fi
    done
    echo "  ✓ forced-fallback consumes the ORIGINAL component sequence: ..-erasure of a real file, a nonexistent intermediate, a dangling link (relative and absolute target), and a root-escaping .. all fail closed."
    for g_ref in "docs/../docs/real.md" "docs/./real.md"; do
      g_want="$(command readlink -f -- "$unit_dir/$g_ref")"
      if ! fb_out="$(canonical_path "$unit_dir/$g_ref")" || [ "$fb_out" != "$g_want" ]; then
        unset -f readlink realpath
        ROOT="$saved_root"
        fail "forced-fallback canonical_path broke the genuine path $g_ref (got ${fb_out:-<failed>}, wanted $g_want)."
      fi
    done
    echo "  ✓ forced-fallback keeps genuine .. and . paths byte-equal to native canonicalization."
    # (d1d) SINGLE-COMPONENT STACK POP under the FORCED fallback (Astra
    #       L2-C5 r7): the r6 walker left a slash-free base (`Users`)
    #       unchanged on `..`, so the fallback resolved /Users/.. to /Users
    #       instead of / and certified every later component under the WRONG
    #       directory. Under the fallback the pop must reach the empty stack
    #       byte-equal to native; a `..` already AT the root keeps failing
    #       closed.
    fb_out=""
    if ! fb_out="$(canonical_path "$one_comp/..")" || [ "$fb_out" != "/" ]; then
      unset -f readlink realpath
      ROOT="$saved_root"
      fail "forced-fallback canonical_path resolved $one_comp/.. to ${fb_out:-<failed>} instead of / — the one-component stack was not popped (Astra L2-C5 r7)."
    fi
    g_want="$(command readlink -f -- "$one_comp/../$d0b_name")"
    [ -n "$g_want" ] || {
      unset -f readlink realpath
      ROOT="$saved_root"
      setup_fail "native readlink -f could not resolve $one_comp/../$d0b_name — forced-fallback pop-then-descend premise broken."
    }
    if ! fb_out="$(canonical_path "$one_comp/../$d0b_name")" || [ "$fb_out" != "$g_want" ]; then
      unset -f readlink realpath
      ROOT="$saved_root"
      fail "forced-fallback canonical_path broke the genuine path $one_comp/../$d0b_name (got ${fb_out:-<failed>}, wanted $g_want) — after the single-component pop, later components must re-root at /."
    fi
    for d1d_shape in "$one_comp/../$wrong_mid" "$one_comp/../../$wrong_mid"; do
      if fb_out="$(canonical_path "$d1d_shape")"; then
        unset -f readlink realpath
        ROOT="$saved_root"
        fail "forced-fallback canonical_path SUCCEEDED on $d1d_shape (fabricated: $fb_out) — its .. left the one-component stack unchanged and certified $wrong_mid against $one_comp instead of / (Astra L2-C5 r7)."
      fi
    done
    for d1d_atroot in "/.." "/../$d0b_name"; do
      if fb_out="$(canonical_path "$d1d_atroot")"; then
        unset -f readlink realpath
        ROOT="$saved_root"
        fail "forced-fallback canonical_path SUCCEEDED on $d1d_atroot (fabricated: $fb_out) — a .. already AT the root must stay fail-closed (Astra L2-C5 r7)."
      fi
    done
    echo "  ✓ forced-fallback pops a one-component stack to the root byte-equal to native (.. no longer leaves a slash-free stack unchanged), rejects re-rooted wrong-directory shapes, and keeps a .. at the root fail-closed."
    # (d2) the Astra probes, replayed with the fallback forced: every escape
    #      class must be rejected and genuine in-root files/links must still
    #      resolve.
    if resolve_evidence_ref "docs/escape-link.md"; then
      unset -f readlink realpath
      ROOT="$saved_root"
      fail "forced-fallback resolver accepted docs/escape-link.md — the fallback fabricated a contained path for /etc/hosts."
    fi
    if resolve_evidence_ref "docs/localtime-link"; then
      unset -f readlink realpath
      ROOT="$saved_root"
      fail "forced-fallback resolver accepted docs/localtime-link — the native-canonicalized escape class must be rejected under the fallback."
    fi
    if resolve_evidence_ref "docs/rel-file-escape.md"; then
      unset -f readlink realpath
      ROOT="$saved_root"
      fail "forced-fallback resolver accepted docs/rel-file-escape.md — the retained relative-target file link climbs out of the root."
    fi
    if resolve_evidence_ref "escape-dir/hosts"; then
      unset -f readlink realpath
      ROOT="$saved_root"
      fail "forced-fallback resolver accepted escape-dir/hosts — the fallback let a directory link leave the root."
    fi
    if ! resolve_evidence_ref "docs/inroot-link.md"; then
      unset -f readlink realpath
      ROOT="$saved_root"
      fail "forced-fallback resolver rejected docs/inroot-link.md — a genuine relative in-root link must keep resolving (over-blocking)."
    fi
    if ! resolve_evidence_ref "docs/real-evidence.md"; then
      unset -f readlink realpath
      ROOT="$saved_root"
      fail "forced-fallback resolver rejected a genuine in-root file — the fixed fallback over-blocks (or fails closed)."
    fi
    unset -f readlink realpath
    ROOT="$saved_root"
    echo "  ✓ forced-fallback resolver rejects every Astra escape class (absolute-target file link, /etc/localtime class, retained relative file link, directory link) and still resolves real in-root files and genuine relative links."
    # (d3) end-to-end guard arms, forced onto the fallback through the PATH shim.
    run_on_root_fb() { # $1 = fixture root, $2 = log path — guard with readlink -f/realpath unavailable
      PATH="$fallback_shim:$PATH" XINCHUANG_ROOT="$1" bash "$0" >"$2" 2>&1
    }
    if run_on_root_fb "$escA_dir" "$guard_log"; then
      fail "guard FORCED onto the fallback accepted docs/escape-link.md -> /etc/hosts (fabricated containment)."
    fi
    assert_named "$guard_log" "evidence ref docs/escape-link.md does not resolve inside the repo" "forced-fallback symlink-escape-file fixture"
    echo "  ✓ forced-fallback guard rejects the file-link escape and names it."
    if run_on_root_fb "$escB_dir" "$guard_log"; then
      fail "guard FORCED onto the fallback accepted escape-dir/hosts (directory link leaves the root)."
    fi
    assert_named "$guard_log" "evidence ref escape-dir/hosts does not resolve inside the repo" "forced-fallback symlink-escape-dir fixture"
    echo "  ✓ forced-fallback guard rejects the directory-link escape and names it."
    if ! run_on_root_fb "$escC_dir" "$guard_log"; then
      sed 's/^/      /' "$guard_log" >&2
      fail "guard FORCED onto the fallback rejected a REAL in-root evidence file — the fixed fallback over-blocks."
    fi
    echo "  ✓ forced-fallback guard still accepts a real in-root evidence file (the fallback resolves, it does not fail closed)."
    # (d3b) the remaining Astra probe classes, end-to-end under the same shim:
    #       the native-canonicalized escape (/etc/localtime class) and the
    #       retained relative-target file-link escape, plus a positive control
    #       proving a genuine relative in-root link survives the shim.
    escD_dir="$tmpdir/symlink-escape-localtime"
    build_escape_fixture "$escD_dir" "docs/localtime-link"
    if run_on_root_fb "$escD_dir" "$guard_log"; then
      fail "guard FORCED onto the fallback accepted docs/localtime-link (native-canonicalized escape class)."
    fi
    assert_named "$guard_log" "evidence ref docs/localtime-link does not resolve inside the repo" "forced-fallback symlink-escape-localtime fixture"
    echo "  ✓ forced-fallback guard rejects the /etc/localtime-class escape and names it."
    escE_dir="$tmpdir/symlink-escape-relative"
    build_escape_fixture "$escE_dir" "docs/rel-file-escape.md"
    if run_on_root_fb "$escE_dir" "$guard_log"; then
      fail "guard FORCED onto the fallback accepted docs/rel-file-escape.md (retained relative-target file-link escape)."
    fi
    assert_named "$guard_log" "evidence ref docs/rel-file-escape.md does not resolve inside the repo" "forced-fallback symlink-escape-relative fixture"
    echo "  ✓ forced-fallback guard rejects the retained relative-target file-link escape and names it."
    escF_dir="$tmpdir/symlink-inroot-relative-fb"
    build_escape_fixture "$escF_dir" "docs/inroot-link.md"
    if ! run_on_root_fb "$escF_dir" "$guard_log"; then
      sed 's/^/      /' "$guard_log" >&2
      fail "guard FORCED onto the fallback rejected a genuine RELATIVE in-root link — the r5 verification over-blocks."
    fi
    echo "  ✓ forced-fallback guard still accepts a genuine relative in-root link (no over-blocking)."
    # (d4) the generator's own normal-mode validation under the forced fallback.
    if PATH="$fallback_shim:$PATH" XINCHUANG_ROOT="$escA_dir" \
      bash "$escA_dir/scripts/gen-xinchuang-doc.sh" >"$escA_dir/gen-fb.log" 2>&1; then
      fail "generator FORCED onto the fallback accepted a symlink-escaping evidence ref."
    fi
    assert_named "$escA_dir/gen-fb.log" "evidence ref docs/escape-link.md does not resolve inside the repo" "forced-fallback generator diagnostic"
    echo "  ✓ forced-fallback generator rejects the escape through the same shared resolver."
    # (d4b) the generator under the shim against the relative-target class —
    #       the OTHER symlink-target branch of the shared resolver.
    if PATH="$fallback_shim:$PATH" XINCHUANG_ROOT="$escE_dir" \
      bash "$escE_dir/scripts/gen-xinchuang-doc.sh" >"$escE_dir/gen-fb.log" 2>&1; then
      fail "generator FORCED onto the fallback accepted a relative-target symlink-escaping evidence ref."
    fi
    assert_named "$escE_dir/gen-fb.log" "evidence ref docs/rel-file-escape.md does not resolve inside the repo" "forced-fallback generator relative-escape diagnostic"
    echo "  ✓ forced-fallback generator rejects the relative-target escape through the same shared resolver."
    # ── end symlink-escape canonical-containment regression ──────────────────

    echo "==> xinchuang-matrix guard self-test (guard and generator share ONE resolver, byte-identical)"
    # The r5 Astra note: "both implementations' resolver functions are
    # identical". That identity is load-bearing — a fix landed in only one
    # copy is how the `..`-erasure class (Astra L2-C5 r6) survives in the
    # other. Pin the three resolver functions byte-identical across both
    # scripts; any future fix must land in both or this arm fires.
    for fn in canonical_path _canonical_path_bash _canonical_path_verify; do
      sed -n "/^${fn}() {/,/^}/p" "$0" >"$tmpdir/resolver-guard-$fn.txt"
      sed -n "/^${fn}() {/,/^}/p" "$GEN" >"$tmpdir/resolver-gen-$fn.txt"
      if ! cmp -s "$tmpdir/resolver-guard-$fn.txt" "$tmpdir/resolver-gen-$fn.txt"; then
        fail "the ${fn} resolver copy drifted between check-xinchuang-matrix.sh and gen-xinchuang-doc.sh — the two implementations must stay identical (Astra L2-C5 r6)."
      fi
    done
    echo "  ✓ canonical_path, _canonical_path_bash, and _canonical_path_verify are byte-identical in the guard and the generator."

    echo "==> xinchuang-matrix guard self-test (structured status/evidence schema violations)"
    capsschema_dir="$tmpdir/caps-bad-schema"
    sed -e "s|^polardb,pg_trgm,untested,\$|polardb,pg_trgm,untested,$caps_ref|" \
      -e 's|^polardb,rls_semantics,untested,$|polardb,rls_semantics,partial,|' \
      -e "s|^polardb,grants_role_separation,untested,\$|polardb,grants_role_separation,pass@$caps_ref,mailserver/sql/xinchuang/engine_capabilities.csv|" \
      "$real_caps" >"$tmpdir/caps-bad-schema.csv"
    grep -qF "polardb,pg_trgm,untested,$caps_ref" "$tmpdir/caps-bad-schema.csv" || setup_fail "schema fixture does not carry the untested-with-evidence row."
    grep -qF 'polardb,rls_semantics,partial,' "$tmpdir/caps-bad-schema.csv" || setup_fail "schema fixture does not carry the bare-status-without-evidence row."
    grep -qF "polardb,grants_role_separation,pass@$caps_ref,mailserver/sql/xinchuang/engine_capabilities.csv" "$tmpdir/caps-bad-schema.csv" || setup_fail "schema fixture does not carry the conflicting-refs row."
    produce_triple "$real_csv" "$capsschema_dir" "$real_inv" "$tmpdir/caps-bad-schema.csv"
    if run_on_dir "$capsschema_dir" "$guard_log"; then
      fail "guard accepted capability rows outside the structured status/evidence schema."
    fi
    assert_named "$guard_log" "row polardb,pg_trgm: untested must not carry an evidence ref" "untested-with-evidence fixture"
    assert_named "$guard_log" "row polardb,rls_semantics: bare partial requires an evidence ref in the evidence column" "bare-status fixture"
    assert_named "$guard_log" "row polardb,grants_role_separation: status cell and evidence column disagree" "conflicting-refs fixture"
    echo "  ✓ guard rejects untested-with-evidence, bare-status-without-evidence, and conflicting refs."

    echo "==> xinchuang-matrix guard self-test (generator diagnostics name the ACTUAL engine, not a shifted one)"
    gendiag_dir="$tmpdir/gen-diag-grammar"
    mkdir -p "$gendiag_dir"
    sed 's|^startup_recovery,Crash recovery on startup,untested,|startup_recovery,Crash recovery on startup,bogus,|' "$real_csv" >"$gendiag_dir/matrix.csv"
    grep -qF 'startup_recovery,Crash recovery on startup,bogus,' "$gendiag_dir/matrix.csv" || setup_fail "gen-diag grammar fixture does not carry the corrupted polardb cell."
    cp "$real_caps" "$gendiag_dir/caps.csv"
    cp "$real_readme" "$gendiag_dir/README.md"
    cp "$real_inv" "$gendiag_dir/inventory.csv"
    if XINCHUANG_MATRIX_CSV="$gendiag_dir/matrix.csv" \
      XINCHUANG_CAPS_CSV="$gendiag_dir/caps.csv" \
      XINCHUANG_README="$gendiag_dir/README.md" \
      XINCHUANG_INVENTORY="$gendiag_dir/inventory.csv" \
      bash "$GEN" >"$gendiag_dir/gen.log" 2>&1; then
      fail "generator accepted a cell outside the pass@|partial@|fail@|untested grammar."
    fi
    assert_named "$gendiag_dir/gen.log" "row startup_recovery engine polardb: cell bogus is outside the pass@|partial@|fail@|untested grammar" "generator grammar diagnostic"
    echo "  ✓ generator grammar diagnostics name the actual engine (polardb, not gaussdb)."
    gendiag_dir="$tmpdir/gen-diag-evidence"
    mkdir -p "$gendiag_dir"
    sed 's|^startup_recovery,Crash recovery on startup,untested,untested,untested,|startup_recovery,Crash recovery on startup,untested,untested,pass@docs/no-such-evidence-ref.md,|' "$real_csv" >"$gendiag_dir/matrix.csv"
    grep -qF 'startup_recovery,Crash recovery on startup,untested,untested,pass@docs/no-such-evidence-ref.md,' "$gendiag_dir/matrix.csv" || setup_fail "gen-diag evidence fixture does not carry the corrupted gaussdb cell."
    cp "$real_caps" "$gendiag_dir/caps.csv"
    cp "$real_readme" "$gendiag_dir/README.md"
    cp "$real_inv" "$gendiag_dir/inventory.csv"
    if XINCHUANG_MATRIX_CSV="$gendiag_dir/matrix.csv" \
      XINCHUANG_CAPS_CSV="$gendiag_dir/caps.csv" \
      XINCHUANG_README="$gendiag_dir/README.md" \
      XINCHUANG_INVENTORY="$gendiag_dir/inventory.csv" \
      bash "$GEN" >"$gendiag_dir/gen.log" 2>&1; then
      fail "generator accepted an evidence ref that does not resolve inside the repo."
    fi
    assert_named "$gendiag_dir/gen.log" "startup_recovery engine gaussdb: evidence ref docs/no-such-evidence-ref.md does not resolve inside the repo" "generator evidence diagnostic"
    echo "  ✓ generator evidence diagnostics name the actual engine (gaussdb) through the shared resolver."

    echo "==> xinchuang-matrix guard self-test (cross-file overload counts ONE unique name, r2.3)"
    xover_dir="$tmpdir/xover"
    mkdir -p "$xover_dir/reducers" "$xover_dir/out"
    cat >"$xover_dir/reducers/alpha.sql" <<'EOF'
CREATE OR REPLACE FUNCTION fixture_overloaded(p_id bigint)
LANGUAGE plpgsql AS $$BEGIN RETURN; END$$;
EOF
    cat >"$xover_dir/reducers/beta.sql" <<'EOF'
CREATE OR REPLACE FUNCTION fixture_overloaded(p_key text)
LANGUAGE plpgsql AS $$BEGIN RETURN; END$$;
EOF
    cat >"$xover_dir/reducers/gamma.sql" <<'EOF'
CREATE OR REPLACE FUNCTION fixture_solo(p_id bigint)
LANGUAGE plpgsql AS $$BEGIN RETURN; END$$;
EOF
    XINCHUANG_MATRIX_FIXTURES=1 \
      XINCHUANG_MATRIX_CSV="$real_csv" \
      XINCHUANG_CAPS_CSV="$real_caps" \
      XINCHUANG_README="$real_readme" \
      XINCHUANG_REDUCERS_DIR="$xover_dir/reducers" \
      bash "$GEN" --check "$xover_dir/out" >"$xover_dir/render.log" 2>&1 ||
      setup_fail "cross-file overload render failed: $(cat "$xover_dir/render.log")"
    [ "$(grep -c '^fixture_overloaded,' "$xover_dir/out/unattested_functions.csv")" = "1" ] ||
      setup_fail "cross-file overload produced duplicate inventory entries for fixture_overloaded."
    grep -qxF 'fixture_overloaded,alpha.sql' "$xover_dir/out/unattested_functions.csv" ||
      setup_fail "cross-file overload lost its defining-file mapping (wanted fixture_overloaded,alpha.sql)."
    grep -qxF 'fixture_solo,gamma.sql' "$xover_dir/out/unattested_functions.csv" ||
      setup_fail "solo fixture name missing from the complement inventory."
    grep -qF 'declarations: 3 · unique names: 2' "$xover_dir/out/README.block" ||
      setup_fail "cross-file overload miscounted the unique-name universe (3 declarations, 2 names)."
    # shellcheck disable=SC2016  # the backticks are literal Markdown in the rendered block
    grep -qF '`fixture_overloaded` — 2 declarations' "$xover_dir/out/README.block" ||
      setup_fail "overload note missing for fixture_overloaded."
    echo "  ✓ generator dedups the name universe independently and keeps the defining-file mapping."

    echo "==> xinchuang-matrix guard self-test (canonical-complement inventory contract, r2.3)"
    neither_dir="$tmpdir/name-neither"
    grep -v '^bump_email_state,' "$real_csv" >"$tmpdir/neither.csv"
    produce_triple "$tmpdir/neither.csv" "$neither_dir"
    cp "$real_inv" "$neither_dir/inventory.csv" # name now in NEITHER file
    if grep -qF 'bump_email_state' "$neither_dir/inventory.csv"; then
      setup_fail "name-in-neither fixture inventory unexpectedly still carries bump_email_state."
    fi
    if run_on_dir "$neither_dir" "$guard_log"; then
      fail "guard accepted a live name present in NEITHER the CSV nor the inventory."
    fi
    assert_named "$guard_log" "NEITHER compatibility_matrix.csv nor unattested_functions.csv: bump_email_state" "name-in-neither fixture"
    echo "  ✓ guard fires on a name present in neither file and names it."
    both_dir="$tmpdir/name-both"
    produce_triple "$real_csv" "$both_dir"
    printf 'bump_email_state,bump_email_state.sql\n' >>"$both_dir/inventory.csv"
    grep -qF 'bump_email_state' "$both_dir/inventory.csv" || setup_fail "name-in-both fixture does not carry the planted inventory entry."
    if run_on_dir "$both_dir" "$guard_log"; then
      fail "guard accepted a name present in BOTH the CSV and the inventory."
    fi
    assert_named "$guard_log" "BOTH compatibility_matrix.csv and unattested_functions.csv: bump_email_state" "name-in-both fixture"
    echo "  ✓ guard fires on a name present in both files and names it."
    deadinv_dir="$tmpdir/dead-inventory"
    produce_triple "$real_csv" "$deadinv_dir"
    printf 'ghost_no_such_function,utils.sql\n' >>"$deadinv_dir/inventory.csv"
    grep -qF 'ghost_no_such_function' "$deadinv_dir/inventory.csv" || setup_fail "dead-inventory fixture does not carry the planted ghost entry."
    if run_on_dir "$deadinv_dir" "$guard_log"; then
      fail "guard accepted a dead inventory entry."
    fi
    assert_named "$guard_log" "dead inventory entry: ghost_no_such_function" "dead-inventory fixture"
    echo "  ✓ guard fires on a dead inventory entry and names it."
    dupinv_dir="$tmpdir/dup-inventory"
    produce_triple "$real_csv" "$dupinv_dir"
    first_inv_name="$(sed -n '2p' "$real_inv" | cut -d, -f1)"
    sed -n '2p' "$real_inv" >>"$dupinv_dir/inventory.csv"
    grep -qxF "$(sed -n '2p' "$real_inv")" "$dupinv_dir/inventory.csv" || setup_fail "dup-inventory fixture does not carry the duplicated entry."
    if run_on_dir "$dupinv_dir" "$guard_log"; then
      fail "guard accepted a duplicate inventory entry."
    fi
    assert_named "$guard_log" "duplicate inventory entry/entries: $first_inv_name" "duplicate-inventory fixture"
    echo "  ✓ guard fires on a duplicate inventory entry and names it."
    regeninv_dir="$tmpdir/regen-inventory"
    produce_triple "$real_csv" "$regeninv_dir"
    # drop one complement line: the committed inventory stops being the
    # byte-identical canonical complement.
    tail -n +3 "$real_inv" >"$regeninv_dir/inventory.csv"
    if run_on_dir "$regeninv_dir" "$guard_log"; then
      fail "guard accepted an inventory that is not the regenerated canonical complement."
    fi
    assert_named "$guard_log" "not the canonical complement" "inventory regeneration fixture"
    echo "  ✓ guard fires when the committed inventory is not the regenerated complement."

    # ── mutation check: the set comparison must be load-bearing (r2.4) ────────
    # Patch a COPY of this script stubbing ONLY check_set_consistency, then
    # prove (a) the mutated guard ACCEPTS the otherwise-consistent row-set
    # fixtures — dead row, duplicate live row, and the name-in-neither
    # complement fixture — so the rejections above are attributable to that
    # check alone, and (b) a full self-test run under the mutation FAILS at
    # the expected assertion. XINCHUANG_MATRIX_SELFTEST_SKIP_MUTATION keeps
    # the mutated copy from re-running this block.
    if [ -z "${XINCHUANG_MATRIX_SELFTEST_SKIP_MUTATION:-}" ]; then
      echo "==> xinchuang-matrix guard self-test (mutation: disabling the set comparison must make the tests fail)"
      mutated="$tmpdir/mutated-guard.sh"
      awk -v root="$ROOT" '
        index($0, "ROOT=\"${XINCHUANG_ROOT:-") == 1 { print "ROOT=\"" root "\""; next }
        $0 == "case \"${1:-}\" in" && !stubbed {
          print "check_set_consistency() { return 0; }  # MUTATION: set-comparison disabled"
          stubbed = 1
        }
        { print }
      ' "$0" >"$mutated"
      grep -q '^check_set_consistency() { return 0; }' "$mutated" ||
        setup_fail "could not build the set-comparison-disabled mutation copy of $0."
      grep -qF "ROOT=\"$ROOT\"" "$mutated" || setup_fail "mutation copy did not pin ROOT."
      for fixture_dir in "$dead_dir" "$dup_dir" "$neither_dir"; do
        if ! XINCHUANG_MATRIX_CSV="$fixture_dir/matrix.csv" \
          XINCHUANG_CAPS_CSV="$fixture_dir/caps.csv" \
          XINCHUANG_README="$fixture_dir/README.md" \
          XINCHUANG_INVENTORY="$fixture_dir/inventory.csv" \
          bash "$mutated" >"$guard_log" 2>&1; then
          sed 's/^/      /' "$guard_log" >&2
          setup_fail "with the set comparison disabled the guard still rejects ${fixture_dir##*/} — the row-set rejections were not attributable to the set comparison."
        fi
      done
      echo "  ✓ with the set comparison disabled the guard accepts all three row-set fixtures (dead row, duplicate row, name-in-neither)."
      if XINCHUANG_MATRIX_SELFTEST_SKIP_MUTATION=1 bash "$mutated" --self-test >"$guard_log" 2>&1; then
        fail "the self-test still PASSES with the set comparison disabled — the row-set assertions are vacuous."
      fi
      assert_named "$guard_log" "guard accepted a planted dead CSV row" "disabled-check self-test run"
      echo "  ✓ mutation check: disabling the set comparison makes the self-test FAIL on the dead-row fixture."
    fi
    echo "  xinchuang-matrix guard self-test: all cases green."
    exit 0
    ;;
esac

echo "==> Xinchuang certification-matrix guard"
if run_guard; then
  echo "    OK — matrix, capability grid, and complement inventory are consistent with the live"
  echo "        reducer sources; the README generated block is byte-identical to regeneration;"
  echo "        prose outside the sentinels carries no verdicts and no counts."
  exit 0
else
  echo "" >&2
  echo "  Xinchuang matrix drift (see ✗ lines). Sources of truth: mailserver/sql/xinchuang/" >&2
  echo "  {compatibility_matrix.csv,engine_capabilities.csv,unattested_functions.csv} + the live" >&2
  echo "  reducer functions. Regenerate with scripts/gen-xinchuang-doc.sh; the guard owns the rest." >&2
  exit 1
fi
