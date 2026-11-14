#!/usr/bin/env bash
# Build and verify the one-commit public tree from a private-repo commit.
#
# Usage:
#   scripts/public-export.sh --sha <commit> --out <empty dir> \
#       --gitleaks <path to gitleaks binary> [--dry-run] [--force]
#
# The script never runs git init/commit/push or gh; it only prints them.
set -euo pipefail

# ---------------------------------------------------------------------------
# EXCLUDE LIST: paths (relative to the tree root) removed from the export.
# Directories are removed recursively. Edit here, nowhere else.
# ---------------------------------------------------------------------------
EXCLUDE_PATHS=(
  ".claude"
  ".codex"
  ".agents"
  ".mcp.json"
  "opencode.json"
  ".watchexec.toml"
  "SELLING_POINTS.md"
  "TODOS.md"
  # junk dirs, in case the sha predates their deletion
  ".zcode-security-deep"
  ".glm-plan-review"
  ".claire"
  ".superpowers"
  "docs/superpowers"
  "docs/archive/agent-context"
  "clients/harmonyos/local.properties"
)

# Forbidden patterns, case-insensitive, searched in every text file of the
# exported tree. Format: "<fixed|regex>@@<pattern>@@<space-separated exempt paths>".
# Exemptions (tree-relative) and why:
#  - scripts/security-program.mjs, scripts/verify-security-program.test.sh keep two
#    historical host-class labels: the retained DX benchmark
#    (docs/verification/security-coverage-dx-benchmark-2026-10-29.json,
#    sourceBinding.controlSourceSha256) binds the sha256 of security-program.mjs and
#    the test asserts the same labels. Changing them needs a new frozen epoch.
#  - scripts/check-workflow-log-hygiene.sh holds self-hosted labels as self-test
#    fixtures; it is the guard that bans them from workflows.
# "self-hosted" alone is a product term (self-hosted mail server); it is only
# forbidden in non-comment workflow lines (check below) and as a runner label.
FORBIDDEN_RULES=(
  "fixed@@/Users/cat@@"
  "fixed@@/home/cat@@"
  "fixed@@ubuntu-ci@@scripts/security-program.mjs scripts/verify-security-program.test.sh"
  "fixed@@bubbleofmoon@@"
  "fixed@@guardian@@"
  "fixed@@m920x@@scripts/security-program.mjs scripts/verify-security-program.test.sh"
  "fixed@@mac-ci-m@@scripts/security-program.mjs scripts/verify-security-program.test.sh"
  "fixed@@imap-mac-ci@@"
  "fixed@@Mac M5@@"
  "fixed@@NEXT/command-line-tools@@"
  "fixed@@/root/go-mod-cache@@"
  "fixed@@/root/.local/bin@@"
  "fixed@@.claude/jobs/@@"
  "regex@@(^|[^a-z0-9])ex1([^a-z0-9]|$)@@"
  "regex@@runs-on:.*self-hosted@@scripts/check-workflow-log-hygiene.sh"
  "regex@@\[self-hosted@@scripts/check-workflow-log-hygiene.sh"
)

MAX_TREE_MB=600
SELF_REL="scripts/public-export.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ALLOW_FILE_DEFAULT="$SCRIPT_DIR/public-export.allow"

SHA="" OUT="" GITLEAKS="" DRY_RUN=0 FORCE=0
FAILS=()
TMP_DIR=""

die() { printf 'error: %s\n' "$*" >&2; exit 2; }
fail() { FAILS+=("$1"); printf 'FAIL: %s\n' "$1"; }
ok() { printf 'ok:   %s\n' "$1"; }

cleanup() { [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf -- "$TMP_DIR"; return 0; }
trap cleanup EXIT

usage() {
  sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 2
}

while (($#)); do
  case "$1" in
    --sha) SHA="${2:?--sha needs a value}"; shift 2 ;;
    --out) OUT="${2:?--out needs a value}"; shift 2 ;;
    --gitleaks) GITLEAKS="${2:?--gitleaks needs a value}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$SHA" && -n "$OUT" && -n "$GITLEAKS" ]] || usage
[[ -x "$GITLEAKS" ]] || die "gitleaks binary not executable: $GITLEAKS"
command -v jq >/dev/null || die "jq is required"
command -v file >/dev/null || die "file is required"
GITLEAKS="$(cd "$(dirname "$GITLEAKS")" && pwd)/$(basename "$GITLEAKS")"

git -C "$REPO_ROOT" rev-parse --verify --quiet "$SHA^{commit}" >/dev/null \
  || die "not a commit: $SHA"
FULL_SHA="$(git -C "$REPO_ROOT" rev-parse "$SHA^{commit}")"

# --out safety: resolve physical paths first, refuse before anything is created
# or wiped. A wipe target must not be "/", $HOME, the repo checkout, an ancestor
# of the checkout, or anything inside the checkout.
unsafe_out_reason() { # out repo-root home -> prints reason, returns 0 when unsafe
  local o="$1" r="$2" h="$3"
  [[ "$o" == "/" ]] && { echo "is the filesystem root"; return 0; }
  [[ -n "$h" && "$o" == "$h" ]] && { echo "is \$HOME"; return 0; }
  [[ "$o" == "$r" ]] && { echo "is the repository root"; return 0; }
  [[ "$r" == "$o"/* ]] && { echo "is an ancestor of the repository root"; return 0; }
  [[ "$o" == "$r"/* ]] && { echo "is inside the repository checkout"; return 0; }
  return 1
}
REPO_REAL="$(realpath -m -- "$REPO_ROOT")"
HOME_REAL="$(realpath -m -- "${HOME:-/nonexistent-home}")"
OUT_REAL="$(realpath -m -- "$OUT")"
if reason="$(unsafe_out_reason "$OUT_REAL" "$REPO_REAL" "$HOME_REAL")"; then
  die "refusing --out $OUT ($OUT_REAL): $reason"
fi
if [[ -n "${PUBLIC_EXPORT_CHECK_OUT_ONLY:-}" ]]; then echo "out path accepted: $OUT_REAL"; exit 0; fi

mkdir -p -- "$OUT_REAL"
OUT="$(cd "$OUT_REAL" && pwd -P)"
if reason="$(unsafe_out_reason "$OUT" "$REPO_REAL" "$HOME_REAL")"; then
  die "refusing --out $OUT: $reason"
fi
if [[ -n "$(ls -A -- "$OUT")" ]]; then
  ((FORCE)) || die "--out is not empty (use --force to wipe it): $OUT"
  find "$OUT" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
fi

TMP_DIR="$(mktemp -d)"

# --- 1. archive -------------------------------------------------------------
echo "== extracting $FULL_SHA into $OUT"
git -C "$REPO_ROOT" archive --format=tar "$FULL_SHA" | tar -x -C "$OUT"

# --- 2. exclude list --------------------------------------------------------
echo "== removing exclude list"
removed=0
for rel in "${EXCLUDE_PATHS[@]}"; do
  if [[ -e "$OUT/$rel" || -L "$OUT/$rel" ]]; then
    rm -rf -- "${OUT:?}/$rel"
    removed=$((removed + 1))
    echo "   removed $rel"
  fi
done

# --- 3. verification --------------------------------------------------------
echo "== verifying tree"

# (a) gitleaks
echo "-- (a) gitleaks"
REPORT="$TMP_DIR/gitleaks.json"
set +e
"$GITLEAKS" dir "$OUT" --redact --no-banner --no-color --exit-code 0 \
  --report-format json --report-path "$REPORT" --log-level error >"$TMP_DIR/gitleaks.log" 2>&1
gl_rc=$?
set -e
if ((gl_rc != 0)) || [[ ! -s "$REPORT" ]]; then
  fail "gitleaks failed to run (rc=$gl_rc): $(tail -n 3 "$TMP_DIR/gitleaks.log" | tr '\n' ' ')"
else
  total="$(jq 'length' "$REPORT")"
  # normalise file paths relative to the tree root
  jq -r --arg root "$OUT/" '.[] | [.RuleID, (.File | ltrimstr($root))] | @tsv' "$REPORT" >"$TMP_DIR/findings.tsv"
  ALLOW_FILE="$ALLOW_FILE_DEFAULT"
  [[ -f "$ALLOW_FILE" ]] || ALLOW_FILE="$OUT/scripts/public-export.allow"
  if [[ ! -f "$ALLOW_FILE" ]]; then
    echo "   no allow-list (scripts/public-export.allow); findings per rule: total=$total"
    cut -f1 "$TMP_DIR/findings.tsv" | sort | uniq -c | sort -rn | sed 's/^/     /'
    if ((total > 0)); then
      if ((DRY_RUN)); then
        echo "   (dry-run: reporting only for the missing allow-list)"
      else
        fail "gitleaks: $total finding(s) and no allow-list file"
      fi
    else
      ok "gitleaks: no findings"
    fi
  else
    globs=()
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
      [[ -n "$line" ]] && globs+=("$line")
    done <"$ALLOW_FILE"
    : >"$TMP_DIR/unallowed.tsv"
    allowed=0
    while IFS=$'\t' read -r rule path; do
      hit=0
      for g in "${globs[@]+"${globs[@]}"}"; do
        # shellcheck disable=SC2254
        case "$path" in $g) hit=1; break ;; esac
      done
      if ((hit)); then allowed=$((allowed + 1)); else printf '%s\t%s\n' "$rule" "$path" >>"$TMP_DIR/unallowed.tsv"; fi
    done <"$TMP_DIR/findings.tsv"
    bad="$(wc -l <"$TMP_DIR/unallowed.tsv" | tr -d ' ')"
    if ((bad > 0)); then
      echo "   findings: total=$total allowed=$allowed not-allowed=$bad; per rule:"
      cut -f1 "$TMP_DIR/unallowed.tsv" | sort | uniq -c | sort -rn | sed 's/^/     /'
      echo "   top paths:"
      cut -f2 "$TMP_DIR/unallowed.tsv" | sort | uniq -c | sort -rn | head -10 | sed 's/^/     /' || true
      fail "gitleaks: $bad finding(s) outside the allow-list"
    else
      ok "gitleaks: $total finding(s), all allow-listed ($allowed)"
    fi
  fi
fi

# (b) forbidden patterns
echo "-- (b) forbidden patterns"
forbidden_total=0
check_pattern() { # mode pattern exempt-paths
  local mode="$1" pat="$2" exempt="$3" flag out count files
  [[ "$mode" == fixed ]] && flag="-F" || flag="-E"
  out="$TMP_DIR/hits.txt"
  (cd "$OUT" && grep -rIi $flag -c --exclude-dir=.git -e "$pat" -- . 2>/dev/null) \
    | awk -F: '{n=$NF; if (n>0) {sub(/:[0-9]+$/,""); sub(/^\.\//,""); print n "\t" $0}}' \
    | awk -F'\t' -v self="$SELF_REL" -v ex="$exempt" \
        'BEGIN{k=split(ex,a," "); for(i=1;i<=k;i++) skip[a[i]]=1; skip[self]=1} !($2 in skip)' >"$out"
  count="$(awk -F'\t' '{s+=$1} END{print s+0}' "$out")"
  if ((count > 0)); then
    forbidden_total=$((forbidden_total + count))
    files="$(wc -l <"$out" | tr -d ' ')"
    fail "forbidden '$pat': $count line(s) in $files file(s)"
    { sort -rn "$out" | head -5 | awk -F'\t' '{printf "       %6d  %s\n", $1, $2}'; } || true
  fi
}
for rule in "${FORBIDDEN_RULES[@]}"; do
  r_mode="${rule%%@@*}"; r_rest="${rule#*@@}"
  check_pattern "$r_mode" "${r_rest%%@@*}" "${r_rest#*@@}"
done
# Workflows: no non-comment "self-hosted" at all (labels, lists, JSON strings).
if [[ -d "$OUT/.github/workflows" ]]; then
  wf_hits="$(cd "$OUT" && grep -rniI --include='*.yml' --include='*.yaml' -e 'self-hosted' -- .github/workflows 2>/dev/null \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)"
  if [[ -n "$wf_hits" ]]; then
    wf_n="$(printf '%s\n' "$wf_hits" | wc -l | tr -d ' ')"
    forbidden_total=$((forbidden_total + wf_n))
    fail "workflows: $wf_n non-comment 'self-hosted' line(s)"
    printf '%s\n' "$wf_hits" | head -5 | sed 's/^/       /'
  fi
fi
((forbidden_total == 0)) && ok "no forbidden patterns"

# (c) binaries
echo "-- (c) executable binaries (ELF / Mach-O / PE)"
SEP='::SEP::'
(cd "$OUT" && find . -path ./.git -prune -o -type f -print0 \
  | xargs -0 -r file --no-pad -F "$SEP" 2>/dev/null) \
  | grep -E "${SEP}[[:space:]]*(ELF |Mach-O|PE32|PE32\+|MS-DOS executable)" >"$TMP_DIR/bins.txt" || true
nbin="$(wc -l <"$TMP_DIR/bins.txt" | tr -d ' ')"
if ((nbin > 0)); then
  fail "binaries: $nbin ELF/Mach-O/PE file(s)"
  head -20 "$TMP_DIR/bins.txt" | sed "s/${SEP}/  =>  /; s/^/       /"
else
  ok "no ELF/Mach-O/PE files"
fi

# (d) LICENSE
echo "-- (d) LICENSE"
if [[ -f "$OUT/LICENSE" ]]; then
  first="$(head -n 1 "$OUT/LICENSE")"
  if [[ "$first" == "# PolyForm"* ]]; then ok "LICENSE starts with '# PolyForm'"
  else fail "LICENSE first line is not '# PolyForm...' (got: ${first:0:60})"; fi
else
  fail "LICENSE is missing"
fi

# (e) size
echo "-- (e) tree size"
size_kb="$(du -sk --exclude=.git "$OUT" | cut -f1)"
size_mb=$((size_kb / 1024))
echo "   tree size: ${size_mb} MB (limit ${MAX_TREE_MB} MB); 20 largest files:"
(cd "$OUT" && find . -path ./.git -prune -o -type f -printf '%s\t%p\n' | sort -rn | head -20 \
  | awk -F'\t' '{printf "     %10.1f MB  %s\n", $1/1048576, $2}') || true
if ((size_mb >= MAX_TREE_MB)); then fail "tree is ${size_mb} MB, limit ${MAX_TREE_MB} MB"
else ok "tree under ${MAX_TREE_MB} MB"; fi

# (f) README placeholders
echo "-- (f) README placeholders"
if [[ ! -f "$OUT/README.md" ]]; then
  fail "README.md is missing"
elif grep -nF '<CONTACT>' "$OUT/README.md" >"$TMP_DIR/contact.txt"; then
  if ((DRY_RUN)); then
    echo "   WARN: README.md still has a <CONTACT> placeholder (dry-run: not failing)"
    sed 's/^/       /' "$TMP_DIR/contact.txt"
  else
    fail "README.md still has a <CONTACT> placeholder (line $(cut -d: -f1 "$TMP_DIR/contact.txt" | paste -sd, -))"
  fi
else
  ok "README.md has no <CONTACT> placeholder"
fi

# --- 4. summary -------------------------------------------------------------
nfiles="$(find "$OUT" -path "$OUT/.git" -prune -o -type f -print | wc -l | tr -d ' ')"
echo
echo "== summary"
echo "   source sha : $FULL_SHA"
echo "   output     : $OUT"
echo "   files      : $nfiles   excluded paths removed: $removed"
echo "   size       : ${size_mb} MB"
if ((${#FAILS[@]} > 0)); then
  echo "   RESULT     : FAILED (${#FAILS[@]} check(s))"
  for f in "${FAILS[@]}"; do echo "     - $f"; done
  exit 1
fi
echo "   RESULT     : all checks passed"

# --- 5. next commands (printed only, never run) -----------------------------
if ((DRY_RUN)); then
  echo "   (dry-run: next-step commands not printed)"
  exit 0
fi
cat <<EOF

== next commands for the owner (NOT executed by this script)
cd "$OUT"
git init -b main
# --force: tracked files may match a .gitignore pattern (e.g. webmail coverage/ route)
git add -A --force
git commit -m "Initial public release"
gh repo create <owner>/<name> --public --source=. --remote=origin --description "Setjoin"
git push -u origin main
EOF
