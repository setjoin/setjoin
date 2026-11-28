#!/usr/bin/env bash
# Formats the Rust files this branch ADDS: the same set the PR pre-check checks.
# Selection mirrors scripts/ci/quick-check.sh, step "rustfmt --check added files", but compares
# BASE to the working tree, so files staged with `git add` but not yet committed are included:
#   git diff --name-only --diff-filter=A "$BASE" -- '*.rs'   (BASE = LANE_QC_BASE or origin/main)
# Parity: once committed and clean, this equals quick-check's "$BASE...HEAD" (the merge-base diff).
# Untracked files are not listed; run `git add` first.
# Each file goes through rustfmt on stdin, so `mod x;` children are not rewritten
# (same reason as quick-check-tests.sh fmt).
#   bash scripts/ci/fmt-added.sh           format in place
#   bash scripts/ci/fmt-added.sh --check   report unformatted files, exit 1, write nothing
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

check=0
case "${1:-}" in
  "") ;;
  --check) check=1 ;;
  *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

BASE="${LANE_QC_BASE:-origin/main}"
# Fork point, as quick-check's "$BASE...HEAD" uses; compared with the working tree so staged files count.
if ! fork="$(git merge-base "$BASE" HEAD)" || ! listing="$(git diff --name-only --diff-filter=A "$fork" -- '*.rs')"; then
  echo "fmt-added: git diff against $BASE failed" >&2
  exit 1
fi
files=()
while IFS= read -r f; do
  [ -n "$f" ] && files+=("$f")
done <<< "$listing"
if [ "${#files[@]}" -eq 0 ]; then
  echo "fmt-added: no Rust file added (staged or committed) relative to $BASE"
  exit 0
fi

tmp="$(mktemp "${TMPDIR:-/tmp}/fmt-added.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
rc=0
for f in "${files[@]}"; do
  if ! rustfmt --edition 2021 < "$f" > "$tmp"; then
    echo "fmt-added: rustfmt failed on $f" >&2
    rc=1
    continue
  fi
  if [ "$check" -eq 1 ]; then
    if ! cmp -s "$f" "$tmp"; then
      echo "unformatted: $f"
      rc=1
    fi
  elif ! cmp -s "$f" "$tmp"; then
    mv "$tmp" "$f"
    tmp="$(mktemp "${TMPDIR:-/tmp}/fmt-added.XXXXXX")"
    echo "formatted: $f"
  fi
done
if [ "$rc" -eq 0 ]; then
  echo "fmt-added: ${#files[@]} added Rust file(s) checked"
fi
exit "$rc"
