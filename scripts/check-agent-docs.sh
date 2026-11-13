#!/usr/bin/env bash
# Front door for agent-instruction checks: context budget and rail links and
# anchors.
# Usage: bash scripts/check-agent-docs.sh [--self-test]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# check_links DIR: every link in the hot rails/docs of the git checkout at DIR
# resolves, including DOX/heading anchors and incoming AGENTS.md anchors.
check_links() {
  (
    cd "$1" && python3 -I - <<'PY'
import pathlib, re, subprocess, sys

def tracked(*specs):
    out = subprocess.run(["git", "ls-files", "-z", "--", *specs], capture_output=True, check=True)
    return [pathlib.Path(p) for p in out.stdout.decode().split("\0")
            if p and not p.startswith("handover") and pathlib.Path(p).is_file()]

def slugs(path, cache={}):
    if path not in cache:
        seen, found, fence = {}, set(), False
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("```"):
                fence = not fence
            if fence or not re.match(r"^#{1,6} ", line):
                continue
            s = re.sub(r"[^\w\- ]", "", re.sub(r"^#+ ", "", line).strip().lower()).replace(" ", "-")
            n = seen.get(s, 0)
            seen[s] = n + 1
            found.add(s if n == 0 else f"{s}-{n}")
        cache[path] = found
    return cache[path]

LINK = re.compile(r"\]\(([^)\s]+)\)")
bad = []

def check(src, target):
    if re.match(r"^[a-z][a-z0-9+.-]*:", target):
        return
    file, _, anchor = target.partition("#")
    dest = (src.parent / file).resolve() if file else src.resolve()
    if not dest.exists():
        bad.append(f"{src}: missing {target}")
    elif anchor and dest.suffix == ".md" and not re.match(r"^L\d+(-L\d+)?$", anchor) and anchor not in slugs(dest):
        bad.append(f"{src}: unresolved anchor {target}")

hot = tracked("AGENTS.md", "*/AGENTS.md", "CONTRIBUTING.md", "docs/agents/*.md",
              "docs/guides/TASK_EXECUTION_AND_CLEANUP.md", "docs/guides/VERIFICATION_COMMANDS.md")
for src in hot:
    for target in LINK.findall(src.read_text(encoding="utf-8")):
        check(src, target)

# Incoming links into any AGENTS.md anchor, from live Markdown. Frozen review
# transcripts and archives keep the paths they were written with.
FROZEN = ("docs/archive/",)
for src in tracked("*.md"):
    if src in hot or str(src).startswith(FROZEN):
        continue
    for target in LINK.findall(src.read_text(encoding="utf-8")):
        if re.search(r"(^|/)AGENTS\.md#", target):
            check(src, target)

for line in bad:
    print(f"AGENT-DOCS-FAIL: {line}", file=sys.stderr)
print(f"agent-docs: {len(hot)} rails/docs checked; {len(bad)} broken link(s)")
sys.exit(1 if bad else 0)
PY
  )
}

self_test() {
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/check-agent-docs-selftest.XXXXXX")"
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/sub"
  printf '# Root\n\n## Section one\n\n- [child](sub/AGENTS.md)\n' >"$tmp/AGENTS.md"
  printf '# Child\n\n- [root](../AGENTS.md#section-one)\n' >"$tmp/sub/AGENTS.md"
  git -C "$tmp" init -q && git -C "$tmp" add -A
  check_links "$tmp" >/dev/null 2>&1 || {
    echo "self-test: clean links reported broken" >&2
    return 1
  }

  printf -- '- [gone](sub/MISSING.md)\n' >>"$tmp/AGENTS.md"
  git -C "$tmp" add -A
  if check_links "$tmp" >/dev/null 2>&1; then
    echo "self-test: missing file not caught" >&2
    return 1
  fi
  printf '# Root\n\n## Section one\n\n- [child](sub/AGENTS.md)\n' >"$tmp/AGENTS.md"
  printf '# Child\n\n- [root](../AGENTS.md#renamed-section)\n' >"$tmp/sub/AGENTS.md"
  git -C "$tmp" add -A
  if check_links "$tmp" >/dev/null 2>&1; then
    echo "self-test: stale anchor not caught" >&2
    return 1
  fi
  echo "check-agent-docs self-test: PASS (missing file, stale anchor caught)"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit
fi

cd "$ROOT"
echo "==> agent-docs: context budget"
bash scripts/check-agent-context-budget.sh

echo "==> agent-docs: rail links and anchors"
check_links "$ROOT"

echo "agent-docs: PASS"
