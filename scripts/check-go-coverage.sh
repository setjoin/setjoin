#!/usr/bin/env bash
# Self-test and structural guard for the Go block-coverage ratchet.
source "$(dirname "$0")/_base.sh"
set -euo pipefail

REPORTER="$ROOT/scripts/report-go-coverage.mjs"

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/test-results/coverage/go" "$tmp/docs/verification" "$tmp/example" "$tmp/config"
  cat > "$tmp/example/go.mod" <<'GOMOD'
module example

go 1.26
GOMOD
  cat > "$tmp/config/go-modules.json" <<'JSON'
{"schemaVersion":1,"modules":[{"id":"example","path":"example","workspace":true,"kind":"library","capabilities":["test","coverage"]}]}
JSON
  cat > "$tmp/test-results/coverage/go/example.out" <<'PROFILE'
mode: atomic
example/pkg/a.go:1.1,2.2 2 1
example/pkg/a.go:4.1,5.2 1 0
example/pkg/a.go:1.1,2.2 2 0
example/pkg/a.go:4.1,5.2 1 0
PROFILE
  cat > "$tmp/docs/verification/go-coverage-thresholds.json" <<'JSON'
{"schemaVersion":1,"modules":{"example":60},"criticalPackages":{"example/pkg":60},"changedLines":{"minimum":90,"criticalMinimum":95,"exclude":["**/*_test.go","**/doc.go"]}}
JSON
  cat > "$tmp/covered.diff" <<'DIFF'
diff --git a/example/pkg/a.go b/example/pkg/a.go
--- a/example/pkg/a.go
+++ b/example/pkg/a.go
@@ -0,0 +1,2 @@
+covered first line
+covered continuation line
DIFF
  node "$REPORTER" --root "$tmp" --modules example --diff-file covered.diff --mode enforce >/dev/null

  cat > "$tmp/uncovered.diff" <<'DIFF'
diff --git a/example/pkg/a.go b/example/pkg/a.go
--- a/example/pkg/a.go
+++ b/example/pkg/a.go
@@ -0,0 +4,1 @@
+uncovered line
DIFF
  if node "$REPORTER" --root "$tmp" --modules example --diff-file uncovered.diff --mode enforce >/dev/null 2>&1; then
    echo "go-coverage self-test: uncovered changed Go line was accepted" >&2
    exit 1
  fi

  cat > "$tmp/test-results/coverage/go/example.out" <<'PROFILE'
mode: atomic
example/pkg/a.go:1.1,9.2 9 1
example/pkg/a.go:10.1,10.2 1 0
PROFILE
  cat > "$tmp/critical-band.diff" <<'DIFF'
diff --git a/example/pkg/a.go b/example/pkg/a.go
--- a/example/pkg/a.go
+++ b/example/pkg/a.go
@@ -0,0 +1,10 @@
+covered 1
+covered 2
+covered 3
+covered 4
+covered 5
+covered 6
+covered 7
+covered 8
+covered 9
+uncovered 10
DIFF
  if node "$REPORTER" --root "$tmp" --modules example --diff-file critical-band.diff --mode enforce >/dev/null 2>&1; then
    echo "go-coverage self-test: 90% critical changed coverage bypassed the 95% gate" >&2
    exit 1
  fi
  node -e 'const r=require(process.argv[1]); if(r.changedLines.status!=="critical-below-threshold") process.exit(1)' "$tmp/test-results/coverage/go-summary.json"

  cat > "$tmp/docs/verification/go-coverage-thresholds.json" <<'JSON'
{"schemaVersion":1,"modules":{"example":60},"criticalPackages":{},"changedLines":{"minimum":90,"criticalMinimum":95,"exclude":["**/*_test.go","**/doc.go"]}}
JSON
  node "$REPORTER" --root "$tmp" --modules example --diff-file critical-band.diff --mode enforce >/dev/null

  cat > "$tmp/test-results/coverage/go/example.out" <<'PROFILE'
mode: atomic
example/pkg/a.go:1.1,2.2 2 1
example/pkg/a.go:4.1,5.2 1 0
example/pkg/a.go:1.1,2.2 2 0
example/pkg/a.go:4.1,5.2 1 0
PROFILE
  cat > "$tmp/docs/verification/go-coverage-thresholds.json" <<'JSON'
{"schemaVersion":1,"modules":{"example":60},"criticalPackages":{"example/pkg":60},"changedLines":{"minimum":90,"criticalMinimum":95,"exclude":["**/*_test.go","**/doc.go"]}}
JSON

  cat > "$tmp/unattributed.diff" <<'DIFF'
diff --git a/example/pkg/new.go b/example/pkg/new.go
--- /dev/null
+++ b/example/pkg/new.go
@@ -0,0 +1,1 @@
+package pkg
DIFF
  if node "$REPORTER" --root "$tmp" --modules example --diff-file unattributed.diff --mode enforce >/dev/null 2>&1; then
    echo "go-coverage self-test: unattributed changed Go file was accepted" >&2
    exit 1
  fi

  cat > "$tmp/docs/verification/go-coverage-thresholds.json" <<'JSON'
{"schemaVersion":1,"modules":{"example":70},"criticalPackages":{"example/pkg":70},"changedLines":{"minimum":90,"criticalMinimum":95,"exclude":["**/*_test.go","**/doc.go"]}}
JSON
  if node "$REPORTER" --root "$tmp" --modules example --diff-file covered.diff --mode enforce >/dev/null 2>&1; then
    echo "go-coverage self-test: below-threshold profile was accepted" >&2
    exit 1
  fi
  rm "$tmp/test-results/coverage/go/example.out"
  if node "$REPORTER" --root "$tmp" --modules example --diff-file covered.diff --mode enforce >/dev/null 2>&1; then
    echo "go-coverage self-test: missing profile was accepted" >&2
    exit 1
  fi

  repo="$tmp/repo"
  mkdir -p "$repo/example/pkg" "$repo/docs/verification" "$repo/test-results/coverage/go" "$repo/config"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.email test@example.invalid
  git -C "$repo" config user.name 'Go Coverage Self-Test'
  cat > "$repo/example/go.mod" <<'GOMOD'
module example

go 1.26
GOMOD
  cat > "$repo/config/go-modules.json" <<'JSON'
{"schemaVersion":1,"modules":[{"id":"example","path":"example","workspace":true,"kind":"library","capabilities":["test","coverage"]}]}
JSON
  cat > "$repo/example/pkg/a.go" <<'GO'
package pkg

func Value() int { return 1 }
GO
  git -C "$repo" add example
  git -C "$repo" commit -q -m base
  merge_base="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" switch -q -c feature
  cat > "$repo/example/pkg/a.go" <<'GO'
package pkg

func Value() int { return 2 }
GO
  git -C "$repo" add example/pkg/a.go
  git -C "$repo" commit -q -m feature
  git -C "$repo" switch -q main
  printf 'main-only\n' > "$repo/example/main-only.txt"
  git -C "$repo" add example/main-only.txt
  git -C "$repo" commit -q -m main
  [[ "$(git -C "$repo" rev-parse main)" != "$merge_base" ]]
  git -C "$repo" switch -q feature
  cat > "$repo/docs/verification/go-coverage-thresholds.json" <<'JSON'
{"schemaVersion":1,"modules":{"example":0},"criticalPackages":{},"changedLines":{"minimum":100,"criticalMinimum":100,"exclude":["**/*_test.go","**/doc.go"]}}
JSON
  cat > "$repo/test-results/coverage/go/example.out" <<'PROFILE'
mode: atomic
example/pkg/a.go:1.1,3.31 1 1
PROFILE
  node "$REPORTER" --root "$repo" --modules example --base main --mode enforce >/dev/null
  grep -Fq "\"base\": \"$merge_base\"" "$repo/test-results/coverage/go-summary.json"

  cat > "$repo/example/pkg/untracked.go" <<'GO'
package pkg

func Untracked() int { return 3 }
GO
  if node "$REPORTER" --root "$repo" --modules example --base main --mode enforce >/dev/null 2>&1; then
    echo "go-coverage self-test: untracked Go source bypassed changed-line attribution" >&2
    exit 1
  fi

  rm "$repo/example/pkg/untracked.go"
  mkdir "$repo/example/pkg/untracked-target"
  ln -s untracked-target "$repo/example/pkg/untracked-directory.go"
  node "$REPORTER" --root "$repo" --modules example --base main --mode enforce >/dev/null

  echo "go-coverage self-test: PASS (whole-module duplicate merge, module/package floors, changed spans, isolated critical threshold, unattributed file, missing profile, merge-base, untracked source, untracked directory symlink)"
  exit 0
fi

if [[ $# -ne 0 ]]; then
  echo "usage: check-go-coverage.sh [--self-test]" >&2
  exit 2
fi

node --check "$REPORTER"
node -e 'const fs=require("fs"); const c=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); if(c.schemaVersion!==1||typeof c.modules!=="object"||typeof c.criticalPackages!=="object"||typeof c.changedLines!=="object"||!Array.isArray(c.changedLines.exclude)) process.exit(1)' "$ROOT/docs/verification/go-coverage-thresholds.json"
echo "go-coverage guard: PASS"
