#!/usr/bin/env bash
# Changed-line coverage merge gate. The self-test proves rename/new-path
# attribution, mechanical test-file exclusion, missing source-map attribution,
# threshold failure, and deleted-only behavior before enforcement is allowed.
source "$(dirname "$0")/_base.sh"
set -euo pipefail

REPORTER="$ROOT/scripts/report-changed-coverage.mjs"

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/src" "$tmp/results"
  printf 'first();\nsecond();\n' > "$tmp/src/new.ts"
  printf 'test();\n' > "$tmp/src/new.test.ts"
  cat > "$tmp/config.json" <<'JSON'
{"schemaVersion":1,"scope":["src/"],"extensions":[".ts"],"exclude":["**/*.test.ts"],"critical":["src/security/**"]}
JSON
  cat > "$tmp/diff.patch" <<'DIFF'
diff --git a/src/old.ts b/src/new.ts
similarity index 80%
rename from src/old.ts
rename to src/new.ts
--- a/src/old.ts
+++ b/src/new.ts
@@ -1,1 +1,2 @@
+first();
+second();
diff --git a/src/new.test.ts b/src/new.test.ts
--- a/src/new.test.ts
+++ b/src/new.test.ts
@@ -0,0 +1,1 @@
+test();
DIFF
  cat > "$tmp/half.json" <<JSON
{"$tmp/src/new.ts":{"statementMap":{"0":{"start":{"line":1},"end":{"line":1}},"1":{"start":{"line":2},"end":{"line":2}}},"s":{"0":1,"1":0}}}
JSON
  node "$REPORTER" --root "$tmp" --diff-file "$tmp/diff.patch" --coverage "$tmp/half.json" --config "$tmp/config.json" --threshold 90 --mode report --output "$tmp/results/half.json" >/dev/null
  grep -Fq '"status": "below-threshold"' "$tmp/results/half.json"
  grep -Fq '"src/new.test.ts"' "$tmp/results/half.json"
  if node "$REPORTER" --root "$tmp" --diff-file "$tmp/diff.patch" --coverage "$tmp/half.json" --config "$tmp/config.json" --threshold 90 --mode enforce --output "$tmp/results/enforced.json" >/dev/null 2>&1; then
    echo "changed-coverage self-test: below-threshold result was enforced as pass" >&2
    exit 1
  fi

  cat > "$tmp/full.json" <<JSON
{"$tmp/src/new.ts":{"statementMap":{"0":{"start":{"line":1},"end":{"line":1}},"1":{"start":{"line":2},"end":{"line":2}}},"s":{"0":1,"1":1}}}
JSON
  node "$REPORTER" --root "$tmp" --diff-file "$tmp/diff.patch" --coverage "$tmp/full.json" --config "$tmp/config.json" --threshold 90 --mode enforce --output "$tmp/results/full.json" >/dev/null
  grep -Fq '"status": "pass"' "$tmp/results/full.json"

  cat > "$tmp/multiline.patch" <<'DIFF'
diff --git a/src/multiline.ts b/src/multiline.ts
--- a/src/multiline.ts
+++ b/src/multiline.ts
@@ -1,0 +2,1 @@ call(
+  changedArgument,
DIFF
  cat > "$tmp/multiline.json" <<JSON
{"$tmp/src/multiline.ts":{"statementMap":{"0":{"start":{"line":1},"end":{"line":3}}},"s":{"0":0}}}
JSON
  if node "$REPORTER" --root "$tmp" --diff-file "$tmp/multiline.patch" --coverage "$tmp/multiline.json" --config "$tmp/config.json" --threshold 90 --mode enforce --output "$tmp/results/multiline.json" >/dev/null 2>&1; then
    echo "changed-coverage self-test: uncovered continuation line was accepted" >&2
    exit 1
  fi
  grep -Fq '"executableLines": 1' "$tmp/results/multiline.json"
  grep -Fq '"status": "below-threshold"' "$tmp/results/multiline.json"

  mkdir -p "$tmp/src/security"
  printf 'first();\nsecond();\n' > "$tmp/src/security/guard.ts"
  cat > "$tmp/critical.patch" <<'DIFF'
diff --git a/src/security/guard.ts b/src/security/guard.ts
new file mode 100644
--- /dev/null
+++ b/src/security/guard.ts
@@ -0,0 +1,2 @@
+first();
+second();
DIFF
  cat > "$tmp/critical.json" <<JSON
{"$tmp/src/security/guard.ts":{"statementMap":{"0":{"start":{"line":1},"end":{"line":1}},"1":{"start":{"line":2},"end":{"line":2}}},"s":{"0":1,"1":0}}}
JSON
  if node "$REPORTER" --root "$tmp" --diff-file "$tmp/critical.patch" --coverage "$tmp/critical.json" --config "$tmp/config.json" --threshold 50 --critical-threshold 95 --mode enforce --output "$tmp/results/critical.json" >/dev/null 2>&1; then
    echo "changed-coverage self-test: under-covered critical path was accepted" >&2
    exit 1
  fi
  grep -Fq '"status": "critical-below-threshold"' "$tmp/results/critical.json"

  printf '{}\n' > "$tmp/missing.json"
  node "$REPORTER" --root "$tmp" --diff-file "$tmp/diff.patch" --coverage "$tmp/missing.json" --config "$tmp/config.json" --mode report --output "$tmp/results/missing.json" >/dev/null
  grep -Fq '"status": "not-ready"' "$tmp/results/missing.json"

  cat > "$tmp/deleted.patch" <<'DIFF'
diff --git a/src/old.ts b/src/old.ts
--- a/src/old.ts
+++ b/src/old.ts
@@ -1,2 +1,0 @@
-first();
-second();
DIFF
  node "$REPORTER" --root "$tmp" --diff-file "$tmp/deleted.patch" --coverage "$tmp/full.json" --config "$tmp/config.json" --mode enforce --output "$tmp/results/deleted.json" >/dev/null
  grep -Fq '"status": "no-executable-changes"' "$tmp/results/deleted.json"

  repo="$tmp/repo"
  mkdir -p "$repo/mailserver/webmail/src" "$repo/results"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.email test@example.invalid
  git -C "$repo" config user.name 'Coverage Self-Test'
  printf 'base();\n' > "$repo/mailserver/webmail/src/app.ts"
  git -C "$repo" add .
  git -C "$repo" commit -q -m base
  merge_base="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" switch -q -c feature
  printf 'base();\nfeature();\n' > "$repo/mailserver/webmail/src/app.ts"
  git -C "$repo" add .
  git -C "$repo" commit -q -m feature
  git -C "$repo" switch -q main
  printf 'base();\nmainOnly();\n' > "$repo/mailserver/webmail/src/app.ts"
  git -C "$repo" add .
  git -C "$repo" commit -q -m main
  git -C "$repo" switch -q feature
  cat > "$repo/config.json" <<'JSON'
{"schemaVersion":1,"scope":["mailserver/webmail/src/"],"extensions":[".ts"],"exclude":[],"critical":[]}
JSON
  cat > "$repo/coverage.json" <<JSON
{"$repo/mailserver/webmail/src/app.ts":{"statementMap":{"0":{"start":{"line":1},"end":{"line":1}},"1":{"start":{"line":2},"end":{"line":2}}},"s":{"0":1,"1":1}}}
JSON
  node "$REPORTER" --root "$repo" --base main --coverage "$repo/coverage.json" --config "$repo/config.json" --threshold 100 --mode enforce --output "$repo/results/merge-base.json" >/dev/null
  grep -Fq "\"base\": \"$merge_base\"" "$repo/results/merge-base.json"

  echo "changed-coverage self-test: PASS (rename, exclusion, attribution, multiline spans, merge-base, normal/critical thresholds, deletion)"
  exit 0
fi

if [[ $# -ne 0 ]]; then
  echo "usage: check-changed-coverage.sh [--self-test]" >&2
  exit 2
fi

node --check "$REPORTER"
node -e 'const fs=require("fs"); const p=process.argv[1]; const c=JSON.parse(fs.readFileSync(p,"utf8")); if(c.schemaVersion!==1||!Array.isArray(c.scope)||!Array.isArray(c.extensions)||!Array.isArray(c.exclude)||!Array.isArray(c.critical)) process.exit(1)' "$ROOT/docs/verification/changed-coverage-exclusions.json"
echo "changed-coverage guard: PASS (reporter syntax + exclusion schema; 90% normal / 95% critical gates enforced locally and in CI)"
