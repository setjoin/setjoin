#!/usr/bin/env bash
# Disposable real-Git fixtures for the read-only R5 collision checker.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/scripts/lib" "$fixture/docs/verification" "$fixture/mailserver/webmail/src/lib/admin"
cp "$ROOT/scripts/_base.sh" "$fixture/scripts/_base.sh"
cp "$ROOT/scripts/lib/source-fingerprint.mjs" "$fixture/scripts/lib/source-fingerprint.mjs"
cp "$ROOT/scripts/check-architecture-r5-cases.mjs" "$fixture/scripts/check-architecture-r5-cases.mjs"
cp "$ROOT/scripts/check-architecture-r5-collisions.sh" "$fixture/scripts/check-architecture-r5-collisions.sh"
cp "$ROOT/scripts/check-architecture-r5-collisions.test.sh" "$fixture/scripts/check-architecture-r5-collisions.test.sh"
cp "$ROOT/docs/verification/architecture-r5-cases.json" "$fixture/docs/verification/architecture-r5-cases.json"
printf 'touched-path collision hold released\n' >"$fixture/docs/architecture.md"
printf 'baseline\n' >"$fixture/mailserver/webmail/src/lib/admin/client.ts"
printf 'test-results/\n' >"$fixture/.gitignore"
git -C "$fixture" init -q -b main
git -C "$fixture" config user.name 'Architecture R5 Fixture'
git -C "$fixture" config user.email 'architecture-r5@example.invalid'
git -C "$fixture" add .
git -C "$fixture" commit -qm baseline
base="$(git -C "$fixture" rev-parse HEAD)"
node - "$fixture/docs/verification/architecture-r5-cases.json" "$base" <<'NODE'
const fs=require('node:fs');
const file=process.argv[2]; const registry=JSON.parse(fs.readFileSync(file));
registry.collisionBaselines.admin.baseCommit=process.argv[3];
fs.writeFileSync(file, `${JSON.stringify(registry,null,2)}\n`);
NODE

before="$(node "$fixture/scripts/lib/source-fingerprint.mjs" compute --root "$fixture")"
mkdir -p "$fixture/test-results"
(cd "$fixture" && ARCH_R5_COLLISION_RESULTS_ROOT="$fixture/test-results/pass" bash scripts/check-architecture-r5-collisions.sh admin >"$fixture/test-results/pass.out")
after="$(node "$fixture/scripts/lib/source-fingerprint.mjs" compute --root "$fixture")"
[[ "$before" == "$after" ]] || { echo 'E_ARCH_R5_COLLISION_TEST pass fixture changed worktree' >&2; exit 1; }
grep -q 'architecture-r5 collision: PASS' "$fixture/test-results/pass.out"
pass_receipt="$(find "$fixture/test-results/pass" -name receipt.json -print -quit)"
node - "$pass_receipt" "$base" <<'NODE'
const fs=require('node:fs'); const r=JSON.parse(fs.readFileSync(process.argv[2]));
if(r.status!=='pass'||r.source.baseCommit!==process.argv[3]||r.intersection.length!==0||r.candidatePaths.length<1)process.exit(1);
if(!/^v2:[0-9a-f]{40,64}:[0-9a-f]{64}$/.test(r.source.currentFingerprint))process.exit(1);
const [,commit,digest]=r.source.currentFingerprint.split(':');
if(r.source.currentCommit!==commit||r.source.dirtyDigest!==digest)process.exit(1);
NODE

# Moving the plan into the archive must not weaken the regular-file evidence
# boundary. The fixture has no implementation marker, so it must inspect the
# archived alternate marker and reject a symlink at that exact path.
archived_plan="$fixture/docs/architecture.md"
mv "$archived_plan" "$archived_plan.saved"
ln -s "$(basename "$archived_plan.saved")" "$archived_plan"
set +e
node "$fixture/scripts/check-architecture-r5-cases.mjs" evaluate admin >"$fixture/test-results/symlink.out" 2>&1
marker_status=$?
set -e
rm "$archived_plan"
mv "$archived_plan.saved" "$archived_plan"
[[ "$marker_status" -eq 1 ]] || { echo 'E_ARCH_R5_COLLISION_TEST archived symlink marker was not refused' >&2; exit 1; }
grep -q 'marker is not a regular file' "$fixture/test-results/symlink.out"

printf 'owner release\n' >>"$fixture/mailserver/webmail/src/lib/admin/client.ts"
git -C "$fixture" add mailserver/webmail/src/lib/admin/client.ts
git -C "$fixture" commit -qm 'owner release'
before="$(node "$fixture/scripts/lib/source-fingerprint.mjs" compute --root "$fixture")"
set +e
(cd "$fixture" && ARCH_R5_COLLISION_RESULTS_ROOT="$fixture/test-results/hold" bash scripts/check-architecture-r5-collisions.sh admin >"$fixture/test-results/hold.out" 2>"$fixture/test-results/hold.err")
status=$?
set -e
after="$(node "$fixture/scripts/lib/source-fingerprint.mjs" compute --root "$fixture")"
[[ "$status" -eq 3 ]] || { echo "E_ARCH_R5_COLLISION_TEST intersection exit=$status, want 3" >&2; exit 1; }
[[ "$before" == "$after" ]] || { echo 'E_ARCH_R5_COLLISION_TEST hold fixture changed worktree' >&2; exit 1; }
grep -q '^E_ARCH_R5_COLLISION_HOLD$' "$fixture/test-results/hold.err"
for field in problem cause location artifact fix rerun docs; do grep -q "^$field:" "$fixture/test-results/hold.err"; done
hold_receipt="$(find "$fixture/test-results/hold" -name receipt.json -print -quit)"
node - "$hold_receipt" <<'NODE'
const fs=require('node:fs'); const r=JSON.parse(fs.readFileSync(process.argv[2]));
if(r.status!=='hold'||!r.intersection.includes('mailserver/webmail/src/lib/admin/client.ts'))process.exit(1);
NODE

# One-commit public history: the registered private baseline is absent. The check
# must say BASELINE-ABSENT, fall back to the root commit and still evaluate.
solo="$(mktemp -d)"
trap 'rm -rf "$fixture" "$solo"' EXIT
git clone -q --depth 1 "file://$fixture" "$solo"
node - "$solo/docs/verification/architecture-r5-cases.json" <<'NODE'
const fs=require('node:fs');
const file=process.argv[2]; const registry=JSON.parse(fs.readFileSync(file));
registry.collisionBaselines.admin.baseCommit='0123456789abcdef0123456789abcdef01234567';
fs.writeFileSync(file, `${JSON.stringify(registry,null,2)}\n`);
NODE
solo_head="$(git -C "$solo" rev-parse HEAD)"
(cd "$solo" && ARCH_R5_COLLISION_RESULTS_ROOT="$fixture/test-results/absent" bash scripts/check-architecture-r5-collisions.sh admin >"$fixture/test-results/absent.out" 2>"$fixture/test-results/absent.err")
grep -q 'BASELINE-ABSENT' "$fixture/test-results/absent.err"
grep -q 'architecture-r5 collision: PASS' "$fixture/test-results/absent.out"
absent_receipt="$(find "$fixture/test-results/absent" -name receipt.json -print -quit)"
node - "$absent_receipt" "$solo_head" <<'NODE'
const fs=require('node:fs'); const r=JSON.parse(fs.readFileSync(process.argv[2]));
if(r.status!=='pass'||r.source.baseCommit!==process.argv[3]||r.intersection.length!==0)process.exit(1);
NODE
# With history, an absent baseline falls back to the root commit and still holds on a real intersection.
node - "$fixture/docs/verification/architecture-r5-cases.json" <<'NODE'
const fs=require('node:fs');
const file=process.argv[2]; const registry=JSON.parse(fs.readFileSync(file));
registry.collisionBaselines.admin.baseCommit='0123456789abcdef0123456789abcdef01234567';
fs.writeFileSync(file, `${JSON.stringify(registry,null,2)}\n`);
NODE
set +e
(cd "$fixture" && ARCH_R5_COLLISION_RESULTS_ROOT="$fixture/test-results/absent-hold" bash scripts/check-architecture-r5-collisions.sh admin >/dev/null 2>"$fixture/test-results/absent-hold.err")
status=$?
set -e
[[ "$status" -eq 3 ]] || { echo "E_ARCH_R5_COLLISION_TEST absent-baseline intersection exit=$status, want 3" >&2; exit 1; }
grep -q 'BASELINE-ABSENT' "$fixture/test-results/absent-hold.err"

echo 'architecture-r5 collision checker self-test: PASS (no-intersection, intersection, archived regular-file marker, BASELINE-ABSENT fallback, source receipt, unchanged worktree)'
