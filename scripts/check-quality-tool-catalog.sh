#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG="${QUALITY_CATALOG:-$ROOT/config/quality-tools.json}"

validate() {
  node - "$CATALOG" "$ROOT" "${QUALITY_CATALOG_SCHEMA_ONLY:-0}" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const [catalogPath, root, schemaOnly] = process.argv.slice(2);
const data = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
if (data.schemaVersion !== 1) throw new Error('quality catalog schemaVersion must be 1');
for (const key of ['languages', 'tools']) {
  if (!Array.isArray(data[key]) || data[key].length === 0) throw new Error(`${key} must be a non-empty array`);
  const ids = data[key].map((item) => item.id);
  if (ids.some((id) => typeof id !== 'string' || !id)) throw new Error(`${key} contains an empty id`);
  const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
  if (duplicates.length) throw new Error(`${key} has duplicate id: ${duplicates[0]}`);
}
for (const language of data.languages) {
  if (typeof language.authored !== 'boolean') throw new Error(`${language.id}: authored must be boolean`);
  if (!Array.isArray(language.extensions) || language.extensions.length === 0) throw new Error(`${language.id}: extensions missing`);
  if (!language.owner || !language.runner) throw new Error(`${language.id}: owner/runner missing`);
}
for (const tool of data.tools) {
  if (!tool.license || !tool.status || tool.offline === undefined) throw new Error(`${tool.id}: license/status/offline missing`);
}
if (schemaOnly === '1') process.exit(0);

const quality = fs.readFileSync(path.join(root, 'scripts/quality.sh'), 'utf8');
for (const mode of ['list', 'doctor', 'fast', 'full', 'security']) {
  if (!quality.includes(`${mode})`)) throw new Error(`quality.sh is missing mode: ${mode}`);
}
const tracked = execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' }).split('\n');
const excluded = /(^|\/)(node_modules|refs|build|dist|test-results)\//;
const extensions = new Set();
for (const file of tracked) {
  if (!file || excluded.test(file) || file === 'mailserver/api/redoc.standalone.js') continue;
  const base = path.basename(file);
  if (/^Dockerfile/.test(base)) extensions.add('dockerfile');
  else if (base.includes('.')) extensions.add(base.split('.').pop().toLowerCase());
}
const classified = new Set(data.languages.flatMap((language) => language.extensions));
for (const extension of ['go', 'sql', 'pg', 'ts', 'svelte', 'css', 'rs', 'ets', 'sh', 'py', 'ps1', 'yml', 'yaml', 'json', 'json5', 'toml', 'dockerfile']) {
  if (extensions.has(extension) && !classified.has(extension)) throw new Error(`active extension is unclassified: ${extension}`);
}
NODE
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  jq '.languages += [.languages[0]]' "$CATALOG" >"$tmp"
  if QUALITY_CATALOG="$tmp" QUALITY_CATALOG_SCHEMA_ONLY=1 bash "$0" >/dev/null 2>&1; then
    echo "quality catalog self-test failed: duplicate language was accepted" >&2
    exit 1
  fi
  printf '{broken' >"$tmp"
  if QUALITY_CATALOG="$tmp" QUALITY_CATALOG_SCHEMA_ONLY=1 bash "$0" >/dev/null 2>&1; then
    echo "quality catalog self-test failed: malformed JSON was accepted" >&2
    exit 1
  fi
  bash "$ROOT/scripts/check-quality-tool-selftests.sh"
  echo "quality tool catalog self-test: PASS"
  exit 0
fi

validate
echo "quality tool catalog: PASS"
