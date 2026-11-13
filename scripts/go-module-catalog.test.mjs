#!/usr/bin/env node
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const catalog = JSON.parse(fs.readFileSync(new URL('../config/go-modules.json', import.meta.url)));
const byID = new Map(catalog.modules.map((mod) => [mod.id, mod]));
assert.equal(catalog.modules.length, 6);
assert.equal(byID.get('asrbot').workspace, false);
assert.equal(byID.get('asrbot').environment.GOWORK, 'off');
assert.deepEqual(byID.get('asrbot').buildTags, ['nolibopusfile']);
assert.equal(byID.get('setjoin-release').kind, 'ciTool');
for (const capability of ['test', 'lint', 'vulnerability', 'coverage']) {
  assert(byID.get('setjoin-release').capabilities.includes(capability), `release tool missing ${capability}`);
}
assert(!byID.get('setjoin-release').capabilities.includes('build'), 'release tool must not become a customer artifact');
assert.deepEqual(byID.get('mailserver').artifacts.map((item) => item.output), ['mailserverd', 'setjoin-updater', 'setjoin-recovery']);
assert.deepEqual(byID.get('authserver').artifacts.map((item) => item.output), ['authserverd']);
assert.equal(byID.get('mailctl').artifacts, undefined, 'frozen Go mailctl is oracle-only');
assert(!byID.get('mailctl').capabilities.includes('build'));
assert.deepEqual(byID.get('asrbot').artifacts.map((item) => item.output), ['asrbotd']);

const artifactRows = childProcess.execFileSync(process.execPath, [
	new URL('./go-module-catalog.mjs', import.meta.url).pathname,
	'artifacts',
], { encoding: 'utf8' }).trim().split('\n').map((row) => row.split('\t'));
assert(artifactRows.every((row) => row.length === 7), 'artifact TSV must retain seven unambiguous columns');
assert.deepEqual(artifactRows.find((row) => row[0] === 'authserver'), [
	'authserver', 'authserver', 'workspace', '-', '-', './cmd/authserverd', 'authserverd',
]);

if (process.argv.includes('--mutant')) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-go-catalog-'));
  try {
    const mutant = structuredClone(catalog);
    mutant.modules = mutant.modules.filter((mod) => mod.id !== 'setjoin-release');
    const filename = path.join(directory, 'go-modules.json');
    fs.writeFileSync(filename, `${JSON.stringify(mutant, null, 2)}\n`);
    const result = childProcess.spawnSync(process.execPath, [new URL('./go-module-catalog.mjs', import.meta.url).pathname, 'check'], {
      env: { ...process.env, GO_MODULE_CATALOG: filename },
      encoding: 'utf8',
    });
    assert.notEqual(result.status, 0, 'catalog checker accepted an omitted Go module');
    assert.match(result.stderr, /E_ARCH_R4_GOMODS_DISCOVERY/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
  console.log('go-module-catalog mutant: PASS');
  process.exit(0);
}
console.log('go-module-catalog test: PASS');
