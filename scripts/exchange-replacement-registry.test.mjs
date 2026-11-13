import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

test('committed registry projections are deterministic and retain CJK labels', () => {
  const result = spawnSync(process.execPath, ['scripts/exchange-replacement-registry.mjs', '--check'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const projection = JSON.parse(readFileSync('config/exchange-replacement/generated/exchange-replacement-v1.json', 'utf8'));
  assert.match(projection.capabilities[0].outcome.zh, /[\u3400-\u9fff]/u);
  assert.equal(new Set(projection.capabilities.map((item) => item.id)).size, projection.capabilities.length);
  assert.ok(projection.sourceDigest.match(/^[a-f0-9]{64}$/));
});

test('compiler is fail-closed on unsupported mode', () => {
  const result = spawnSync(process.execPath, ['scripts/exchange-replacement-registry.mjs', '--unknown'], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /E_EXCHANGE_REGISTRY_INVALID/);
});

// D-CONFIG-002 (GENERATED-ARTIFACT-INJECTION): registry/catalog versions and
// root enumerators are interpolated into executable SQL and the collector
// command allowlist, so the compiler must fail closed on any mutant of the
// version/type/version-contract invariants — a maintainer running `--write`
// can never project an unvalidated catalog field.
async function withMutatedSource(t, mutate) {
  const dir = await mkdtemp(join(tmpdir(), 'exchange-registry-mutant-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await cp('config/exchange-replacement', dir, { recursive: true });
  await mutate(dir);
  return spawnSync(process.execPath, ['scripts/exchange-replacement-registry.mjs', '--write'], {
    encoding: 'utf8',
    env: { ...process.env, EXCHANGE_REPLACEMENT_SOURCE_DIR: dir },
  });
}

async function mutateJson(dir, file, mutator) {
  const path = join(dir, file);
  const doc = JSON.parse(await readFile(path, 'utf8'));
  mutator(doc);
  await writeFile(path, JSON.stringify(doc, null, 2));
}

const versionMutants = [
  { name: 'registry version as string', file: 'registry-v1.json', mutate: (doc) => { doc.registryVersion = '1'; } },
  { name: 'registry version as float', file: 'registry-v1.json', mutate: (doc) => { doc.registryVersion = 1.5; } },
  { name: 'registry version below range', file: 'registry-v1.json', mutate: (doc) => { doc.registryVersion = 0; } },
  { name: 'registry version outside accepted range', file: 'registry-v1.json', mutate: (doc) => { doc.registryVersion = 99; } },
  { name: 'catalog version as string', file: 'discovery-catalog-v1.json', mutate: (doc) => { doc.catalogVersion = '1'; } },
  { name: 'catalog version outside accepted range', file: 'discovery-catalog-v1.json', mutate: (doc) => { doc.catalogVersion = 99; } },
  { name: 'root enumerator not Get-*', file: 'discovery-catalog-v1.json', mutate: (doc) => { doc.roots[0].enumerator = 'Invoke-OrganizationConfig'; } },
  { name: 'root enumerator with shell metacharacters', file: 'discovery-catalog-v1.json', mutate: (doc) => { doc.roots[0].enumerator = 'Get-OrganizationConfig$(id)'; } },
  { name: 'cell collectorVersion outside accepted range', file: 'support-cells-v1.json', mutate: (doc) => { doc.cells[0].collectorVersion = '2'; } },
];

for (const mutant of versionMutants) {
  test(`compiler rejects ${mutant.name}`, async (t) => {
    const result = await withMutatedSource(t, (dir) => mutateJson(dir, mutant.file, mutant.mutate));
    assert.notEqual(result.status, 0, `mutant accepted: ${result.stdout}`);
    assert.match(result.stderr, /E_EXCHANGE_REGISTRY_INVALID/);
  });
}

test('compiler accepts the committed sources unmutated', async (t) => {
  const result = await withMutatedSource(t, async () => {});
  assert.equal(result.status, 0, result.stderr);
});
