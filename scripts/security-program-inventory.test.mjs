#!/usr/bin/env node
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  EXCLUSION_POLICY_SCHEMA,
  INVENTORY_DECISION_SCHEMA,
  INVENTORY_DECISION_VERSION,
  InventoryError,
  applyExclusionPolicy,
  buildShardGeneration,
  classifyOwnership,
  compileInventory,
  createStreamingInventoryHasher,
  enumerateGitTree,
  hashInventory,
  parseGitTreeZ,
  stringifyJsonDocument,
  validateGitPath,
  validateOwnership,
} from './lib/security-program-inventory.mjs';

const emptyPolicy = {
  schema: EXCLUSION_POLICY_SCHEMA,
  policyVersion: 'test/empty/v1',
  classes: [],
};

function git(root, ...args) {
  return childProcess.execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' }).trim();
}

function write(root, pathname, content) {
  const filename = path.join(root, pathname);
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  fs.writeFileSync(filename, content);
}

function commitAll(root, message) {
  git(root, 'add', '-A');
  git(root, 'commit', '-m', message);
  return git(root, 'rev-parse', 'HEAD');
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-inventory-'));
  git(root, 'init', '-q');
  git(root, 'config', 'user.email', 'inventory@example.invalid');
  git(root, 'config', 'user.name', 'Inventory Test');
  return root;
}

function expectCode(code, operation) {
  assert.throws(operation, (error) => error instanceof InventoryError && error.code === code, `expected ${code}`);
}

function entry(pathname, objectId = '1'.repeat(40), mode = '100644') {
  const kinds = { '100644': 'file', '100755': 'executable', '120000': 'symlink', '160000': 'submodule' };
  return { path: pathname, pathBytes: Buffer.from(pathname), objectId, mode, objectType: mode === '160000' ? 'commit' : 'blob', kind: kinds[mode] };
}

const root = fixture();
try {
  write(root, 'shared/threat/policy.go', 'package threat\n');
  write(root, 'shared/jwt/token.go', 'package jwt\n');
  write(root, 'docs/guide.md', '# guide\n');
  write(root, 'generated/output.js', 'generated\n');
  fs.symlinkSync('../docs/guide.md', path.join(root, 'guide-link'));
  const firstRevision = commitAll(root, 'first');

  const tree = enumerateGitTree({ repoRoot: root, revision: firstRevision });
  assert.equal(tree.revision, firstRevision);
  assert.equal(tree.entries.find((item) => item.path === 'guide-link').kind, 'symlink');

  const policy = {
    schema: EXCLUSION_POLICY_SCHEMA,
    policyVersion: 'test/generated/v1',
    classes: [{
      id: 'generated-output', reason: 'fixture-generated output owns no runtime behavior', expectedCount: 1,
      selectors: [{ kind: 'prefix', value: 'generated/' }],
    }],
  };
  const applied = applyExclusionPolicy(tree.entries, policy);
  assert.equal(applied.excluded.length, 1);
  assert.equal(applied.excluded[0].path, 'generated/output.js');
  assert.equal(applyExclusionPolicy(tree.entries, {
    ...policy,
    classes: [{ ...policy.classes[0], selectors: [...policy.classes[0].selectors].reverse() }],
  }).policyHash, applied.policyHash, 'selector order must not affect policy hash');
  assert.notEqual(applyExclusionPolicy(tree.entries, {
    schema: EXCLUSION_POLICY_SCHEMA,
    policyVersion: 'test/generated-docs/v1',
    classes: [{ id: 'generated-output', reason: 'different reviewed policy', expectedCount: 1, selectors: [{ kind: 'prefix', value: 'docs/' }] }],
  }).policyHash, applied.policyHash, 'changed exclusion policy must invalidate the policy hash');

  const fixtureCatalog = [
    { id: 'S01', title: 'threat', provenance: 'fixture', matches: (p) => p.startsWith('shared/threat/') },
    { id: 'S02', title: 'everything else', provenance: 'fixture', matches: (p) => !p.startsWith('shared/threat/') },
  ];
  expectCode('C0_DENOMINATOR_CANDIDATE', () => compileInventory({
    repoRoot: root, revision: firstRevision, exclusionPolicy: policy, sectionCatalog: fixtureCatalog,
  }));
  const compiled = compileInventory({
    repoRoot: root, revision: firstRevision, exclusionPolicy: policy,
    sectionCatalog: fixtureCatalog, historicalCandidateCount: 4,
  });
  assert.equal(compiled.epoch.authorizedCount, 4);
  assert.equal(compiled.epoch.historicalCandidateCount, 4);
  assert.equal(Object.hasOwn(compiled.epoch, 'inventoryDecision'), false);
  assert.equal(compiled.sections.sections.reduce((sum, item) => sum + item.pathCount, 0), 4);
  assert.doesNotThrow(() => JSON.parse(stringifyJsonDocument(compiled.epoch)));
  assert.notEqual(compiled.epoch.inventorySha256, applied.policyHash);
  expectCode('C0_DENOMINATOR_DECISION', () => compileInventory({
    repoRoot: root, revision: firstRevision, exclusionPolicy: policy,
    sectionCatalog: fixtureCatalog, historicalCandidateCount: 3,
  }));
  const validDecision = {
    schema: INVENTORY_DECISION_SCHEMA,
    decisionVersion: INVENTORY_DECISION_VERSION,
    decidedAt: new Date().toISOString(),
    revision: firstRevision,
    historicalCandidateCount: 3,
    acceptedAuthorizedCount: 4,
    exclusionPolicySha256: applied.policyHash,
    inventorySha256: hashInventory(applied.authorized),
    rationaleToken: 'SECURITY-INVENTORY-TEST-ALTERNATE',
  };
  const alternate = compileInventory({
    repoRoot: root, revision: firstRevision, exclusionPolicy: policy,
    sectionCatalog: fixtureCatalog, historicalCandidateCount: 3,
    inventoryDecision: validDecision,
  });
  assert.deepEqual(alternate.epoch.inventoryDecision, validDecision, 'approved alternate denominator must retain its exact decision');
  assert.equal(alternate.epoch.historicalCandidateCount, 3);

  const decisionMutants = [
    ['C0_DECISION_SCHEMA', (value) => { delete value.rationaleToken; }],
    ['C0_DECISION_SCHEMA', (value) => { value.unreviewed = true; }],
    ['C0_DECISION_VERSION', (value) => { value.decisionVersion = 'inventory-denominator/v2'; }],
    ['C0_DECISION_BINDING', (value) => { value.historicalCandidateCount = 2; }],
    ['C0_DECISION_BINDING', (value) => { value.acceptedAuthorizedCount = 3; }],
    ['C0_DECISION_BINDING', (value) => { value.inventorySha256 = '0'.repeat(64); }],
    ['C0_DECISION_BINDING', (value) => { value.revision = '0'.repeat(40); }],
    ['C0_DECISION_BINDING', (value) => { value.exclusionPolicySha256 = '0'.repeat(64); }],
    ['C0_DECISION_STALE', (value) => { value.decidedAt = '1970-01-01T00:00:00.000Z'; }],
  ];
  for (const [code, mutate] of decisionMutants) {
    const mutant = structuredClone(validDecision);
    mutate(mutant);
    expectCode(code, () => compileInventory({
      repoRoot: root, revision: firstRevision, exclusionPolicy: policy,
      sectionCatalog: fixtureCatalog, historicalCandidateCount: 3,
      inventoryDecision: mutant,
    }));
  }

  const beforeRename = compiled.epoch.inventorySha256;
  fs.renameSync(path.join(root, 'docs/guide.md'), path.join(root, 'docs/manual.md'));
  const secondRevision = commitAll(root, 'rename');
  const renamed = compileInventory({
    repoRoot: root, revision: secondRevision, exclusionPolicy: policy,
    sectionCatalog: fixtureCatalog, historicalCandidateCount: 4,
  });
  assert.notEqual(renamed.epoch.inventorySha256, beforeRename, 'rename with the same blob must change inventory hash');

  const oid = git(root, 'rev-parse', 'HEAD');
  git(root, 'update-index', '--add', '--cacheinfo', `160000,${oid},vendor-module`);
  git(root, 'commit', '-m', 'gitlink');
  const withSubmodule = enumerateGitTree({ repoRoot: root, revision: 'HEAD' });
  assert.equal(withSubmodule.entries.find((item) => item.path === 'vendor-module').kind, 'submodule');

  const missingCatalog = [{ id: 'S01', title: 'only threat', provenance: 'fixture', matches: (p) => p.startsWith('shared/threat/') }];
  expectCode('C0_CLASSIFICATION_HOLD', () => classifyOwnership(applied.authorized, missingCatalog));
  try { classifyOwnership(applied.authorized, missingCatalog); } catch (error) {
    assert(error.details.orphans.includes('shared/jwt/token.go'), 'HOLD must name orphan paths');
  }
  const duplicateCatalog = [
    { id: 'S01', title: 'all one', provenance: 'fixture', matches: () => true },
    { id: 'S02', title: 'all two', provenance: 'fixture', matches: () => true },
  ];
  expectCode('C0_CLASSIFICATION_HOLD', () => classifyOwnership(applied.authorized, duplicateCatalog));
  try { classifyOwnership(applied.authorized, duplicateCatalog); } catch (error) {
    assert.deepEqual(error.details.duplicates[0].owners, ['S01', 'S02']);
  }

  const one = entry('one');
  const two = entry('two', '2'.repeat(40));
  const streaming = createStreamingInventoryHasher();
  assert.equal(streaming.update(one), streaming);
  assert.equal(streaming.updateChunk([two]), streaming);
  assert.deepEqual(streaming.finalize(), {
    inventorySha256: hashInventory([two, one]),
    pathCount: 2,
  }, 'streaming and compatibility inventory hashes must share one digest contract');

  const unicodeEntries = [entry('alpha'), entry('éclair'), entry('中'), entry('😀')]
    .sort((left, right) => Buffer.compare(left.pathBytes, right.pathBytes));
  const unicodeStream = createStreamingInventoryHasher();
  unicodeStream.updateChunk(unicodeEntries.slice(0, 2));
  unicodeStream.updateChunk(unicodeEntries.slice(2));
  assert.equal(unicodeStream.finalize().inventorySha256, hashInventory([...unicodeEntries].reverse()),
    'streaming raw-byte ordering must preserve the compatibility digest for Unicode paths');

  const outOfOrderChunk = createStreamingInventoryHasher();
  expectCode('C0_INVENTORY_ORDER', () => outOfOrderChunk.updateChunk([two, one]));
  expectCode('C0_INVENTORY_STREAM_FAILED', () => outOfOrderChunk.finalize());
  const outOfOrderBoundary = createStreamingInventoryHasher();
  outOfOrderBoundary.update(two);
  expectCode('C0_INVENTORY_ORDER', () => outOfOrderBoundary.updateChunk([one]));
  const duplicateChunk = createStreamingInventoryHasher();
  expectCode('C0_INVENTORY_DUPLICATE', () => duplicateChunk.updateChunk([one, one]));
  const duplicateBoundary = createStreamingInventoryHasher();
  duplicateBoundary.updateChunk([one]);
  expectCode('C0_INVENTORY_DUPLICATE', () => duplicateBoundary.update(one));
  for (const [code, invalidEntry] of [
    ['C0_ENTRY_PATH', { ...entry('safe'), path: 'spoofed' }],
    ['C0_PATH_UTF8', { ...entry('safe'), pathBytes: Buffer.from([0xff]) }],
    ['C0_OBJECT_ID', { ...entry('safe'), objectId: 'not-an-object-id' }],
    ['C0_MODE_UNSUPPORTED', { ...entry('safe'), mode: '100600' }],
    ['C0_MODE_TYPE', { ...entry('safe'), kind: 'executable' }],
  ]) {
    const invalidStream = createStreamingInventoryHasher();
    expectCode(code, () => invalidStream.updateChunk([invalidEntry]));
    expectCode('C0_INVENTORY_STREAM_FAILED', () => invalidStream.update(entry('later')));
  }
  const finalizedStream = createStreamingInventoryHasher();
  finalizedStream.update(one);
  finalizedStream.finalize();
  expectCode('C0_INVENTORY_STREAM_FINALIZED', () => finalizedStream.update(two));
  expectCode('C0_INVENTORY_STREAM_FINALIZED', () => finalizedStream.finalize());
  expectCode('C0_INVENTORY_EMPTY', () => createStreamingInventoryHasher().finalize());
  const invalidChunkStream = createStreamingInventoryHasher();
  expectCode('C0_INVENTORY_STREAM_CHUNK', () => invalidChunkStream.updateChunk(new Set([one])));
  expectCode('C0_INVENTORY_STREAM_FAILED', () => invalidChunkStream.finalize());

  expectCode('C0_OWNERSHIP_HOLD', () => validateOwnership([one, two], [{ id: 'S01', entries: [one] }]));
  expectCode('C0_OWNERSHIP_HOLD', () => validateOwnership([one], [{ id: 'S01', entries: [one] }, { id: 'S02', entries: [one] }]));
  expectCode('C0_SHARD_SCHEMA', () => buildShardGeneration({
    revision: firstRevision, inventorySha256: hashInventory([one]),
    ownerSections: [{ id: 'S01', entries: [one] }],
    shards: [{ id: 'S02/P01', ownerSectionId: 'S02', entries: [one] }],
  }));

  expectCode('C0_POLICY_SCHEMA', () => applyExclusionPolicy(tree.entries, { ...policy, schema: 'unknown' }));
  expectCode('C0_POLICY_SELECTOR', () => applyExclusionPolicy(tree.entries, {
    ...policy, classes: [{ ...policy.classes[0], selectors: [{ kind: 'prefix', value: 'generated' }] }],
  }));
  expectCode('C0_POLICY_OVERLAP', () => applyExclusionPolicy(tree.entries, {
    schema: EXCLUSION_POLICY_SCHEMA, policyVersion: 'test/overlap/v1', classes: [
      { id: 'generated-a', reason: 'a', expectedCount: 1, selectors: [{ kind: 'prefix', value: 'generated/' }] },
      { id: 'generated-b', reason: 'b', expectedCount: 1, selectors: [{ kind: 'exact', value: 'generated/output.js' }] },
    ],
  }));
  expectCode('C0_POLICY_COUNT', () => applyExclusionPolicy(tree.entries, {
    ...policy, classes: [{ ...policy.classes[0], expectedCount: 2 }],
  }));
  expectCode('C0_POLICY_COUNT', () => applyExclusionPolicy(tree.entries, {
    ...policy, classes: [{
      id: 'generated-output', reason: 'missing frozen count', selectors: [{ kind: 'prefix', value: 'generated/' }],
    }],
  }));
  expectCode('C0_POLICY_SCHEMA', () => applyExclusionPolicy(tree.entries, { ...policy, extra: true }));
  expectCode('C0_POLICY_CLASS', () => applyExclusionPolicy(tree.entries, {
    ...policy, classes: [{ ...policy.classes[0], extra: true }],
  }));
  expectCode('C0_POLICY_SELECTOR', () => applyExclusionPolicy(tree.entries, {
    ...policy, classes: [{ ...policy.classes[0], selectors: [{ kind: 'prefix', value: 'generated/', extra: true }] }],
  }));
  expectCode('C0_POLICY_SELECTOR', () => applyExclusionPolicy(tree.entries, {
    ...policy, classes: [{ ...policy.classes[0], selectors: [{ kind: 'exact', value: 'Cafe\u0301' }] }],
  }));
  for (const reason of [
    'two\nlines',
    '/Users/private/security-program/bundle',
    'bundle=/Users/private/security-program/bundle',
    'bundle:(/private/tmp/security-program)',
    'file:///Users/private/security-program/bundle',
    'token=sk-12345678901234567890',
    'api-key:(sk-12345678901234567890)',
    'Cafe\u0301 output',
  ]) {
    expectCode('C0_POLICY_REASON', () => applyExclusionPolicy(tree.entries, {
      ...policy, classes: [{ ...policy.classes[0], reason }],
    }));
  }

  expectCode('C0_PATH_UTF8', () => validateGitPath(Buffer.from([0xff])));
  expectCode('C0_PATH_CONTROL', () => validateGitPath(Buffer.from('line\nbreak')));
  expectCode('C0_PATH_SEPARATOR', () => validateGitPath(Buffer.from('a\\b')));
  const casefoldTree = Buffer.concat([
    Buffer.from(`100644 blob ${'1'.repeat(40)}\tAlpha\0`),
    Buffer.from(`100644 blob ${'2'.repeat(40)}\talpha\0`),
  ]);
  expectCode('C0_PATH_CASEFOLD', () => parseGitTreeZ(casefoldTree));
  expectCode('C0_MODE_UNSUPPORTED', () => parseGitTreeZ(Buffer.from(`100600 blob ${'1'.repeat(40)}\tsecret\0`)));
  expectCode('C0_MODE_TYPE', () => parseGitTreeZ(Buffer.from(`160000 blob ${'1'.repeat(40)}\tmodule\0`)));
  expectCode('C0_ENTRY_PATH', () => hashInventory([{ ...entry('safe'), path: 'spoofed' }]));

  const collisionA = [entry('a|bc', '1'.repeat(40)), entry('d', '2'.repeat(40))];
  const collisionB = [entry('a', '1'.repeat(40)), entry('bc|d', '2'.repeat(40))];
  assert.notEqual(hashInventory(collisionA), hashInventory(collisionB), 'length frames must reject delimiter collisions');
  assert.notEqual(
    hashInventory([entry('mode-sensitive', '3'.repeat(40), '100644')]),
    hashInventory([entry('mode-sensitive', '3'.repeat(40), '100755')]),
    'mode and derived kind must be part of the inventory digest',
  );
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}

const casefoldRoot = fixture();
try {
  const blob = childProcess.execFileSync('git', ['-C', casefoldRoot, 'hash-object', '-w', '--stdin'], {
    input: 'same blob\n', encoding: 'utf8',
  }).trim();
  git(casefoldRoot, 'update-index', '--add', '--cacheinfo', `100644,${blob},Alpha`);
  git(casefoldRoot, 'update-index', '--add', '--cacheinfo', `100644,${blob},alpha`);
  git(casefoldRoot, 'commit', '-m', 'casefold collision');
  expectCode('C0_PATH_CASEFOLD', () => enumerateGitTree({ repoRoot: casefoldRoot, revision: 'HEAD' }));
} finally {
  fs.rmSync(casefoldRoot, { recursive: true, force: true });
}

const emptyRoot = fixture();
try {
  git(emptyRoot, 'commit', '--allow-empty', '-m', 'empty');
  expectCode('C0_INVENTORY_EMPTY', () => enumerateGitTree({ repoRoot: emptyRoot, revision: 'HEAD' }));
} finally {
  fs.rmSync(emptyRoot, { recursive: true, force: true });
}

const repositoryRoot = path.resolve(new URL('..', import.meta.url).pathname);
try {
  const epoch = enumerateGitTree({ repoRoot: repositoryRoot, revision: '727f40ad1274d950926369913a464bcc8f2e0236' });
  const shared = epoch.entries.filter((item) => item.path.startsWith('shared/'));
  const sections = classifyOwnership(shared);
  assert.equal(sections.find((item) => item.id === 'S01').entries.length, 71);
  assert.equal(sections.find((item) => item.id === 'S02').entries.length, 219);
  assert.equal(shared.length, 290);
  assert.equal(new Set(sections.flatMap((item) => item.entries.map((item) => item.path))).size, 290);
} catch (error) {
  if (!(error instanceof InventoryError) || error.code !== 'C0_GIT_FAILED') throw error;
  process.stderr.write('security-program-inventory: epoch fixture unavailable; S01/S02 integration proof skipped\n');
}

assert.deepEqual(applyExclusionPolicy([entry('a')], emptyPolicy).authorized.map((item) => item.path), ['a']);
console.log('security-program-inventory test: PASS');
