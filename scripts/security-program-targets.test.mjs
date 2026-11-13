#!/usr/bin/env node

import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { canonicalJson, SecurityProgramError, sha256Hex } from './lib/security-program-json.mjs';
import { hashInventory, parseGitTreeZ } from './lib/security-program-inventory.mjs';
import { buildShardGenerationRecord } from './lib/security-program-records.mjs';
import {
  createMacOsReadOnlyDiskImageBackend,
  DESKTOP_ATTEMPT_BINDING_SCHEMA,
  EXPORT_CAPACITY_SCHEMA,
  PINNED_STANDARD_ROUTE_CONTRACT_SHA256,
  prepareDesktopAttestedExportTarget,
  prepareDeepTarget,
  prepareStandardTarget,
  projectExportCapacity,
  rehydrateDesktopAttestedExportTarget,
  STANDARD_TARGET_ROUTES,
  validateGitMaterialization,
  verifyPreparedTarget,
  verifyStandardRouteContract,
} from './lib/security-program-targets.mjs';

const revision = '7'.repeat(40);
const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-targets-repo-')));
const stateRoot = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-targets-state-')));
const copyRoot = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-targets-copy-')));
const exportStateRoot = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-state-')));
const exportParentRoot = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-parent-')));
const helperScriptPath = path.join(
  os.homedir(), '.codex/plugins/cache/openai-curated-remote/codex-security/0.1.24/scripts/generate_rank_input.py',
);
assert(fs.statSync(helperScriptPath).isFile(), 'the pinned codex-security scope helper must be installed');
const pluginRoot = path.dirname(path.dirname(helperScriptPath));
let subprocessRuns = 0;
let fingerprintVerifications = 0;

const sourceFingerprint = `v2:${revision}:${'6'.repeat(64)}`;

function exportCapacity(overrides = {}) {
  return {
    schema: EXPORT_CAPACITY_SCHEMA,
    maxEntries: 1_000,
    maxBytes: 16 * 1024 * 1024,
    minimumFreeBytes: 0,
    maxBuildElapsedMs: 60_000,
    maxBuildPeakRssBytes: Number.MAX_SAFE_INTEGER,
    maxSnapshotElapsedMs: 60_000,
    maxSnapshotPeakRssBytes: Number.MAX_SAFE_INTEGER,
    ...overrides,
  };
}

function desktopAttemptBinding(attemptId = 'attempt-s02-p01', overrides = {}) {
  return {
    schema: DESKTOP_ATTEMPT_BINDING_SCHEMA,
    attemptId,
    sourceFingerprint,
    controlGenerationHash: 'b'.repeat(64),
    budgetId: 'pilot-budget-v1',
    budgetSha256: 'c'.repeat(64),
    exportCapacity: exportCapacity(),
    ...overrides,
  };
}

function sourceFingerprintVerifier(request) {
  fingerprintVerifications += 1;
  assert.deepEqual(Object.keys(request), ['repoRoot'],
    'fingerprint verification must not disclose the expected fingerprint to its verifier');
  const { repoRoot: requestedRoot } = request;
  assert.equal(requestedRoot, root);
  return { sourceFingerprint };
}

function gitBlobId(contents) {
  const bytes = Buffer.from(contents);
  return crypto.createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}

function entry(pathname, contents, mode = '100644') {
  return { path: pathname, objectId: gitBlobId(contents), mode, kind: mode === '100755' ? 'executable' : 'file' };
}

function inventoryHash(entries) {
  return hashInventory(entries.map((item) => ({
    ...item,
    pathBytes: Buffer.from(item.path),
    objectType: item.mode === '160000' ? 'commit' : 'blob',
  })));
}

function treeBytes(entries) {
  return Buffer.concat(entries.map((item) => Buffer.from(
    `${item.mode} ${item.mode === '160000' ? 'commit' : 'blob'} ${item.objectId}\t${item.path}\0`,
  )));
}

function writeEntry(item, contents) {
  const filename = path.join(root, item.path);
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  fs.writeFileSync(filename, contents, { mode: item.mode === '100755' ? 0o755 : 0o644 });
}

function runnerFor(entries, overrides = {}, expectedRoot = root) {
  return ({ repoRoot, args }) => {
    assert.equal(repoRoot, expectedRoot);
    const key = args.join('\0');
    if (key === ['rev-parse', '--is-inside-work-tree'].join('\0')) return { status: 0, stdout: 'true\n' };
    if (key === ['rev-parse', '--show-toplevel'].join('\0')) return { status: 0, stdout: `${expectedRoot}\n` };
    if (key === ['rev-parse', '--verify', 'HEAD^{commit}'].join('\0')) {
      return { status: 0, stdout: `${overrides.head ?? revision}\n` };
    }
    if (key === ['symbolic-ref', '-q', 'HEAD'].join('\0')) {
      return overrides.attached ? { status: 0, stdout: 'refs/heads/main\n' } : { status: 1, stdout: Buffer.alloc(0) };
    }
    if (args[0] === 'status') return { status: 0, stdout: overrides.status ?? Buffer.alloc(0) };
    if (args[0] === 'ls-tree') {
      const selectedTree = overrides.tree ?? entries;
      return { status: 0, stdout: Buffer.isBuffer(selectedTree) ? selectedTree : treeBytes(selectedTree) };
    }
    throw new Error(`unexpected Git operation ${args.join(' ')}`);
  };
}

function helperRunner({ mutate, mutateScopes = false } = {}) {
  return async ({ command, args, cwd }) => {
    assert.equal(command, 'python3');
    assert.equal(args[0], helperScriptPath);
    assert.equal(args[1], 'make-repo-scope-input');
    assert.equal(cwd, root);
    const scopesFile = args[args.indexOf('--scopes-file') + 1];
    const outputFile = args[args.indexOf('--out') + 1];
    const requested = JSON.parse(fs.readFileSync(scopesFile, 'utf8'));
    if (mutateScopes) fs.writeFileSync(scopesFile, `${JSON.stringify(requested.slice(1))}\n`);
    const rows = mutate ? mutate([...requested]) : requested;
    fs.writeFileSync(outputFile, rows.map((pathname) => JSON.stringify(
      typeof pathname === 'string' ? { path: pathname } : pathname,
    )).join('\n') + '\n');
    return { status: 0, stdout: `Wrote ${rows.length} scoped paths\n`, stderr: '' };
  };
}

async function installedHelperRunner({ command, args, cwd }) {
  subprocessRuns += 1;
  assert.equal(command, 'python3');
  assert.equal(args[0], helperScriptPath);
  assert.equal(args[1], 'make-repo-scope-input');
  const result = childProcess.spawnSync(command, args, { cwd, encoding: 'utf8' });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function installedPluginDigestRunner({ pluginRoot: requestedPluginRoot, targetPath }) {
  subprocessRuns += 1;
  const program = [
    'from pathlib import Path',
    'import sys',
    "sys.path.insert(0, str(Path(sys.argv[1]) / 'scripts'))",
    'from workbench_target import directory_content_digest',
    'print(directory_content_digest(Path(sys.argv[2]).resolve()))',
  ].join('\n');
  const result = childProcess.spawnSync('python3', ['-c', program, requestedPluginRoot, targetPath], {
    encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  return { digest: result.stdout.trim() };
}

function createFixtureReadOnlyBackend() {
  const controls = { readOnly: true, deviceIdentifier: 'fixture-device' };
  const backend = {
    backendId: 'fixture-readonly-mount/v1',
    productionEligible: false,
    unsupportedDisposition: 'HOLD_TEST_ONLY_BACKEND',
    inspect({ targetPath }) {
      const metadata = fs.lstatSync(targetPath, { bigint: true });
      return {
        readOnly: controls.readOnly,
        targetPath: path.resolve(targetPath),
        realPath: fs.realpathSync.native(targetPath),
        deviceId: String(metadata.dev),
        rootInode: String(metadata.ino),
        deviceIdentifier: controls.deviceIdentifier,
        volumeUuid: 'fixture-volume',
      };
    },
    seal({ sourceDirectory, stateDirectory, stem }) {
      const imagePath = path.join(stateDirectory, `fixture-${stem}.img`);
      const descriptor = fs.openSync(imagePath,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
      fs.writeFileSync(descriptor, Buffer.from(`fixture-readonly-image:${stem}\n`));
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      const inspection = backend.inspect({ targetPath: sourceDirectory, imagePath });
      return { targetPath: sourceDirectory, imagePath, inspection };
    },
  };
  return { backend: Object.freeze(backend), controls };
}

function generation(entries, id = 'S02/P01') {
  const sorted = [...entries].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  return buildShardGenerationRecord({
    revision,
    inventorySha256: inventoryHash(sorted),
    generationId: 'fixture-target-shards/v1',
    shards: [{
      id,
      ownerSectionId: id.split('/')[0],
      pathCount: sorted.length,
      pathListSha256: inventoryHash(sorted),
      paths: sorted,
    }],
  });
}

async function expectCode(code, operation) {
  await assert.rejects(operation, (error) => error instanceof SecurityProgramError && error.code === code, `expected ${code}`);
}

function removeFixtureTree(directory) {
  if (!fs.existsSync(directory)) return;
  const metadata = fs.lstatSync(directory);
  if (metadata.isDirectory() && !metadata.isSymbolicLink()) {
    fs.chmodSync(directory, 0o700);
    for (const name of fs.readdirSync(directory)) removeFixtureTree(path.join(directory, name));
  } else if (!metadata.isSymbolicLink()) fs.chmodSync(directory, 0o600);
  fs.rmSync(directory, { recursive: true, force: true });
}

const hardExitTargetProgram = String.raw`
  import childProcess from 'node:child_process';
  const api = await import(process.argv[1]);
  const repoRoot = process.argv[2];
  const stateDir = process.argv[3];
  const exportParentDir = process.argv[4];
  const pluginRoot = process.argv[5];
  const shardGeneration = JSON.parse(process.argv[6]);
  const attemptBinding = JSON.parse(process.argv[7]);
  const checkpoint = process.argv[8];
  const backendKind = process.argv[9];
  const gitRunner = async ({ args }) => {
    const key = args.join('\0');
    if (key === ['rev-parse', '--is-inside-work-tree'].join('\0')) return { status: 0, stdout: 'true\n' };
    if (key === ['rev-parse', '--show-toplevel'].join('\0')) return { status: 0, stdout: repoRoot + '\n' };
    if (key === ['rev-parse', '--verify', 'HEAD^{commit}'].join('\0')) {
      return { status: 0, stdout: shardGeneration.revision + '\n' };
    }
    if (args[0] === 'symbolic-ref') return { status: 1, stdout: Buffer.alloc(0) };
    if (args[0] === 'status') return { status: 0, stdout: Buffer.alloc(0) };
    if (args[0] === 'ls-tree') return { status: 0, stdout: Buffer.concat(shardGeneration.shards[0].paths.map(
      (entry) => Buffer.from(entry.mode + ' blob ' + entry.objectId + '\t' + entry.path + '\0'))) };
    throw new Error('unexpected Git operation: ' + args.join(' '));
  };
  const commandRunner = ({ command, args, input }) => {
    const result = childProcess.spawnSync(command, args, {
      input, encoding: null, maxBuffer: 16 * 1024 * 1024,
    });
    return {
      status: result.status ?? 127,
      stdout: result.stdout ?? Buffer.alloc(0),
      stderr: result.stderr ?? Buffer.alloc(0),
    };
  };
  const fixtureBackend = Object.freeze({
    backendId: 'fixture-readonly-mount/v1',
    productionEligible: false,
    unsupportedDisposition: 'HOLD_TEST_ONLY_BACKEND',
    seal() { throw new Error('construction checkpoint must exit before fixture seal'); },
    inspect() { throw new Error('construction checkpoint must exit before fixture inspection'); },
  });
  const backend = backendKind === 'macos'
    ? api.createMacOsReadOnlyDiskImageBackend({ runner: commandRunner })
    : fixtureBackend;
  await api.prepareDesktopAttestedExportTarget({
    repoRoot,
    shardGeneration,
    shardId: 'S02/P01',
    stateDir,
    exportParentDir,
    pluginRoot,
    gitRunner,
    pluginDigestRunner() { throw new Error('hard-exit checkpoint must precede plugin digest'); },
    readOnlyBackend: backend,
    attemptBinding,
    sourceFingerprintVerifier: () => ({
      sourceFingerprint: attemptBinding.sourceFingerprint,
    }),
    sourceFingerprintRevalidator: () => ({
      sourceFingerprint: attemptBinding.sourceFingerprint,
    }),
    allowTestBackend: backendKind !== 'macos',
    faultInjector(observedCheckpoint) {
      if (observedCheckpoint === checkpoint) process.kill(process.pid, 'SIGKILL');
    },
  });
  process.stderr.write('hard-exit checkpoint was not reached: ' + checkpoint + '\n');
  process.exit(91);
`;

function hardExitDesktopTarget({ stateDir, exportParentDir, attemptBinding, checkpoint, backendKind }) {
  subprocessRuns += 1;
  const result = childProcess.spawnSync(process.execPath, [
    '--input-type=module', '-e', hardExitTargetProgram,
    new URL('./lib/security-program-targets.mjs', import.meta.url).href,
    root,
    stateDir,
    exportParentDir,
    pluginRoot,
    JSON.stringify(pilotGeneration),
    JSON.stringify(attemptBinding),
    checkpoint,
    backendKind,
  ], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  assert.equal(result.status, null, `hard-exit child unexpectedly exited normally: ${result.stderr}`);
  assert.equal(result.signal, 'SIGKILL', `hard-exit child used the wrong signal: ${result.stderr}`);
}

function onlyPreparationRecord(stateDir) {
  const files = fs.readdirSync(stateDir)
    .filter((name) => /^desktop-export-preparation-[0-9a-f]{24}\.json$/.test(name));
  assert.equal(files.length, 1, 'a crashed target build must leave exactly one preparation authority');
  const filename = path.join(stateDir, files[0]);
  return { filename, record: JSON.parse(fs.readFileSync(filename, 'utf8')) };
}

function crashQuarantinePaths(record) {
  const key = sha256Hex(canonicalJson(record)).slice(0, 16);
  return {
    build: path.join(record.exportParentDir, `.quarantine-desktop-export-${record.stem}-${key}-build`),
    mount: path.join(record.exportParentDir, `.quarantine-desktop-export-${record.stem}-${key}-mount`),
    image: path.join(record.stateDir, `.quarantine-desktop-export-${record.stem}-${key}-image`),
    preparation: path.join(record.stateDir,
      `.quarantine-desktop-export-${record.stem}-${key}-preparation.json`),
  };
}

function rewritePreparationRecord(filename, record, overrides) {
  const binding = { ...record };
  delete binding.recordSha256;
  const changedBinding = { ...binding, ...overrides };
  const changed = {
    ...changedBinding,
    recordSha256: sha256Hex(canonicalJson(changedBinding)),
  };
  fs.writeFileSync(filename, `${canonicalJson(changed)}\n`, { mode: 0o600 });
  return changed;
}

function localMacBackend() {
  return createMacOsReadOnlyDiskImageBackend({
    runner({ command, args, input }) {
      subprocessRuns += 1;
      const result = childProcess.spawnSync(command, args, {
        input, encoding: null, maxBuffer: 16 * 1024 * 1024,
      });
      return {
        status: result.status ?? 127,
        stdout: result.stdout ?? Buffer.alloc(0),
        stderr: result.stderr ?? Buffer.alloc(0),
      };
    },
  });
}

const pilotEntries = Array.from({ length: 219 }, (_, index) => {
  const pathname = `shared/pilot-${String(index).padStart(3, '0')}.go`;
  const contents = `package pilot${index}\n`;
  const item = entry(pathname, contents);
  writeEntry(item, contents);
  return item;
});
const pilotGeneration = generation(pilotEntries);
const pilotAttemptBinding = desktopAttemptBinding();

try {
  let scopeRuns = 0;
  const target = await prepareStandardTarget({
    repoRoot: root,
    shardGeneration: pilotGeneration,
    shardId: 'S02/P01',
    stateDir: stateRoot,
    helperScriptPath,
    gitRunner: runnerFor(pilotEntries),
    scopeRunner: async (invocation) => {
      scopeRuns += 1;
      return installedHelperRunner(invocation);
    },
  });
  assert.equal(scopeRuns, 1, 'the exact scope helper must run once');
  assert.equal(subprocessRuns, 1, 'only the explicitly injected installed helper runner may start a subprocess');
  assert.equal(target.mode, 'standard');
  assert.equal(target.pathCount, 219, 'the current S02 inventory fixture must retain 219 authorized paths');
  assert.equal(target.targetPath, root);
  assert.equal(target.scope, '.');
  assert.equal(fs.statSync(target.targetPathsFile).mode & 0o777, 0o600);
  assert.equal(fs.statSync(target.scopeInputFile).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(fs.readFileSync(target.targetPathsFile, 'utf8')), pilotEntries.map((item) => item.path));
  const sdkAuthority = verifyPreparedTarget(target);
  assert.match(sdkAuthority.artifactSha256, /^[0-9a-f]{64}$/);
  assert.deepEqual({ ...sdkAuthority, artifactSha256: '<bound>' }, {
    artifactSha256: '<bound>',
    pathCount: 219,
    pathListSha256: target.pathListSha256,
    standardRoute: STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS,
    routeContractSha256: PINNED_STANDARD_ROUTE_CONTRACT_SHA256[STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS],
    pluginVersion: '0.1.24',
    productionEligible: true,
  }, 'attempt authority must bind the exact private paths file, shard, and pinned SDK route');
  assert.equal(target.standardRoute, STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS);
  assert.equal(
    verifyStandardRouteContract({ pluginRoot, standardRoute: target.standardRoute }).routeContractSha256,
    target.routeContractSha256,
  );
  assert.throws(
    () => verifyPreparedTarget({ ...target }),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_UNVERIFIED',
    'copying caller-visible target fields must not forge target authority',
  );

  await expectCode('E_SECURITY_TARGET_REVISION_MISMATCH', () => validateGitMaterialization({
    repoRoot: root, revision, entries: pilotEntries, gitRunner: runnerFor(pilotEntries, { head: '8'.repeat(40) }),
  }));
  await expectCode('E_SECURITY_TARGET_MUTABLE_HEAD', () => validateGitMaterialization({
    repoRoot: root, revision, entries: pilotEntries, gitRunner: runnerFor(pilotEntries, { attached: true }),
  }));
  await expectCode('E_SECURITY_TARGET_DIRTY', () => validateGitMaterialization({
    repoRoot: root, revision, entries: pilotEntries, gitRunner: runnerFor(pilotEntries, { status: Buffer.from('?? injected\0') }),
  }));
  await expectCode('E_SECURITY_TARGET_TUPLE_MISMATCH', () => validateGitMaterialization({
    repoRoot: root, revision, entries: pilotEntries, gitRunner: runnerFor(pilotEntries, {
      tree: [{ ...pilotEntries[0], objectId: '1'.repeat(40) }, ...pilotEntries.slice(1)],
    }),
  }));

  const unicodeEntries = [
    entry('unicode/alpha.go', 'package alpha\n'),
    entry('unicode/éclair.go', 'package eclair\n'),
    entry('unicode/中.go', 'package zhong\n'),
    entry('unicode/😀.go', 'package emoji\n'),
  ].sort((left, right) => Buffer.compare(Buffer.from(left.path, 'utf8'), Buffer.from(right.path, 'utf8')));
  for (const [item, contents] of unicodeEntries.map((item, index) => [
    item, ['package alpha\n', 'package eclair\n', 'package zhong\n', 'package emoji\n'][index],
  ])) writeEntry(item, contents);
  const unicodeTreeBytes = treeBytes([...unicodeEntries].reverse());
  const parsedUnicodeTree = parseGitTreeZ(unicodeTreeBytes);
  assert.deepEqual(
    parsedUnicodeTree.map((item) => item.path),
    unicodeEntries.map((item) => item.path),
    'Unicode Git paths must retain UTF-8 byte ordering rather than locale ordering',
  );
  for (const [index, item] of parsedUnicodeTree.entries()) {
    assert(item.pathBytes.equals(Buffer.from(unicodeEntries[index].path, 'utf8')),
      'raw Git path bytes must round-trip without normalization or replacement');
  }
  assert.equal(hashInventory(parsedUnicodeTree), inventoryHash(unicodeEntries),
    'raw UTF-8 path bytes must feed the same framed inventory digest');
  const unicodeMaterialization = await validateGitMaterialization({
    repoRoot: root,
    revision,
    entries: unicodeEntries,
    gitRunner: runnerFor(unicodeEntries),
  });
  assert.deepEqual(
    unicodeMaterialization.selectedTreeEntries.map((item) => item.path),
    unicodeEntries.map((item) => item.path),
  );
  const invalidUtf8Tree = Buffer.concat([
    Buffer.from(`100644 blob ${unicodeEntries[0].objectId}\t`, 'ascii'),
    Buffer.from([0xff, 0x00]),
  ]);
  await expectCode('E_SECURITY_TARGET_TREE_INVALID', () => validateGitMaterialization({
    repoRoot: root,
    revision,
    entries: unicodeEntries,
    gitRunner: runnerFor(unicodeEntries, { tree: invalidUtf8Tree }),
  }));

  const changedPath = path.join(root, pilotEntries[0].path);
  fs.writeFileSync(changedPath, 'changed without Git status adapter noticing\n');
  await expectCode('E_SECURITY_TARGET_CONTENT_MISMATCH', () => validateGitMaterialization({
    repoRoot: root, revision, entries: pilotEntries, gitRunner: runnerFor(pilotEntries),
  }));
  fs.writeFileSync(changedPath, 'package pilot0\n');

  const insideState = path.join(root, 'state');
  fs.mkdirSync(insideState, { mode: 0o700 });
  await expectCode('E_SECURITY_TARGET_STATE_LOCATION', () => prepareStandardTarget({
    repoRoot: root, shardGeneration: pilotGeneration, shardId: 'S02/P01', stateDir: insideState,
    helperScriptPath, gitRunner: runnerFor(pilotEntries), scopeRunner: helperRunner(),
  }));
  const stateLink = path.join(os.tmpdir(), `setjoin-security-targets-link-${sha256Hex(root).slice(0, 12)}`);
  fs.symlinkSync(stateRoot, stateLink);
  await expectCode('E_SECURITY_TARGET_PATH_INVALID', () => prepareStandardTarget({
    repoRoot: root, shardGeneration: pilotGeneration, shardId: 'S02/P01', stateDir: stateLink,
    helperScriptPath, gitRunner: runnerFor(pilotEntries), scopeRunner: helperRunner(),
  }));
  fs.unlinkSync(stateLink);

  for (const [code, mutate] of [
    ['E_SECURITY_TARGET_SCOPE_MISMATCH', (paths) => paths.slice(1)],
    ['E_SECURITY_TARGET_SCOPE_MISMATCH', (paths) => [...paths, 'unexpected.go']],
    ['E_SECURITY_TARGET_SCOPE_OUTPUT', (paths) => [paths[0], paths[0], ...paths.slice(1)]],
    ['E_SECURITY_TARGET_SCOPE_OUTPUT', (paths) => [{ path: paths[0], extra: true }, ...paths.slice(1)]],
  ]) {
    const isolatedState = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-targets-mutant-'));
    try {
      await expectCode(code, () => prepareStandardTarget({
        repoRoot: root, shardGeneration: pilotGeneration, shardId: 'S02/P01', stateDir: isolatedState,
        helperScriptPath, gitRunner: runnerFor(pilotEntries), scopeRunner: helperRunner({ mutate }),
      }));
    } finally { fs.rmSync(isolatedState, { recursive: true, force: true }); }
  }
  const mutatedScopesState = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-targets-mutated-scopes-'));
  try {
    await expectCode('E_SECURITY_TARGET_STATE_CONTENT', () => prepareStandardTarget({
      repoRoot: root, shardGeneration: pilotGeneration, shardId: 'S02/P01', stateDir: mutatedScopesState,
      helperScriptPath, gitRunner: runnerFor(pilotEntries), scopeRunner: helperRunner({ mutateScopes: true }),
    }));
  } finally { fs.rmSync(mutatedScopesState, { recursive: true, force: true }); }

  const { backend: fixtureBackend, controls: fixtureMount } = createFixtureReadOnlyBackend();
  const constructionCrashState = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-construction-crash-state-')),
  );
  const constructionCrashParent = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-construction-crash-parent-')),
  );
  const constructionCrashBinding = desktopAttemptBinding('attempt-construction-hard-exit');
  try {
    hardExitDesktopTarget({
      stateDir: constructionCrashState,
      exportParentDir: constructionCrashParent,
      attemptBinding: constructionCrashBinding,
      checkpoint: 'export-sealed',
      backendKind: 'fixture',
    });
    const crashed = onlyPreparationRecord(constructionCrashState);
    assert.equal(crashed.record.phase, 'EXPORT_SEALED');
    assert.equal(crashed.record.attemptBindingSha256,
      sha256Hex(canonicalJson(constructionCrashBinding)));
    assert(fs.statSync(crashed.record.stagingPath).isDirectory(),
      'hard exit after export construction must leave the attributed sealed export');
    assert.equal(fs.statSync(crashed.record.stagingPath).mode & 0o777, 0o500);
    assert.equal(fs.existsSync(crashed.record.imagePath), false);
    assert.equal(fs.existsSync(crashed.record.mountPath), false);
    const quarantines = crashQuarantinePaths(crashed.record);
    const recovered = await prepareDesktopAttestedExportTarget({
      repoRoot: root,
      shardGeneration: pilotGeneration,
      shardId: 'S02/P01',
      stateDir: constructionCrashState,
      exportParentDir: constructionCrashParent,
      pluginRoot,
      gitRunner: runnerFor(pilotEntries),
      pluginDigestRunner: installedPluginDigestRunner,
      readOnlyBackend: fixtureBackend,
      attemptBinding: constructionCrashBinding,
      sourceFingerprintVerifier,
      allowTestBackend: true,
    });
    const authority = verifyPreparedTarget(recovered);
    assert.equal(authority.attemptId, constructionCrashBinding.attemptId,
      'recovery must rebuild under the same immutable attempt identity');
    assert.equal(authority.pathCount, 219);
    assert(fs.statSync(quarantines.build).isDirectory(),
      'the abandoned construction must be quarantined before rebuilding');
    assert(fs.statSync(quarantines.preparation).isFile(),
      'the abandoned preparation authority must be quarantined before rebuilding');
    assert.equal(fs.existsSync(quarantines.mount), false);
    assert.equal(fs.existsSync(quarantines.image), false);
    assert.equal(fs.readdirSync(constructionCrashState)
      .filter((name) => /^desktop-export-attestation-[0-9a-f]{24}\.json$/.test(name)).length, 1,
    'recovery must publish exactly one active target attestation');
  } finally {
    removeFixtureTree(constructionCrashState);
    removeFixtureTree(constructionCrashParent);
  }

  const survivorHoldState = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-survivor-hold-state-')),
  );
  const survivorHoldParent = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-survivor-hold-parent-')),
  );
  const survivorHoldBinding = desktopAttemptBinding('attempt-survivor-hold');
  const survivorHoldArgs = {
    repoRoot: root,
    shardGeneration: pilotGeneration,
    shardId: 'S02/P01',
    stateDir: survivorHoldState,
    exportParentDir: survivorHoldParent,
    pluginRoot,
    gitRunner: runnerFor(pilotEntries),
    pluginDigestRunner: installedPluginDigestRunner,
    readOnlyBackend: fixtureBackend,
    attemptBinding: survivorHoldBinding,
    sourceFingerprintVerifier,
    allowTestBackend: true,
  };
  try {
    hardExitDesktopTarget({
      stateDir: survivorHoldState,
      exportParentDir: survivorHoldParent,
      attemptBinding: survivorHoldBinding,
      checkpoint: 'export-sealed',
      backendKind: 'fixture',
    });
    const crashed = onlyPreparationRecord(survivorHoldState);
    rewritePreparationRecord(crashed.filename, crashed.record, { ownerProcessId: process.pid });
    await expectCode('E_SECURITY_TARGET_PREPARATION_HOLD', () => (
      prepareDesktopAttestedExportTarget(survivorHoldArgs)
    ));
    rewritePreparationRecord(crashed.filename, crashed.record, {
      attemptBindingSha256: '0'.repeat(64),
    });
    await expectCode('E_SECURITY_TARGET_PREPARATION_INVALID', () => (
      prepareDesktopAttestedExportTarget(survivorHoldArgs)
    ));
    assert(fs.existsSync(crashed.record.stagingPath),
      'live or identity-mutated survivor must remain untouched on HOLD');
    for (const candidate of Object.values(crashQuarantinePaths(crashed.record))) {
      assert.equal(fs.existsSync(candidate), false,
        'unattributable survivor must not be silently accepted or quarantined as trusted authority');
    }
  } finally {
    removeFixtureTree(survivorHoldState);
    removeFixtureTree(survivorHoldParent);
  }

  const exported = await prepareDesktopAttestedExportTarget({
    repoRoot: root,
    shardGeneration: pilotGeneration,
    shardId: 'S02/P01',
    stateDir: exportStateRoot,
    exportParentDir: exportParentRoot,
    pluginRoot,
    gitRunner: runnerFor(pilotEntries),
    pluginDigestRunner: installedPluginDigestRunner,
    readOnlyBackend: fixtureBackend,
    attemptBinding: pilotAttemptBinding,
    sourceFingerprintVerifier,
    allowTestBackend: true,
  });
  assert.equal(exported.mode, 'standard');
  assert.equal(exported.standardRoute, STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT);
  assert.equal(exported.targetKind, 'directory_snapshot');
  assert.equal(exported.pathCount, 219);
  assert.equal(exported.productionEligible, false, 'the injectable backend must never claim production support');
  assert.equal(Object.isFrozen(exported.exportCapacity), true, 'issued export capacity must be immutable');
  assert.throws(() => { exported.exportCapacity.maxEntries = 1; }, TypeError);
  assert.deepEqual(exported.entryDisposition, {
    regularFileCount: 219, executableFileCount: 0, rejectedEntryCount: 0, unsupportedDisposition: 'none',
  }, 'S02 must have an explicit all-regular-file export disposition');
  assert.equal(fs.statSync(exported.attestationFile).mode & 0o777, 0o600);
  assert.equal(fs.existsSync(path.join(exported.targetPath, '.git')), false);
  await expectCode('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', () => prepareDesktopAttestedExportTarget({
    repoRoot: root, shardGeneration: pilotGeneration, shardId: 'S02/P01', stateDir: exportStateRoot,
    exportParentDir: exportParentRoot, pluginRoot, gitRunner: runnerFor(pilotEntries),
    pluginDigestRunner: installedPluginDigestRunner, readOnlyBackend: fixtureBackend,
    attemptBinding: { ...desktopAttemptBinding('attempt-extra-field'), extra: true },
    sourceFingerprintVerifier, allowTestBackend: true,
  }));
  assert.equal(
    verifyStandardRouteContract({ pluginRoot, standardRoute: exported.standardRoute }).routeContractSha256,
    PINNED_STANDARD_ROUTE_CONTRACT_SHA256[STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT],
  );
  let echoRevalidatorRequest;
  await expectCode('E_SECURITY_TARGET_FINGERPRINT_MISMATCH', () => rehydrateDesktopAttestedExportTarget({
    repoRoot: root,
    attestationFile: exported.attestationFile,
    shardGeneration: pilotGeneration,
    shardId: 'S02/P01',
    pluginRoot,
    pluginDigestRunner: installedPluginDigestRunner,
    readOnlyBackend: fixtureBackend,
    attemptBinding: pilotAttemptBinding,
    gitRunner: runnerFor(pilotEntries),
    sourceFingerprintVerifier,
    sourceFingerprintRevalidator: (request) => {
      echoRevalidatorRequest = request;
      return { sourceFingerprint: request.expectedSourceFingerprint };
    },
    allowTestBackend: true,
  }));
  assert.deepEqual(echoRevalidatorRequest, { repoRoot: root },
    'the live revalidator must independently observe the repository without receiving the expected value');
  const driftParent = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-plugin-drift-'));
  const driftPlugin = path.join(driftParent, '0.1.24');
  fs.cpSync(pluginRoot, driftPlugin, { recursive: true });
  try {
    for (const [relativePath, route] of [
      ['scripts/finalize_scan_contract.py', STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS],
      ['skills/security-scan/references/desktop-scan.md', STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT],
    ]) {
      const filename = path.join(driftPlugin, relativePath);
      const original = fs.readFileSync(filename);
      const mode = fs.statSync(filename).mode & 0o777;
      fs.chmodSync(filename, 0o600);
      fs.appendFileSync(filename, '\n# route drift fixture\n');
      assert.throws(
        () => verifyStandardRouteContract({ pluginRoot: driftPlugin, standardRoute: route }),
        (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_ROUTE_DRIFT',
        `${relativePath} must be included in the transitive Standard route contract`,
      );
      fs.writeFileSync(filename, original);
      fs.chmodSync(filename, mode);
    }
  } finally { removeFixtureTree(driftParent); }
  const exportAuthority = verifyPreparedTarget(exported);
  assert.equal(exportAuthority.standardRoute, STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT);
  assert.equal(exportAuthority.pathCount, 219);
  assert.equal(exportAuthority.directorySnapshotDigest, exported.directorySnapshotDigest);
  assert.equal(exportAuthority.exportTreeSha256, exported.exportTreeSha256);
  assert.throws(
    () => verifyPreparedTarget({ ...exported }),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_UNVERIFIED',
    'copying Desktop target fields must not forge the opaque capability',
  );
  const rehydrated = await rehydrateDesktopAttestedExportTarget({
    repoRoot: root,
    attestationFile: exported.attestationFile,
    shardGeneration: pilotGeneration,
    shardId: 'S02/P01',
    pluginRoot,
    pluginDigestRunner: installedPluginDigestRunner,
    readOnlyBackend: fixtureBackend,
    attemptBinding: pilotAttemptBinding,
    gitRunner: runnerFor(pilotEntries),
    sourceFingerprintVerifier,
    allowTestBackend: true,
  });
  assert.notEqual(rehydrated, exported);
  assert.deepEqual(verifyPreparedTarget(rehydrated), exportAuthority,
    'rehydration must reissue equivalent authority only after live verification');
  assert.equal(exportAuthority.attemptId, pilotAttemptBinding.attemptId);
  assert.equal(exportAuthority.budgetId, pilotAttemptBinding.budgetId);
  assert.equal(exportAuthority.budgetSha256, pilotAttemptBinding.budgetSha256);
  assert.equal(exportAuthority.controlGenerationHash, pilotAttemptBinding.controlGenerationHash);
  assert.deepEqual(exportAuthority.exportCapacity, pilotAttemptBinding.exportCapacity);

  for (const [code, binding, gitRunner, fingerprintVerifier] of [
    ['E_SECURITY_TARGET_ATTESTATION_TAMPERED', desktopAttemptBinding('attempt-reuse'), runnerFor(pilotEntries), sourceFingerprintVerifier],
    ['E_SECURITY_TARGET_ATTESTATION_TAMPERED', desktopAttemptBinding(pilotAttemptBinding.attemptId, {
      budgetId: 'other-budget-v1', budgetSha256: 'd'.repeat(64),
    }), runnerFor(pilotEntries), sourceFingerprintVerifier],
    ['E_SECURITY_TARGET_DIRTY', pilotAttemptBinding, runnerFor(pilotEntries, {
      status: Buffer.from('?? later-change\0'),
    }), sourceFingerprintVerifier],
    ['E_SECURITY_TARGET_REVISION_MISMATCH', pilotAttemptBinding, runnerFor(pilotEntries, {
      head: '8'.repeat(40),
    }), sourceFingerprintVerifier],
    ['E_SECURITY_TARGET_TUPLE_MISMATCH', pilotAttemptBinding, runnerFor(pilotEntries, {
      tree: [{ ...pilotEntries[0], objectId: '1'.repeat(40) }, ...pilotEntries.slice(1)],
    }), sourceFingerprintVerifier],
    ['E_SECURITY_TARGET_FINGERPRINT_MISMATCH', pilotAttemptBinding, runnerFor(pilotEntries), async () => ({
      sourceFingerprint: `v2:${revision}:${'9'.repeat(64)}`,
    })],
  ]) {
    await expectCode(code, () => rehydrateDesktopAttestedExportTarget({
      repoRoot: root, attestationFile: exported.attestationFile, shardGeneration: pilotGeneration,
      shardId: 'S02/P01', pluginRoot, pluginDigestRunner: installedPluginDigestRunner,
      readOnlyBackend: fixtureBackend, attemptBinding: binding, gitRunner,
      sourceFingerprintVerifier: fingerprintVerifier, allowTestBackend: true,
    }));
  }

  // These are deterministic capacity-boundary inputs, not claims about the
  // repository's observed average file size or directory fanout.
  const projectionDirectoryFanout = 64;
  const projectionBytesPerFile = 4_096;
  const projectedRetainedCopies = 4;
  const projectionSeries = [
    { name: 'authoritative-epoch', baseFileCount: 5_824, expected: [5_824, 58_240, 582_400] },
    { name: 'historical-candidate', baseFileCount: 6_163, expected: [6_163, 61_630, 616_300] },
  ];
  for (const series of projectionSeries) {
    for (const [index, multiplier] of [1, 10, 100].entries()) {
      const fileCount = series.baseFileCount * multiplier;
      assert.equal(fileCount, series.expected[index], `${series.name} ${multiplier}x file count`);
      const directoryCount = Math.ceil(fileCount / projectionDirectoryFanout);
      const exportBytes = fileCount * projectionBytesPerFile;
      const minimumFreeBytes = 8 * 1024 * 1024 * 1024;
      const copies = projectedRetainedCopies;
      const requiredBytes = BigInt(minimumFreeBytes) + (BigInt(exportBytes) * BigInt(copies));
      const exactCapacity = exportCapacity({
        maxEntries: fileCount + directoryCount,
        maxBytes: exportBytes,
        minimumFreeBytes,
      });
      const volumeId = `${series.name}-${multiplier}x`;
      const projection = projectExportCapacity({
        fileCount,
        directoryCount,
        exportBytes,
        volumes: [{ volumeId, copies, availableBytes: requiredBytes }],
      }, exactCapacity);
      assert.equal(projection.fileCount, fileCount);
      assert.equal(projection.expectedEntryCount, fileCount + directoryCount);
      assert.equal(projection.exportBytes, exportBytes);
      assert.equal(projection.entryLimitPass, true);
      assert.equal(projection.byteLimitPass, true);
      assert.equal(projection.volumes[0].requiredBytes, String(requiredBytes));
      assert.equal(projection.volumes[0].spaceLimitPass, true);
      assert.equal(projectExportCapacity({
        fileCount, directoryCount, exportBytes,
        volumes: [{ volumeId, copies, availableBytes: requiredBytes - 1n }],
      }, exactCapacity).volumes[0].spaceLimitPass, false);
      assert.equal(projectExportCapacity({
        fileCount, directoryCount, exportBytes,
        volumes: [{ volumeId, copies, availableBytes: requiredBytes }],
      }, exportCapacity({ ...exactCapacity, maxEntries: exactCapacity.maxEntries - 1 })).entryLimitPass, false);
      assert.equal(projectExportCapacity({
        fileCount, directoryCount, exportBytes,
        volumes: [{ volumeId, copies, availableBytes: requiredBytes }],
      }, exportCapacity({ ...exactCapacity, maxBytes: exactCapacity.maxBytes - 1 })).byteLimitPass, false);
    }
  }

  async function expectCapacityHold(code, count, overrides, attemptId) {
    const entries = pilotEntries.slice(0, count);
    const state = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-capacity-state-'));
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-capacity-parent-'));
    const { backend } = createFixtureReadOnlyBackend();
    try {
      await expectCode(code, () => prepareDesktopAttestedExportTarget({
        repoRoot: root, shardGeneration: generation(entries), shardId: 'S02/P01',
        stateDir: state, exportParentDir: parent, pluginRoot, gitRunner: runnerFor(pilotEntries),
        pluginDigestRunner: installedPluginDigestRunner, readOnlyBackend: backend,
        attemptBinding: desktopAttemptBinding(attemptId, { exportCapacity: exportCapacity(overrides) }),
        sourceFingerprintVerifier, allowTestBackend: true,
      }));
    } finally {
      removeFixtureTree(state);
      removeFixtureTree(parent);
    }
  }
  await expectCapacityHold('E_SECURITY_TARGET_HOLD_CAPACITY_ENTRIES', 10, { maxEntries: 9 }, 'attempt-entry-hold');
  await expectCapacityHold('E_SECURITY_TARGET_HOLD_CAPACITY_BYTES', 10, { maxBytes: 1 }, 'attempt-byte-hold');
  await expectCapacityHold('E_SECURITY_TARGET_HOLD_CAPACITY_SPACE', 1,
    { minimumFreeBytes: Number.MAX_SAFE_INTEGER }, 'attempt-space-hold');
  await expectCapacityHold('E_SECURITY_TARGET_HOLD_BUILD_RSS', 1,
    { maxBuildPeakRssBytes: 1 }, 'attempt-build-rss-hold');
  await expectCapacityHold('E_SECURITY_TARGET_HOLD_BUILD_ELAPSED', 100,
    { maxBuildElapsedMs: 1 }, 'attempt-build-elapsed-hold');
  await expectCapacityHold('E_SECURITY_TARGET_HOLD_SNAPSHOT_ELAPSED', 100,
    { maxSnapshotElapsedMs: 1 }, 'attempt-snapshot-elapsed-hold');
  await expectCapacityHold('E_SECURITY_TARGET_HOLD_SNAPSHOT_RSS', 1,
    { maxSnapshotPeakRssBytes: 1 }, 'attempt-snapshot-rss-hold');

  const rehydrateProgram = String.raw`
    import childProcess from 'node:child_process';
    import fs from 'node:fs';
    import path from 'node:path';
    const api = await import(process.argv[1]);
    const repoRoot = process.argv[2];
    const attestationFile = process.argv[3];
    const pluginRoot = process.argv[4];
    const shardGeneration = JSON.parse(process.argv[5]);
    const backend = {
      backendId: 'fixture-readonly-mount/v1', productionEligible: false,
      unsupportedDisposition: 'HOLD_TEST_ONLY_BACKEND',
      seal() { throw new Error('fresh-process verifier must not rebuild'); },
      inspect({ targetPath }) {
        const metadata = fs.lstatSync(targetPath, { bigint: true });
        return { readOnly: true, targetPath: path.resolve(targetPath), realPath: fs.realpathSync.native(targetPath),
          deviceId: String(metadata.dev), rootInode: String(metadata.ino), deviceIdentifier: 'fixture-device',
          volumeUuid: 'fixture-volume' };
      },
    };
    const digestRunner = ({ pluginRoot: pinned, targetPath }) => {
      const source = [
        'from pathlib import Path', 'import sys',
        "sys.path.insert(0, str(Path(sys.argv[1]) / 'scripts'))",
        'from workbench_target import directory_content_digest',
        'print(directory_content_digest(Path(sys.argv[2]).resolve()))',
      ].join('\n');
      const result = childProcess.spawnSync('python3', ['-c', source, pinned, targetPath], { encoding: 'utf8' });
      if (result.status !== 0) throw new Error(result.stderr);
      return { digest: result.stdout.trim() };
    };
    const attemptBinding = JSON.parse(process.argv[6]);
    const gitRunner = async ({ args }) => {
      const key = args.join('\0');
      if (key === ['rev-parse', '--is-inside-work-tree'].join('\0')) return { status: 0, stdout: 'true\n' };
      if (key === ['rev-parse', '--show-toplevel'].join('\0')) return { status: 0, stdout: repoRoot + '\n' };
      if (key === ['rev-parse', '--verify', 'HEAD^{commit}'].join('\0')) return { status: 0, stdout: shardGeneration.revision + '\n' };
      if (args[0] === 'symbolic-ref') return { status: 1, stdout: Buffer.alloc(0) };
      if (args[0] === 'status') return { status: 0, stdout: Buffer.alloc(0) };
      if (args[0] === 'ls-tree') return { status: 0, stdout: Buffer.concat(shardGeneration.shards[0].paths.map(
        (entry) => Buffer.from(entry.mode + ' blob ' + entry.objectId + '\t' + entry.path + '\0'))) };
      throw new Error('unexpected Git operation');
    };
    const prepared = await api.rehydrateDesktopAttestedExportTarget({ repoRoot, attestationFile, shardGeneration,
      shardId: 'S02/P01', pluginRoot, pluginDigestRunner: digestRunner, readOnlyBackend: backend,
      attemptBinding, gitRunner,
      sourceFingerprintVerifier: () => ({ sourceFingerprint: attemptBinding.sourceFingerprint }),
      allowTestBackend: true });
    const authority = api.verifyPreparedTarget(prepared);
    if (authority.pathCount !== 219 || authority.standardRoute !== 'desktop-attested-export') process.exit(9);
    process.stdout.write('PASS fresh-process rehydration\n');
  `;
  subprocessRuns += 1;
  const freshProcess = childProcess.spawnSync(process.execPath, ['--input-type=module', '-e', rehydrateProgram,
    new URL('./lib/security-program-targets.mjs', import.meta.url).href, root, exported.attestationFile,
    pluginRoot, JSON.stringify(pilotGeneration), JSON.stringify(pilotAttemptBinding)],
  { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  assert.equal(freshProcess.status, 0, freshProcess.stderr);
  assert.equal(freshProcess.stdout, 'PASS fresh-process rehydration\n');

  fixtureMount.readOnly = false;
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_MOUNT_INVALID',
  );
  fixtureMount.readOnly = true;
  fixtureMount.deviceIdentifier = 'replacement-device';
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_MOUNT_CHANGED',
  );
  fixtureMount.deviceIdentifier = 'fixture-device';

  await expectCode('E_SECURITY_TARGET_ATTESTATION_TAMPERED', () => rehydrateDesktopAttestedExportTarget({
      repoRoot: root, attestationFile: exported.attestationFile,
      shardGeneration: { ...pilotGeneration, generationId: 'fixture-target-shards-mutant/v1' },
      shardId: 'S02/P01', pluginRoot, pluginDigestRunner: installedPluginDigestRunner,
      readOnlyBackend: fixtureBackend, attemptBinding: pilotAttemptBinding,
      gitRunner: runnerFor(pilotEntries), sourceFingerprintVerifier, allowTestBackend: true,
    }));

  const attestationBytes = fs.readFileSync(exported.attestationFile);
  const tamperedAttestation = JSON.parse(attestationBytes.toString('utf8'));
  tamperedAttestation.routeContractSha256 = '0'.repeat(64);
  fs.writeFileSync(exported.attestationFile, `${JSON.stringify(tamperedAttestation)}\n`, { mode: 0o600 });
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_ATTESTATION_TAMPERED',
  );
  fs.writeFileSync(exported.attestationFile, attestationBytes, { mode: 0o600 });

  await expectCode('E_SECURITY_TARGET_PLUGIN_DIGEST_MISMATCH', () => rehydrateDesktopAttestedExportTarget({
    repoRoot: root, attestationFile: exported.attestationFile, shardGeneration: pilotGeneration,
    shardId: 'S02/P01', pluginRoot, pluginDigestRunner: () => ({
      digest: `codex-security-snapshot/v1:sha256:${'0'.repeat(64)}`,
    }), readOnlyBackend: fixtureBackend, attemptBinding: pilotAttemptBinding,
    gitRunner: runnerFor(pilotEntries), sourceFingerprintVerifier, allowTestBackend: true,
  }));

  const imagePath = JSON.parse(attestationBytes.toString('utf8')).mount.imagePath;
  const imageBytes = fs.readFileSync(imagePath);
  fs.appendFileSync(imagePath, 'tamper');
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_MOUNT_CHANGED',
  );
  fs.writeFileSync(imagePath, imageBytes, { mode: 0o600 });
  assert.deepEqual(verifyPreparedTarget(exported), exportAuthority);

  const firstExportPath = path.join(exported.targetPath, pilotEntries[0].path);
  const firstExportBytes = fs.readFileSync(firstExportPath);
  const firstExportParent = path.dirname(firstExportPath);
  const firstExportParentMode = fs.statSync(firstExportParent).mode & 0o777;
  const identicalReplacement = `${firstExportPath}.replacement`;
  fs.chmodSync(firstExportParent, 0o700);
  fs.writeFileSync(identicalReplacement, firstExportBytes, { mode: 0o400 });
  fs.renameSync(identicalReplacement, firstExportPath);
  fs.chmodSync(firstExportParent, firstExportParentMode);
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_EXPORT_CHANGED',
    'identical-content inode replacement must invalidate the original stable snapshot authority',
  );

  const exportRootMode = fs.statSync(exported.targetPath).mode & 0o777;
  fs.chmodSync(exported.targetPath, 0o700);
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_MODE_MISMATCH',
    'export root mode drift must fail before target use',
  );
  fs.chmodSync(exported.targetPath, exportRootMode);

  fs.chmodSync(firstExportPath, 0o600);
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_MODE_MISMATCH',
  );
  fs.writeFileSync(firstExportPath, Buffer.from('mutated export\n'));
  fs.chmodSync(firstExportPath, 0o400);
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_CONTENT_MISMATCH',
  );
  fs.chmodSync(firstExportPath, 0o600);
  fs.writeFileSync(firstExportPath, firstExportBytes);
  fs.chmodSync(firstExportPath, 0o400);

  const sharedExportDirectory = path.dirname(firstExportPath);
  fs.chmodSync(sharedExportDirectory, 0o700);
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_MODE_MISMATCH',
  );
  fs.chmodSync(sharedExportDirectory, 0o500);

  fs.chmodSync(exported.targetPath, 0o700);
  const extraExportPath = path.join(exported.targetPath, 'unexpected.go');
  fs.writeFileSync(extraExportPath, 'package unexpected\n', { mode: 0o400 });
  fs.chmodSync(exported.targetPath, exportRootMode);
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_EXPORT_SET_MISMATCH',
  );
  fs.chmodSync(exported.targetPath, 0o700);
  fs.unlinkSync(extraExportPath);
  fs.chmodSync(exported.targetPath, exportRootMode);

  const missingExportPath = `${firstExportPath}.missing`;
  fs.chmodSync(firstExportParent, 0o700);
  fs.renameSync(firstExportPath, missingExportPath);
  fs.chmodSync(firstExportParent, firstExportParentMode);
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_EXPORT_SET_MISMATCH',
  );
  fs.chmodSync(firstExportParent, 0o700);
  fs.renameSync(missingExportPath, firstExportPath);
  fs.chmodSync(firstExportParent, firstExportParentMode);

  fs.chmodSync(exported.targetPath, 0o700);
  const symlinkExportPath = path.join(exported.targetPath, 'unexpected-link');
  fs.symlinkSync(pilotEntries[0].path, symlinkExportPath);
  fs.chmodSync(exported.targetPath, exportRootMode);
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_LINK_UNSAFE',
  );
  fs.chmodSync(exported.targetPath, 0o700);
  fs.unlinkSync(symlinkExportPath);
  fs.chmodSync(exported.targetPath, exportRootMode);

  fs.chmodSync(exported.targetPath, 0o700);
  const hardlinkExportPath = path.join(exported.targetPath, 'unexpected-hardlink');
  fs.linkSync(firstExportPath, hardlinkExportPath);
  fs.chmodSync(exported.targetPath, exportRootMode);
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_LINK_UNSAFE',
  );
  fs.chmodSync(exported.targetPath, 0o700);
  fs.unlinkSync(hardlinkExportPath);
  fs.chmodSync(exported.targetPath, exportRootMode);

  fs.chmodSync(exported.targetPath, 0o700);
  const specialExportPath = path.join(exported.targetPath, 'unexpected-special');
  subprocessRuns += 1;
  const specialFixture = childProcess.spawnSync('/usr/bin/mkfifo', [specialExportPath], { encoding: 'utf8' });
  assert.equal(specialFixture.status, 0, specialFixture.stderr);
  fs.chmodSync(exported.targetPath, exportRootMode);
  assert.throws(
    () => verifyPreparedTarget(exported),
    (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_KIND_UNSUPPORTED',
  );
  fs.chmodSync(exported.targetPath, 0o700);
  fs.unlinkSync(specialExportPath);
  fs.chmodSync(exported.targetPath, exportRootMode);

  const deepEntries = [
    entry('deep/a.go', 'package deep\n'),
    entry('deep/b.go', 'package deep\n'),
  ];
  for (const item of deepEntries) writeEntry(item, 'package deep\n');
  const allEntries = [...deepEntries, ...pilotEntries];
  const deepGeneration = generation(deepEntries, 'S03/P01');
  const deepRunnerState = {};
  const deepRunner = runnerFor(allEntries, deepRunnerState);
  const deep = await prepareDeepTarget({
    repoRoot: root, shardGeneration: deepGeneration, shardId: 'S03/P01', scope: 'deep',
    gitRunner: deepRunner,
  });
  assert.match(verifyPreparedTarget(deep).artifactSha256, /^[0-9a-f]{64}$/, 'Deep directory target must expose a stable authority digest');
  assert.equal(deep.mode, 'deep');
  assert.equal(deep.targetPath, path.join(root, 'deep'));
  assert.equal(deep.scope, '.');

  deepRunnerState.head = '8'.repeat(40);
  assert.throws(() => verifyPreparedTarget(deep), (error) => (
    error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_REVISION_MISMATCH'
  ));
  delete deepRunnerState.head;
  deepRunnerState.status = Buffer.from(' M deep/a.go\0');
  assert.throws(() => verifyPreparedTarget(deep), (error) => (
    error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_DIRTY'
  ));
  delete deepRunnerState.status;
  deepRunnerState.tree = [{ ...deepEntries[0], objectId: '1'.repeat(40) }, ...allEntries.slice(1)];
  assert.throws(() => verifyPreparedTarget(deep), (error) => (
    error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_TUPLE_MISMATCH'
  ));
  delete deepRunnerState.tree;

  const deepAPath = path.join(root, 'deep/a.go');
  fs.writeFileSync(deepAPath, 'package changed\n');
  assert.throws(() => verifyPreparedTarget(deep), (error) => (
    error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_CONTENT_MISMATCH'
  ));
  fs.writeFileSync(deepAPath, 'package deep\n');
  fs.chmodSync(deepAPath, 0o755);
  assert.throws(() => verifyPreparedTarget(deep), (error) => (
    error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_MODE_MISMATCH'
  ));
  fs.chmodSync(deepAPath, 0o644);
  fs.unlinkSync(deepAPath);
  assert.throws(() => verifyPreparedTarget(deep), (error) => (
    error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_PATH_INVALID'
  ));
  fs.writeFileSync(deepAPath, 'package deep\n', { mode: 0o644 });

  const originalDeepPath = path.join(root, 'deep-original');
  fs.renameSync(deep.targetPath, originalDeepPath);
  fs.cpSync(originalDeepPath, deep.targetPath, { recursive: true });
  assert.throws(() => verifyPreparedTarget(deep), (error) => (
    error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_REPOSITORY_MISMATCH'
  ));
  fs.rmSync(deep.targetPath, { recursive: true, force: true });
  fs.renameSync(originalDeepPath, deep.targetPath);
  assert.match(verifyPreparedTarget(deep).artifactSha256, /^[0-9a-f]{64}$/,
    'restored original directory identity must retain the live Deep authority');

  await expectCode('E_SECURITY_TARGET_RUNNER_REQUIRED', () => prepareDeepTarget({
    repoRoot: root, shardGeneration: deepGeneration, shardId: 'S03/P01', scope: 'deep',
    gitRunner: async (invocation) => deepRunner(invocation),
  }));
  const asyncPreparedDeep = await prepareDeepTarget({
    repoRoot: root,
    shardGeneration: deepGeneration,
    shardId: 'S03/P01',
    scope: 'deep',
    gitRunner: async (invocation) => deepRunner(invocation),
    verificationGitRunner: deepRunner,
  });
  assert.match(verifyPreparedTarget(asyncPreparedDeep).artifactSha256, /^[0-9a-f]{64}$/,
    'an asynchronous preparation runner requires a separate synchronous live verifier');

  const isolatedDeepRoot = fs.realpathSync.native(fs.mkdtempSync(
    path.join(os.tmpdir(), 'setjoin-security-deep-root-'),
  ));
  const isolatedDeepOriginal = `${isolatedDeepRoot}-original`;
  const isolatedEntry = entry('only.go', 'package isolated\n');
  fs.writeFileSync(path.join(isolatedDeepRoot, isolatedEntry.path), 'package isolated\n');
  const isolatedGeneration = generation([isolatedEntry], 'S05/P01');
  const isolatedRunner = runnerFor([isolatedEntry], {}, isolatedDeepRoot);
  const isolatedDeep = await prepareDeepTarget({
    repoRoot: isolatedDeepRoot,
    shardGeneration: isolatedGeneration,
    shardId: 'S05/P01',
    scope: '.',
    gitRunner: isolatedRunner,
  });
  fs.renameSync(isolatedDeepRoot, isolatedDeepOriginal);
  fs.mkdirSync(isolatedDeepRoot);
  fs.writeFileSync(path.join(isolatedDeepRoot, isolatedEntry.path), 'package isolated\n');
  assert.throws(() => verifyPreparedTarget(isolatedDeep), (error) => (
    error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_REPOSITORY_MISMATCH'
  ));
  fs.rmSync(isolatedDeepRoot, { recursive: true, force: true });
  fs.renameSync(isolatedDeepOriginal, isolatedDeepRoot);
  assert.match(verifyPreparedTarget(isolatedDeep).artifactSha256, /^[0-9a-f]{64}$/);
  fs.rmSync(isolatedDeepRoot, { recursive: true, force: true });

  await expectCode('E_SECURITY_TARGET_NONCONTIGUOUS', () => prepareDeepTarget({
    repoRoot: root, shardGeneration: pilotGeneration, shardId: 'S02/P01', scope: '.',
    gitRunner: runnerFor(allEntries),
  }));
  await expectCode('E_SECURITY_PROGRAM_EVIDENCE_INVALID', () => prepareDeepTarget({
    repoRoot: root, shardGeneration: deepGeneration, shardId: 'S03/P01', scope: copyRoot,
    gitRunner: runnerFor(allEntries),
  }));
  const copiedDeep = path.join(root, 'copied-deep');
  fs.mkdirSync(copiedDeep);
  fs.copyFileSync(path.join(root, 'deep/a.go'), path.join(copiedDeep, 'a.go'));
  fs.copyFileSync(path.join(root, 'deep/b.go'), path.join(copiedDeep, 'b.go'));
  await expectCode('E_SECURITY_TARGET_NONCONTIGUOUS', () => prepareDeepTarget({
    repoRoot: root, shardGeneration: deepGeneration, shardId: 'S03/P01', scope: 'copied-deep',
    gitRunner: runnerFor(allEntries),
  }));
  const deepLink = path.join(root, 'deep-link');
  fs.symlinkSync('deep', deepLink);
  await expectCode('E_SECURITY_TARGET_SYMLINK', () => prepareDeepTarget({
    repoRoot: root, shardGeneration: deepGeneration, shardId: 'S03/P01', scope: 'deep-link',
    gitRunner: runnerFor(allEntries),
  }));

  const symlinkEntry = { path: 'linked.go', objectId: sha256Hex('deep/a.go').slice(0, 40), mode: '120000', kind: 'symlink' };
  const symlinkGeneration = buildShardGenerationRecord({
    revision,
    inventorySha256: inventoryHash([symlinkEntry]),
    generationId: 'fixture-symlink-shards/v1',
    shards: [{
      id: 'S04/P01', ownerSectionId: 'S04', pathCount: 1,
      pathListSha256: inventoryHash([symlinkEntry]), paths: [symlinkEntry],
    }],
  });
  fs.symlinkSync('deep/a.go', path.join(root, 'linked.go'));
  await expectCode('E_SECURITY_TARGET_KIND_UNSUPPORTED', () => prepareStandardTarget({
    repoRoot: root, shardGeneration: symlinkGeneration, shardId: 'S04/P01',
    stateDir: fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-targets-symlink-')),
    helperScriptPath, gitRunner: runnerFor([...allEntries, symlinkEntry]), scopeRunner: helperRunner(),
  }));

  const unsupportedExportState = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-unsupported-state-'));
  const unsupportedExportParent = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-unsupported-parent-'));
  try {
    await expectCode('E_SECURITY_TARGET_KIND_UNSUPPORTED', () => prepareDesktopAttestedExportTarget({
      repoRoot: root, shardGeneration: symlinkGeneration, shardId: 'S04/P01',
      stateDir: unsupportedExportState, exportParentDir: unsupportedExportParent, pluginRoot,
      gitRunner: runnerFor([...allEntries, symlinkEntry]), pluginDigestRunner: installedPluginDigestRunner,
      readOnlyBackend: fixtureBackend, attemptBinding: desktopAttemptBinding('attempt-symlink'),
      sourceFingerprintVerifier, allowTestBackend: true,
    }));
    const submoduleEntry = { path: 'vendor/submodule', objectId: 'a'.repeat(40), mode: '160000', kind: 'submodule' };
    const submoduleGeneration = buildShardGenerationRecord({
      revision, inventorySha256: inventoryHash([submoduleEntry]), generationId: 'fixture-submodule-shards/v1',
      shards: [{ id: 'S05/P01', ownerSectionId: 'S05', pathCount: 1,
        pathListSha256: inventoryHash([submoduleEntry]), paths: [submoduleEntry] }],
    });
    await expectCode('E_SECURITY_TARGET_KIND_UNSUPPORTED', () => prepareDesktopAttestedExportTarget({
      repoRoot: root, shardGeneration: submoduleGeneration, shardId: 'S05/P01',
      stateDir: unsupportedExportState, exportParentDir: unsupportedExportParent, pluginRoot,
      gitRunner: runnerFor([...allEntries, symlinkEntry, submoduleEntry]), pluginDigestRunner: installedPluginDigestRunner,
      readOnlyBackend: fixtureBackend, attemptBinding: desktopAttemptBinding('attempt-submodule'),
      sourceFingerprintVerifier, allowTestBackend: true,
    }));
  } finally {
    fs.rmSync(unsupportedExportState, { recursive: true, force: true });
    fs.rmSync(unsupportedExportParent, { recursive: true, force: true });
  }

  const unsupportedHostBackend = createMacOsReadOnlyDiskImageBackend({ platform: 'linux' });
  assert.equal(unsupportedHostBackend.productionEligible, false);
  const forgedProductionBackend = Object.freeze({
    backendId: 'macos-readonly-disk-image/v1', productionEligible: true,
    seal() { throw new Error('must not run'); }, inspect() { throw new Error('must not run'); },
  });
  const holdState = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-hold-state-'));
  const holdParent = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-hold-parent-'));
  try {
    await expectCode('E_SECURITY_TARGET_READONLY_UNAVAILABLE', () => prepareDesktopAttestedExportTarget({
      repoRoot: root, shardGeneration: pilotGeneration, shardId: 'S02/P01', stateDir: holdState,
      exportParentDir: holdParent, pluginRoot, gitRunner: runnerFor([...allEntries, symlinkEntry]),
      pluginDigestRunner: installedPluginDigestRunner, readOnlyBackend: unsupportedHostBackend,
      attemptBinding: desktopAttemptBinding('attempt-host-hold'), sourceFingerprintVerifier,
    }));
    await expectCode('E_SECURITY_TARGET_READONLY_UNAVAILABLE', () => prepareDesktopAttestedExportTarget({
      repoRoot: root, shardGeneration: pilotGeneration, shardId: 'S02/P01', stateDir: holdState,
      exportParentDir: holdParent, pluginRoot, gitRunner: runnerFor([...allEntries, symlinkEntry]),
      pluginDigestRunner: installedPluginDigestRunner, readOnlyBackend: forgedProductionBackend,
      attemptBinding: desktopAttemptBinding('attempt-forged-backend'), sourceFingerprintVerifier,
    }));
  } finally {
    fs.rmSync(holdState, { recursive: true, force: true });
    fs.rmSync(holdParent, { recursive: true, force: true });
  }

  let macCrashEvidence = 'HOLD: host is not macOS; production read-only mount crash recovery skipped deterministically';
  let macRouteEvidence = 'HOLD: host is not macOS; production read-only disk-image probe skipped deterministically';
  if (process.platform === 'darwin') {
    const mountCrashState = fs.realpathSync.native(
      fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-mount-crash-state-')),
    );
    const mountCrashParent = fs.realpathSync.native(
      fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-mount-crash-parent-')),
    );
    const mountCrashBinding = desktopAttemptBinding('attempt-readonly-mount-hard-exit');
    const mountCrashBackend = localMacBackend();
    let mountCrashRecord;
    let recoveredMountTarget;
    try {
      hardExitDesktopTarget({
        stateDir: mountCrashState,
        exportParentDir: mountCrashParent,
        attemptBinding: mountCrashBinding,
        checkpoint: 'readonly-target-ready',
        backendKind: 'macos',
      });
      const crashed = onlyPreparationRecord(mountCrashState);
      mountCrashRecord = crashed.record;
      assert.equal(mountCrashRecord.phase, 'READONLY_TARGET_READY');
      assert.equal(mountCrashRecord.attemptBindingSha256,
        sha256Hex(canonicalJson(mountCrashBinding)));
      assert(fs.statSync(mountCrashRecord.stagingPath).isDirectory());
      assert(fs.statSync(mountCrashRecord.imagePath).isFile());
      assert.notEqual(fs.statSync(mountCrashRecord.mountPath).dev,
        fs.statSync(mountCrashParent).dev,
        'hard exit after read-only attachment must leave an attributable mounted survivor');
      const quarantines = crashQuarantinePaths(mountCrashRecord);
      const recovered = await prepareDesktopAttestedExportTarget({
        repoRoot: root,
        shardGeneration: pilotGeneration,
        shardId: 'S02/P01',
        stateDir: mountCrashState,
        exportParentDir: mountCrashParent,
        pluginRoot,
        gitRunner: runnerFor(pilotEntries),
        pluginDigestRunner: installedPluginDigestRunner,
        readOnlyBackend: mountCrashBackend,
        attemptBinding: mountCrashBinding,
        sourceFingerprintVerifier,
      });
      recoveredMountTarget = recovered.targetPath;
      const authority = verifyPreparedTarget(recovered);
      assert.equal(authority.attemptId, mountCrashBinding.attemptId,
        'mounted-survivor recovery must rebuild under the same immutable attempt identity');
      assert.equal(authority.pathCount, 219);
      assert.equal(authority.productionEligible, true);
      for (const [label, candidate] of Object.entries(quarantines)) {
        assert(fs.existsSync(candidate), `${label} crash survivor must be quarantined before rebuilding`);
      }
      assert.equal(fs.statSync(quarantines.mount).dev, fs.statSync(mountCrashParent).dev,
        'quarantined crash mount must be detached from the disk image');
      assert.equal(fs.readdirSync(mountCrashState)
        .filter((name) => /^desktop-export-attestation-[0-9a-f]{24}\.json$/.test(name)).length, 1,
      'mounted-survivor recovery must publish exactly one active target attestation');
      macCrashEvidence = 'PASS: real macOS read-only disk-image crash survivor detached, quarantined, and rebuilt';
    } finally {
      const targetPath = recoveredMountTarget ?? mountCrashRecord?.mountPath;
      if (targetPath && fs.existsSync(targetPath)
          && fs.statSync(targetPath).dev !== fs.statSync(mountCrashParent).dev) {
        mountCrashBackend.detach({ targetPath });
      }
      removeFixtureTree(mountCrashState);
      removeFixtureTree(mountCrashParent);
    }

    const macRunner = ({ command, args, input }) => {
      subprocessRuns += 1;
      const result = childProcess.spawnSync(command, args, { input, encoding: null, maxBuffer: 16 * 1024 * 1024 });
      return { status: result.status ?? 127, stdout: result.stdout ?? Buffer.alloc(0), stderr: result.stderr ?? Buffer.alloc(0) };
    };
    const macBackend = createMacOsReadOnlyDiskImageBackend({ runner: macRunner });
    const macState = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-mac-state-'));
    const macParent = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-export-mac-parent-'));
    let macExport;
    try {
      try {
        macExport = await prepareDesktopAttestedExportTarget({
          repoRoot: root, shardGeneration: pilotGeneration, shardId: 'S02/P01', stateDir: macState,
          exportParentDir: macParent, pluginRoot, gitRunner: runnerFor([...allEntries, symlinkEntry]),
          pluginDigestRunner: installedPluginDigestRunner, readOnlyBackend: macBackend,
          attemptBinding: desktopAttemptBinding('attempt-real-macos'), sourceFingerprintVerifier,
        });
      } catch (error) {
        if (!(error instanceof SecurityProgramError) || error.code !== 'E_SECURITY_TARGET_READONLY_UNAVAILABLE') throw error;
        macRouteEvidence = 'HOLD: macOS disk-image create/attach was unavailable on this host';
      }
      if (macExport) {
        const mountedFile = path.join(macExport.targetPath, pilotEntries[0].path);
        assert.throws(() => fs.writeFileSync(mountedFile, 'write must fail\n'),
          (error) => ['EACCES', 'EROFS'].includes(error.code), 'mounted export must reject a direct write');
        const replacement = path.join(macParent, 'replacement.tmp');
        fs.writeFileSync(replacement, 'replacement\n', { mode: 0o600 });
        assert.throws(() => fs.renameSync(replacement, mountedFile),
          (error) => ['EACCES', 'EROFS', 'EXDEV'].includes(error.code), 'mounted export must reject replacement');
        fs.unlinkSync(replacement);
        assert.equal(verifyPreparedTarget(macExport).productionEligible, true);
        macRouteEvidence = 'PASS: real macOS read-only disk-image rejected mid-scan write and replacement attempts';
      }
    } finally {
      if (macExport) macBackend.detach({ targetPath: macExport.targetPath });
      removeFixtureTree(macState);
      removeFixtureTree(macParent);
    }
  }

  console.log('PASS: exact Standard target round-trip preserves the 219-path S02 fixture');
  console.log('PASS: desktop export binds exact tuples, pinned route/digest, durable authority, and fresh-process rehydration');
  console.log('PASS: closed attempt/budget/capacity authority and full source revalidation reject cross-attempt reuse and drift');
  console.log('PASS: authoritative 5,824 / 58,240 / 582,400 and historical 6,163 / 61,630 / 616,300 path projections prove exact entry/byte/copy/reserve limit arithmetic without mass materialization');
  console.log('PASS: transitive Standard plugin script/schema/reference drift and stable-inode/root-mode mutants fail closed');
  console.log('PASS: route, mount, image, mode, content, extra/missing, symlink, hardlink, and capability mutants fail closed');
  console.log('PASS: real child SIGKILL after export construction quarantines and rebuilds the same attempt with one active authority; live and identity-mutated survivors HOLD');
  console.log(macCrashEvidence);
  console.log(macRouteEvidence);
  console.log('PASS: immutable detached materialization, Unicode/raw-path bytes, tuple, mode, content, state, and helper-output faults fail closed');
  console.log('PASS: Deep live replay rejects revision, dirty, tuple, path, content, mode, target-root, repository-root, async-runner, copied, symlinked, and non-contiguous drift');
  console.log(`PASS: scanner=0 network=0 fingerprint-verifications=${fingerprintVerifications} subprocess=${subprocessRuns} (explicitly injected local helpers/backends only)`);
} finally {
  fs.rmSync(root, { recursive: true, force: true });
  fs.rmSync(stateRoot, { recursive: true, force: true });
  fs.rmSync(copyRoot, { recursive: true, force: true });
  removeFixtureTree(exportStateRoot);
  removeFixtureTree(exportParentRoot);
}
