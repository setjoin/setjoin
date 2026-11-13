#!/usr/bin/env node

import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { EXCLUSION_POLICY_SCHEMA, hashInventory, hashJson } from './lib/security-program-inventory.mjs';
import { computeSourceFingerprint, computeSourceFingerprintSync } from './lib/source-fingerprint.mjs';
import {
  ADMISSION_INPUT_SCHEMA,
  RECORD_ROLES,
  REVIEWED_SET_EXTENSION_KEY,
  buildEpochRecord,
  buildPilotBudgetRecord,
  buildPilotVerdictRecord,
  buildReconciliationRecord,
  buildResultClaimRecord,
  buildReviewedSetRecord,
  buildSectionsRecord,
  buildShardGenerationRecord,
  hashReviewedFilePaths,
  issueVerifiedAdmissionCapability,
  validateReviewedSetExtension,
} from './lib/security-program-records.mjs';
import { SecurityProgramError, canonicalJson, sha256Hex } from './lib/security-program-json.mjs';
import {
  appendAttemptEvent,
  appendSourceVerifiedStartEvent,
  buildReservedAttemptEvent,
  loadAttemptJournal,
  nextAttemptEvent,
} from './lib/security-program-attempts.mjs';
import { publishImmutableBundle, verifyImmutableBundle } from './lib/security-program-publication.mjs';
import {
  EXPORT_CAPACITY_SCHEMA,
  PINNED_STANDARD_ROUTE_CONTRACT_SHA256,
  STANDARD_TARGET_ROUTES,
  TARGET_ADAPTER_VERSION,
  createMacOsReadOnlyDiskImageBackend,
  prepareDesktopAttestedExportTarget,
  verifyPreparedTarget,
} from './lib/security-program-targets.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const epochArtifactPath = path.join(repositoryRoot, 'docs', 'verification', 'security-coverage-epoch.json');
const shardArtifactPath = path.join(repositoryRoot, 'docs', 'verification', 'security-coverage-shards.json');
const pluginRoot = process.env.CODEX_SECURITY_PLUGIN_ROOT
  ?? path.join(os.homedir(), '.codex', 'plugins', 'cache', 'openai-curated-remote', 'codex-security', '0.1.24');
const pluginManifestPath = path.join(pluginRoot, '.codex-plugin', 'plugin.json');
const workbenchPath = path.join(pluginRoot, 'scripts', 'workbench_db.py');
const targetHelperPath = path.join(pluginRoot, 'scripts', 'workbench_target.py');
const sandboxLauncher = '/usr/bin/sandbox-exec';
const gitLauncher = '/Applications/Xcode.app/Contents/Developer/usr/bin/git';
const sqliteRuntimeRoot = fs.realpathSync.native('/opt/homebrew/opt/sqlite');
function resolveExecutable(name) {
  for (const directory of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!directory) continue;
    const candidate = path.resolve(directory, name);
    try {
      const metadata = fs.lstatSync(candidate);
      if ((metadata.isFile() || metadata.isSymbolicLink()) && (fs.statSync(candidate).mode & 0o111) !== 0) {
        return fs.realpathSync.native(candidate);
      }
    } catch (error) {
      if (error?.code !== 'ENOENT' && error?.code !== 'ENOTDIR') throw error;
    }
  }
  throw new Error(`${name} is required for the pinned offline workbench fixture`);
}

const pythonLauncher = resolveExecutable('python3');
const pythonRuntimeLauncher = path.resolve(
  path.dirname(pythonLauncher), '..', 'Resources', 'Python.app', 'Contents', 'MacOS', 'Python',
);
const zeroCost = JSON.stringify({
  model: 'offline-fixture',
  inputTokens: 0,
  cachedInputTokens: 0,
  cacheWriteInputTokens: 0,
  outputTokens: 0,
  estimatedUsd: 0,
});

function requirePinnedRegularFile(filePath, label) {
  assert.equal(path.isAbsolute(filePath), true, `${label} must use an absolute path`);
  assert.equal(fs.realpathSync.native(filePath), filePath, `${label} must not resolve through a symlink`);
  assert.equal(fs.lstatSync(filePath).isFile(), true, `${label} must be a regular file`);
}

assert.equal(fs.realpathSync.native(pluginRoot), pluginRoot, 'pinned plugin root must be canonical');
requirePinnedRegularFile(pluginManifestPath, 'plugin manifest');
requirePinnedRegularFile(workbenchPath, 'workbench');
requirePinnedRegularFile(targetHelperPath, 'target helper');
requirePinnedRegularFile(fs.realpathSync.native(pythonLauncher), 'Python interpreter');
requirePinnedRegularFile(pythonRuntimeLauncher, 'Python runtime launcher');
requirePinnedRegularFile(sandboxLauncher, 'Seatbelt launcher');
requirePinnedRegularFile(gitLauncher, 'Git executable');
requirePinnedRegularFile(epochArtifactPath, 'frozen epoch artifact');
requirePinnedRegularFile(shardArtifactPath, 'frozen shard artifact');
assert.equal(JSON.parse(fs.readFileSync(pluginManifestPath, 'utf8')).version, '0.1.24');

const shardArtifact = JSON.parse(fs.readFileSync(shardArtifactPath, 'utf8'));
const sourceEpochArtifact = JSON.parse(fs.readFileSync(epochArtifactPath, 'utf8'));
assert.equal(sourceEpochArtifact.revision, shardArtifact.revision);
assert.equal(sourceEpochArtifact.inventorySha256, shardArtifact.inventorySha256);
assert.equal(shardArtifact.schema, 'setjoin.security-program.shards/v1');
assert.equal(shardArtifact.revision, '727f40ad1274d950926369913a464bcc8f2e0236');
assert.equal(shardArtifact.inventorySha256, 'b48c312ddc01b7410463eeb1bc659da6a28b2ee2bff50a4d422bf95b5b7407af');
const pilotShard = shardArtifact.shards.find((shard) => shard.id === 'S02/P01');
assert.ok(pilotShard, 'frozen S02/P01 shard must exist');
assert.equal(pilotShard.ownerSectionId, 'S02');
assert.equal(pilotShard.pathCount, 219);
assert.equal(pilotShard.paths.length, 219);
assert.equal(pilotShard.pathListSha256, '0e30eddaacc4e5cb68949e3f043baf514417291cca86b17702ea4f9e7aaafc1f');
assert.equal(hashInventory(pilotShard.paths.map((entry) => ({
  ...entry,
  pathBytes: Buffer.from(entry.path, 'utf8'),
  objectType: 'blob',
}))), pilotShard.pathListSha256);
assert.equal(pilotShard.paths.every((entry) => entry.kind === 'file' && entry.mode === '100644'), true,
  'S02/P01 must remain an all-regular, mode-100644 shard');

const reviewedFiles = pilotShard.paths.map((entry) => entry.path);
assert.deepEqual(reviewedFiles, [...reviewedFiles]
  .sort((left, right) => Buffer.from(left, 'utf8').compare(Buffer.from(right, 'utf8'))));
assert.equal(new Set(reviewedFiles).size, 219);

function reviewedSetExtension(files = reviewedFiles) {
  return {
    [REVIEWED_SET_EXTENSION_KEY]: {
      fully_reviewed_files: [...files],
      count: files.length,
      path_list_sha256: hashReviewedFilePaths(files),
    },
  };
}

const expectedExtension = reviewedSetExtension();
assert.equal(
  expectedExtension[REVIEWED_SET_EXTENSION_KEY].path_list_sha256,
  '9dcddda7950dc0a2f823c50e90016882269cd893ab50b9e30c0b6dfda03f8eb6',
  'the reviewed-set path hash must stay pinned to the exact S02/P01 paths',
);

function requireExactReviewedSet(extensions) {
  const validated = validateReviewedSetExtension(extensions);
  if (canonicalJson(extensions) !== canonicalJson(expectedExtension)) {
    throw new SecurityProgramError(
      'E_SECURITY_PROGRAM_EVIDENCE_INVALID',
      'reviewed-set extension does not match the exact expected export file set',
    );
  }
  assert.deepEqual(validated.reviewedFiles, reviewedFiles);
  assert.equal(validated.count, reviewedFiles.length);
  assert.equal(validated.pathListSha256, expectedExtension[REVIEWED_SET_EXTENSION_KEY].path_list_sha256);
  return validated;
}

function expectSetjoinRejection(extensions, label) {
  assert.throws(
    () => requireExactReviewedSet(extensions),
    (error) => error instanceof SecurityProgramError
      && ['E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', 'E_SECURITY_PROGRAM_EVIDENCE_INVALID'].includes(error.code),
    label,
  );
}

function extensionMutants() {
  const payload = expectedExtension[REVIEWED_SET_EXTENSION_KEY];
  const changedFiles = [...reviewedFiles];
  changedFiles[0] = 'changed-but-well-formed.txt';
  changedFiles.sort((left, right) => Buffer.from(left, 'utf8').compare(Buffer.from(right, 'utf8')));
  return new Map([
    ['missing extensions', undefined],
    ['dropped extension', {}],
    ['unknown extension version', {
      'setjoin.security-program.reviewed-set/v2': structuredClone(payload),
    }],
    ['missing member', {
      [REVIEWED_SET_EXTENSION_KEY]: (({ path_list_sha256: _omitted, ...rest }) => rest)(structuredClone(payload)),
    }],
    ['unknown member', {
      [REVIEWED_SET_EXTENSION_KEY]: { ...structuredClone(payload), inferred: true },
    }],
    ['mutated internally consistent path set', reviewedSetExtension(changedFiles)],
    ['wrong count', {
      [REVIEWED_SET_EXTENSION_KEY]: { ...structuredClone(payload), count: payload.count + 1 },
    }],
    ['wrong framed path hash', {
      [REVIEWED_SET_EXTENSION_KEY]: { ...structuredClone(payload), path_list_sha256: '0'.repeat(64) },
    }],
    ['out-of-order paths', {
      [REVIEWED_SET_EXTENSION_KEY]: {
        ...structuredClone(payload), fully_reviewed_files: [...reviewedFiles].reverse(),
      },
    }],
    ['duplicate path', {
      [REVIEWED_SET_EXTENSION_KEY]: {
        ...structuredClone(payload),
        fully_reviewed_files: [reviewedFiles[0], reviewedFiles[0], ...reviewedFiles.slice(1)],
        count: reviewedFiles.length + 1,
      },
    }],
    ['absolute path', {
      [REVIEWED_SET_EXTENSION_KEY]: {
        ...structuredClone(payload), fully_reviewed_files: ['/private/escape', ...reviewedFiles.slice(1)],
      },
    }],
    ['parent traversal', {
      [REVIEWED_SET_EXTENSION_KEY]: {
        ...structuredClone(payload), fully_reviewed_files: ['../escape', ...reviewedFiles.slice(1)],
      },
    }],
    ['backslash path', {
      [REVIEWED_SET_EXTENSION_KEY]: {
        ...structuredClone(payload), fully_reviewed_files: ['nested\\escape', ...reviewedFiles.slice(1)],
      },
    }],
  ]);
}

for (const [label, mutant] of extensionMutants()) expectSetjoinRejection(mutant, `pre-draft: ${label}`);
requireExactReviewedSet(expectedExtension);

function restoreFixturePermissions(root) {
  if (!fs.existsSync(root)) return;
  const visit = (directory) => {
    fs.chmodSync(directory, 0o700);
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(entryPath);
      else fs.chmodSync(entryPath, 0o600);
    }
  };
  visit(root);
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

const fixtureRoot = fs.realpathSync.native(
  fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-security-workbench-')),
);
const exportRoot = path.join(fixtureRoot, 'export');
const stateRoot = path.join(fixtureRoot, 'state');
const scanRoot = path.join(fixtureRoot, 'scans');
const guardRoot = path.join(fixtureRoot, 'python-guard');
const guardAuditPath = path.join(fixtureRoot, 'guard-audit.log');
const disposableHome = path.join(fixtureRoot, 'home');
const disposableConfig = path.join(fixtureRoot, 'config');
const disposableCache = path.join(fixtureRoot, 'cache');
const emptyBin = path.join(fixtureRoot, 'empty-bin');
const sandboxProfilePath = path.join(fixtureRoot, 'workbench.sb');
const materializerSandboxProfilePath = path.join(fixtureRoot, 'materializer.sb');
const targetAuthorityRoot = path.join(fixtureRoot, 'target-authority');
const targetExportParent = path.join(fixtureRoot, 'target-exports');
const bundleSource = path.join(fixtureRoot, 'bundle-source');
const attemptsDirectory = path.join(fixtureRoot, 'attempt-bundles');
const replayAttemptsDirectory = path.join(fixtureRoot, 'attempt-bundles-republished');
const journalPath = path.join(fixtureRoot, 'journal', 'attempts.json');
const handoffStateRoot = path.join(fixtureRoot, 'fresh-process-state');
const handoffStatePath = path.join(handoffStateRoot, 'authority.json');
const handoffBriefPath = path.join(handoffStateRoot, 'brief.json');
const freshPublicationRoot = path.join(fixtureRoot, 'fresh-process-publication');
const generationsDirectory = path.join(freshPublicationRoot, 'generations');
const pointerPath = path.join(freshPublicationRoot, 'latest.json');
const freshProcessSandboxProfilePath = path.join(fixtureRoot, 'fresh-process.sb');
const sourceCheckoutRoot = path.join(fixtureRoot, 'detached-source');
let workbenchStarts = 0;
let scannerStarts = 0;
let networkStarts = 0;
let materializerGitStarts = 0;
let backendProcessStarts = 0;
let preparedDesktopTarget;
let macReadOnlyBackend;
let activeMountPath;
let sourceFingerprintBeforeLifecycle;
const rawByteFixturePaths = [];
const rawByteFixtureRoots = [];
let invalidUtf8Disposition = 'not-probed';

const credentialSentinels = ['SETJOIN_WORKBENCH_CREDENTIAL_SENTINEL', 'AWS_SECRET_ACCESS_KEY'];
const savedSentinels = Object.fromEntries(credentialSentinels.map((name) => [name, process.env[name]]));
for (const name of credentialSentinels) process.env[name] = `parent-only-${name.toLowerCase()}`;

function seatbeltLiteral(value) {
  assert.equal(/["\\\n\r]/.test(value), false, 'Seatbelt literal path contains unsupported characters');
  return `"${value}"`;
}

function gitObjectId(bytes) {
  const header = Buffer.from(`blob ${bytes.length}\0`, 'utf8');
  return crypto.createHash('sha1').update(header).update(bytes).digest('hex');
}

try {
  for (const directory of [exportRoot, stateRoot, scanRoot, guardRoot, disposableHome,
    disposableConfig, disposableCache, emptyBin, targetAuthorityRoot, targetExportParent,
    bundleSource, handoffStateRoot, freshPublicationRoot]) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  }

  const pythonFrameworkOffset = pythonLauncher.indexOf(`${path.sep}Frameworks${path.sep}`);
  assert.notEqual(pythonFrameworkOffset, -1, 'Python runtime root must be identifiable');
  const pythonRuntimeRoot = pythonLauncher.slice(0, pythonFrameworkOffset);
  const sandboxProfile = [
    '(version 1)',
    '(deny default)',
    '(import "system.sb")',
    '(allow process-fork)',
    `(allow process-exec (literal ${seatbeltLiteral(pythonLauncher)}) (literal ${seatbeltLiteral(pythonRuntimeLauncher)}))`,
    '(allow file-read-metadata)',
    `(allow file-read* (subpath "/System") (subpath "/usr/lib") (subpath "/usr/share") (subpath ${seatbeltLiteral(pythonRuntimeRoot)}) (subpath ${seatbeltLiteral(sqliteRuntimeRoot)}) (subpath ${seatbeltLiteral(pluginRoot)}) (subpath ${seatbeltLiteral(fixtureRoot)}) (literal "/dev/null") (literal "/dev/urandom") (literal "/private/var/db/timezone/zoneinfo/UTC"))`,
    `(allow file-write* (subpath ${seatbeltLiteral(stateRoot)}) (subpath ${seatbeltLiteral(scanRoot)}) (subpath ${seatbeltLiteral(disposableHome)}) (subpath ${seatbeltLiteral(disposableConfig)}) (subpath ${seatbeltLiteral(disposableCache)}) (literal ${seatbeltLiteral(guardAuditPath)}) (literal "/dev/null"))`,
    '(allow sysctl-read)',
    '(allow mach-lookup)',
    '(allow signal (target self))',
    '(deny network*)',
    '',
  ].join('\n');
  fs.writeFileSync(sandboxProfilePath, sandboxProfile, { mode: 0o600 });
  const materializerSandboxProfile = [
    '(version 1)',
    '(deny default)',
    `(allow process-exec (literal ${seatbeltLiteral(gitLauncher)}))`,
    // Apple Git 2.50.1 aborts before diagnostics with an enumerated read allowlist.
    // Its argv is fixed to local cat-file below; writes and network remain denied.
    '(allow file-read*)',
    '(allow file-write* (literal "/dev/null"))',
    '(allow sysctl-read)',
    '(allow mach-lookup)',
    '(deny network*)',
    '',
  ].join('\n');
  fs.writeFileSync(materializerSandboxProfilePath, materializerSandboxProfile, { mode: 0o600 });

  const baseChildEnvironment = Object.freeze({
    PATH: emptyBin,
    HOME: disposableHome,
    XDG_CONFIG_HOME: disposableConfig,
    XDG_CACHE_HOME: disposableCache,
    XDG_STATE_HOME: stateRoot,
    TMPDIR: fixtureRoot,
    LC_ALL: 'C',
    PYTHONUTF8: '1',
    PYTHONNOUSERSITE: '1',
    PYTHONDONTWRITEBYTECODE: '1',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
    GCM_INTERACTIVE: 'Never',
    GIT_ASKPASS: '/usr/bin/false',
    SSH_ASKPASS: '/usr/bin/false',
  });
  const nodeLauncher = fs.realpathSync.native(process.execPath);
  const nodeRuntimeRoot = path.resolve(path.dirname(nodeLauncher), '..');
  const gitRuntimeRoot = path.resolve(path.dirname(gitLauncher), '..');
  const nodeDependencyLinks = [
    'abseil', 'ada-url', 'brotli', 'c-ares', 'hdrhistogram_c', 'highway',
    'icu4c@78', 'libffi', 'libnghttp2', 'libnghttp3', 'libngtcp2', 'libuv',
    'llhttp', 'merve', 'nbytes', 'openssl@3', 'simdjson', 'simdutf', 'sqlite',
    'uvwasi', 'zstd',
  ].map((name) => `/opt/homebrew/opt/${name}`);
  const nodeDependencyRoots = nodeDependencyLinks.flatMap((root) => [
    root, fs.realpathSync.native(root),
  ]);
  const nodeDependencyReadRules = nodeDependencyRoots
    .map((root) => `(subpath ${seatbeltLiteral(root)})`).join(' ');
  const freshProcessSandboxProfile = [
    '(version 1)',
    '(deny default)',
    '(import "system.sb")',
    '(allow process-fork)',
    `(allow process-exec (literal ${seatbeltLiteral(nodeLauncher)}) (literal ${seatbeltLiteral(pythonLauncher)}) (literal ${seatbeltLiteral(pythonRuntimeLauncher)}) (literal ${seatbeltLiteral(gitLauncher)}) (literal "/usr/sbin/diskutil") (literal "/usr/bin/plutil"))`,
    '(allow file-read-metadata)',
    `(allow file-read* (subpath "/System") (subpath "/usr/lib") (subpath "/usr/share") (subpath ${seatbeltLiteral(nodeRuntimeRoot)}) ${nodeDependencyReadRules} (subpath ${seatbeltLiteral(pythonRuntimeRoot)}) (subpath ${seatbeltLiteral(sqliteRuntimeRoot)}) (subpath ${seatbeltLiteral(gitRuntimeRoot)}) (subpath ${seatbeltLiteral(repositoryRoot)}) (subpath ${seatbeltLiteral(pluginRoot)}) (subpath ${seatbeltLiteral(fixtureRoot)}) (literal "/dev/null") (literal "/dev/urandom") (literal "/private/var/db/timezone/zoneinfo/UTC"))`,
    `(allow file-write* (subpath ${seatbeltLiteral(freshPublicationRoot)}) (literal ${seatbeltLiteral(guardAuditPath)}) (literal "/dev/null"))`,
    '(allow sysctl-read)',
    '(allow mach-lookup)',
    '(allow signal (target self))',
    '(deny network*)',
    '',
  ].join('\n');
  fs.writeFileSync(freshProcessSandboxProfilePath, freshProcessSandboxProfile, { mode: 0o600 });
  for (const name of credentialSentinels) {
    assert.equal(Object.hasOwn(baseChildEnvironment, name), false, `${name} must be absent from child env`);
    assert.match(process.env[name], /^parent-only-/, `${name} must remain present only in parent env`);
  }

  const sourceGitEnvironment = Object.freeze({
    ...baseChildEnvironment,
    PATH: '/usr/bin:/bin',
    GIT_OPTIONAL_LOCKS: '0',
  });
  const runSourceGitCommand = (args, label, {
    cwd = fixtureRoot, input, expectedStatus = 0,
  } = {}) => {
    const result = childProcess.spawnSync(gitLauncher, args, {
      cwd,
      input,
      encoding: null,
      env: sourceGitEnvironment,
      maxBuffer: 64 * 1024 * 1024,
    });
    assert.equal(result.status, expectedStatus,
      `${label} failed (signal=${result.signal}):\n${result.error?.stack ?? ''}\n${result.stderr ?? ''}`);
    return result.stdout ?? Buffer.alloc(0);
  };
  runSourceGitCommand([
    '-c', 'core.hooksPath=/dev/null',
    'clone', '-q', '--no-checkout', '--shared', '--no-tags', '--',
    repositoryRoot, sourceCheckoutRoot,
  ], 'disposable local Git clone');
  runSourceGitCommand([
    '-c', 'core.hooksPath=/dev/null', '-C', sourceCheckoutRoot,
    'checkout', '-q', '--detach', shardArtifact.revision,
  ], 'detached frozen Git checkout');
  assert.equal(runSourceGitCommand([
    '-C', sourceCheckoutRoot, 'rev-parse', '--verify', 'HEAD',
  ], 'detached source revision').toString('ascii').trim(), shardArtifact.revision);
  assert.equal(runSourceGitCommand([
    '-C', sourceCheckoutRoot, 'symbolic-ref', '-q', 'HEAD',
  ], 'detached source symbolic ref', { expectedStatus: 1 }).length, 0);
  assert.equal(runSourceGitCommand([
    '-C', sourceCheckoutRoot, 'status', '--porcelain=v1', '-z',
    '--untracked-files=all', '--ignored=matching', '--ignore-submodules=none',
  ], 'detached source cleanliness').length, 0);

  const computeLiveSourceFingerprint = async (root) => {
    const savedEnvironment = { ...process.env };
    for (const name of Object.keys(process.env)) delete process.env[name];
    Object.assign(process.env, sourceGitEnvironment);
    try {
      return await computeSourceFingerprint(root);
    } finally {
      for (const name of Object.keys(process.env)) delete process.env[name];
      Object.assign(process.env, savedEnvironment);
    }
  };
  const computeLiveSourceFingerprintSync = (root) => computeSourceFingerprintSync(root, {
    gitBinary: gitLauncher,
    env: sourceGitEnvironment,
  });
  sourceFingerprintBeforeLifecycle = await computeLiveSourceFingerprint(sourceCheckoutRoot);
  assert.match(sourceFingerprintBeforeLifecycle,
    new RegExp(`^v2:${shardArtifact.revision}:[0-9a-f]{64}$`));

  for (const entry of pilotShard.paths) {
    const gitArgs = ['-C', repositoryRoot, 'cat-file', 'blob', entry.objectId];
    const result = childProcess.spawnSync(sandboxLauncher,
      ['-f', materializerSandboxProfilePath, gitLauncher, ...gitArgs], {
        cwd: fixtureRoot,
        encoding: null,
        env: {
          ...baseChildEnvironment,
          PATH: '/Applications/Xcode.app/Contents/Developer/usr/bin:/usr/bin:/bin',
        },
        maxBuffer: 64 * 1024 * 1024,
      });
    materializerGitStarts += 1;
    assert.equal(result.status, 0, `sandboxed read-only Git materialization failed for ${entry.path} (signal=${result.signal}):\n${result.error?.stack ?? ''}\n${result.stderr ?? ''}`);
    assert.equal(gitObjectId(result.stdout), entry.objectId, `${entry.path} bytes must match its frozen Git blob`);
    const destination = path.join(exportRoot, entry.path);
    fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
    fs.writeFileSync(destination, result.stdout, { mode: 0o400 });
  }
  assert.equal(materializerGitStarts, 219);

  const exportEntries = [];
  const visitExport = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) visitExport(absolute);
      else exportEntries.push(path.relative(exportRoot, absolute).split(path.sep).join('/'));
    }
  };
  visitExport(exportRoot);
  exportEntries.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
  assert.deepEqual(exportEntries, reviewedFiles, 'disposable export must contain exactly the 219 frozen paths');
  // Link, submodule, and special-file rejection belongs to security-program-targets.test.mjs;
  // this workbench route correlates that boundary by requiring the frozen shard to be all regular files.
  for (const relative of reviewedFiles) {
    const metadata = fs.lstatSync(path.join(exportRoot, relative));
    assert.equal(metadata.isFile() && !metadata.isSymbolicLink(), true,
      `${relative} must be a regular non-link export entry`);
    assert.equal(metadata.mode & 0o777, 0o400, `${relative} must preserve frozen mode 100644 as read-only`);
  }
  for (const directory of fs.readdirSync(exportRoot, { recursive: true })
    .map((relative) => path.join(exportRoot, relative))
    .filter((candidate) => fs.lstatSync(candidate).isDirectory())) {
    fs.chmodSync(directory, 0o500);
  }
  fs.chmodSync(exportRoot, 0o500);

  const unwritableProbe = childProcess.spawnSync(sandboxLauncher,
    ['-f', sandboxProfilePath, pythonLauncher, '-c', [
      'import os, pathlib, sys',
      'target = pathlib.Path(sys.argv[1])',
      'checks = [',
      '  lambda: target.open("ab"),',
      '  lambda: os.chmod(target, 0o600),',
      '  lambda: (target.parent / ".forbidden-write").mkdir(),',
      ']',
      'for check in checks:',
      '  try:',
      '    check()',
      '  except PermissionError:',
      '    continue',
      '  raise SystemExit("target write unexpectedly succeeded")',
      'print("target-write-denied")',
    ].join('\n'), path.join(exportRoot, reviewedFiles[0])], {
      cwd: fixtureRoot,
      encoding: 'utf8',
      env: baseChildEnvironment,
    });
  assert.equal(unwritableProbe.status, 0,
    `Seatbelt target-unwritability probe failed: ${unwritableProbe.stderr || unwritableProbe.stdout}`);
  assert.equal(unwritableProbe.stdout.trim(), 'target-write-denied');

  fs.writeFileSync(path.join(guardRoot, 'sitecustomize.py'), String.raw`
import json
import os
import socket
import subprocess

audit_path = os.environ["SETJOIN_WORKBENCH_GUARD_AUDIT"]

def record(event):
    with open(audit_path, "a", encoding="utf-8") as handle:
        handle.write(event + "\n")

credential_names = ${JSON.stringify(credentialSentinels)}
if any(name in os.environ for name in credential_names):
    record("credential-leak")
    raise RuntimeError("offline workbench fixture leaked a parent credential sentinel")
record("credentials-absent")
record("guard-active")

def deny_network(*args, **kwargs):
    record("network-denied")
    raise RuntimeError("offline workbench fixture denied a network operation")

socket.create_connection = deny_network
socket.getaddrinfo = deny_network
socket.socket.connect = deny_network
socket.socket.connect_ex = deny_network
socket.socket.sendto = deny_network

real_popen = subprocess.Popen
allowed_git = {tuple(item) for item in json.loads(os.environ["SETJOIN_WORKBENCH_ALLOWED_GIT_JSON"])}

def guarded_popen(command, *args, **kwargs):
    argv = tuple(os.fspath(item) for item in command) if isinstance(command, (list, tuple)) else (os.fspath(command),)
    if argv not in allowed_git:
        record("scanner-or-process-denied")
        raise RuntimeError("offline workbench fixture denied an unlisted helper argv: " + repr(argv))
    record("local-git-allowed:" + json.dumps(argv[-2:]))
    return real_popen(command, *args, **kwargs)

subprocess.Popen = guarded_popen
`, { mode: 0o600 });

  const allowedGitCommandsFor = (targetPath) => {
    const gitPrefix = [
      'git', '-c', 'core.fsmonitor=false', '-c', 'i18n.logOutputEncoding=UTF-8', '-C', targetPath,
    ];
    return [
      [...gitPrefix, 'rev-parse', '--git-dir'],
      [...gitPrefix, 'rev-parse', '--is-inside-work-tree'],
      [...gitPrefix, 'rev-parse', '--verify', 'HEAD'],
      [...gitPrefix, 'rev-parse', 'HEAD'],
      [...gitPrefix, 'rev-parse', '--show-toplevel'],
    ];
  };
  const guardedEnvironment = {
    ...baseChildEnvironment,
    CODEX_SECURITY_STATE_DIR: stateRoot,
    PYTHONPATH: guardRoot,
    SETJOIN_WORKBENCH_GUARD_AUDIT: guardAuditPath,
    SETJOIN_WORKBENCH_ALLOWED_GIT_JSON: JSON.stringify(allowedGitCommandsFor(exportRoot)),
  };

  const runPython = (args, label, targetPath = exportRoot) => {
    workbenchStarts += args[0] === workbenchPath ? 1 : 0;
    const result = childProcess.spawnSync(sandboxLauncher,
      ['-f', sandboxProfilePath, fs.realpathSync.native(pythonLauncher), ...args], {
      cwd: fixtureRoot,
      encoding: 'utf8',
      env: {
        ...guardedEnvironment,
        SETJOIN_WORKBENCH_ALLOWED_GIT_JSON: JSON.stringify(allowedGitCommandsFor(targetPath)),
      },
      maxBuffer: 16 * 1024 * 1024,
      });
    assert.equal(result.status, 0, `${label} failed:\n${result.stderr || result.stdout}`);
    return result.stdout.trim();
  };

  const expectedDigest = runPython([
    '-c',
    [
      'from pathlib import Path',
      'import sys',
      'sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))',
      'from workbench_target import directory_content_digest',
      'print(directory_content_digest(Path(sys.argv[2]).resolve()))',
    ].join('\n'),
    pluginRoot,
    exportRoot,
  ], 'pinned directory digest');
  assert.match(expectedDigest, /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/);

  const modeProbePath = path.join(exportRoot, reviewedFiles[0]);
  fs.chmodSync(modeProbePath, 0o500);
  const modeMutatedDigest = runPython([
    '-c',
    [
      'from pathlib import Path',
      'import sys',
      'sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))',
      'from workbench_target import directory_content_digest',
      'print(directory_content_digest(Path(sys.argv[2]).resolve()))',
    ].join('\n'),
    pluginRoot,
    exportRoot,
  ], 'mode-sensitive directory digest');
  assert.notEqual(modeMutatedDigest, expectedDigest, 'directory digest must bind regular-file mode');
  fs.chmodSync(modeProbePath, 0o400);

  fs.chmodSync(exportRoot, 0o700);
  const emptyDirectoryProbe = path.join(exportRoot, '.setjoin-empty-directory-probe');
  fs.mkdirSync(emptyDirectoryProbe, { mode: 0o500 });
  fs.chmodSync(exportRoot, 0o500);
  const emptyDirectoryDigest = runPython([
    '-c',
    [
      'from pathlib import Path',
      'import sys',
      'sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))',
      'from workbench_target import directory_content_digest',
      'print(directory_content_digest(Path(sys.argv[2]).resolve()))',
    ].join('\n'),
    pluginRoot,
    exportRoot,
  ], 'empty-directory-sensitive digest');
  assert.notEqual(emptyDirectoryDigest, expectedDigest, 'directory digest must bind empty directories');
  fs.chmodSync(exportRoot, 0o700);
  fs.rmdirSync(emptyDirectoryProbe);
  fs.chmodSync(exportRoot, 0o500);
  const restoredDigest = runPython([
    '-c',
    [
      'from pathlib import Path',
      'import sys',
      'sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))',
      'from workbench_target import directory_content_digest',
      'print(directory_content_digest(Path(sys.argv[2]).resolve()))',
    ].join('\n'),
    pluginRoot,
    exportRoot,
  ], 'restored exact S02/P01 digest');
  assert.equal(restoredDigest, expectedDigest,
    'temporary mode and empty-directory probes must leave the exact export unchanged');

  const digestDirectory = (targetPath, label) => runPython([
    '-c',
    [
      'from pathlib import Path',
      'import sys',
      'sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))',
      'from workbench_target import directory_content_digest',
      'print(directory_content_digest(Path(sys.argv[2]).resolve()))',
    ].join('\n'),
    pluginRoot,
    targetPath,
  ], label, targetPath);
  const enumerateRawPaths = (targetPath, label) => JSON.parse(runPython([
    '-c',
    [
      'import json, os, sys',
      'from pathlib import Path',
      'target = Path(sys.argv[1]).resolve()',
      'print(json.dumps([os.fsencode(path.relative_to(target).as_posix()).hex()',
      '  for path in sorted(target.rglob("*"))]))',
    ].join('\n'),
    targetPath,
  ], label, targetPath));

  const unicodeRoots = [
    path.join(fixtureRoot, 'unicode-digest-forward'),
    path.join(fixtureRoot, 'unicode-digest-reverse'),
  ];
  const privateUseName = '\uE000-private.txt';
  const supplementaryName = '\u{10000}-supplementary.txt';
  const unicodeDirectories = [
    'nested', 'nested/empty', '\u03A9-container', '\u03A9-container/empty',
  ];
  const unicodeFiles = [
    ['Z-latin.txt', Buffer.from('upper-ascii')],
    ['a-latin.txt', Buffer.from('lower-ascii')],
    [privateUseName, Buffer.from('private-use')],
    [supplementaryName, Buffer.from('supplementary-plane')],
    ['\u4E2D-file.txt', Buffer.from('cjk')],
    ['nested/\u03A9-file.txt', Buffer.from('greek-nested')],
  ];
  const unicodeOperations = [
    ...unicodeDirectories.map((relative) => ({ kind: 'directory', relative })),
    ...unicodeFiles.map(([relative, bytes]) => ({ kind: 'file', relative, bytes })),
  ];
  const materializeUnicodeTree = (root, operations) => {
    fs.mkdirSync(root, { mode: 0o700 });
    for (const operation of operations) {
      const destination = path.join(root, operation.relative);
      if (operation.kind === 'directory') fs.mkdirSync(destination, { recursive: true, mode: 0o700 });
      else {
        fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
        fs.writeFileSync(destination, operation.bytes, { mode: 0o600, flag: 'wx' });
      }
    }
    const descendants = fs.readdirSync(root, { recursive: true })
      .map((relative) => path.join(root, relative));
    for (const candidate of descendants.filter((entry) => !fs.lstatSync(entry).isDirectory())) {
      fs.chmodSync(candidate, 0o400);
    }
    for (const candidate of descendants.filter((entry) => fs.lstatSync(entry).isDirectory())
      .sort((left, right) => right.length - left.length)) {
      fs.chmodSync(candidate, 0o500);
    }
    fs.chmodSync(root, 0o500);
  };
  materializeUnicodeTree(unicodeRoots[0], unicodeOperations);
  materializeUnicodeTree(unicodeRoots[1], [...unicodeOperations].reverse());

  const topLevelNames = unicodeOperations
    .map((operation) => operation.relative.split('/')[0])
    .filter((name, index, names) => names.indexOf(name) === index);
  const rawTopLevelOrder = [...topLevelNames]
    .sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  const codeUnitTopLevelOrder = [...topLevelNames].sort();
  assert.notDeepEqual(rawTopLevelOrder, codeUnitTopLevelOrder,
    'U+E000 versus U+10000 must distinguish raw UTF-8 order from UTF-16 code-unit order');
  assert.ok(rawTopLevelOrder.indexOf(privateUseName) < rawTopLevelOrder.indexOf(supplementaryName));
  assert.ok(codeUnitTopLevelOrder.indexOf(supplementaryName) < codeUnitTopLevelOrder.indexOf(privateUseName));
  const expectedUnicodePaths = [
    ...unicodeDirectories, ...unicodeFiles.map(([relative]) => relative),
  ].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  const enumeratedUnicodePaths = enumerateRawPaths(unicodeRoots[0], 'Unicode raw-byte enumeration');
  assert.deepEqual(enumeratedUnicodePaths,
    expectedUnicodePaths.map((relative) => Buffer.from(relative).toString('hex')),
    'pinned helper enumeration must preserve os.fsencode byte ordering');

  const unicodeDigest = digestDirectory(unicodeRoots[0], 'Unicode forward-order digest');
  assert.equal(digestDirectory(unicodeRoots[1], 'Unicode reverse-order digest'), unicodeDigest,
    'directory digest must not depend on creation or native enumeration order');
  const unicodeContentPath = path.join(unicodeRoots[0], 'nested/\u03A9-file.txt');
  const unicodeContentBytes = fs.readFileSync(unicodeContentPath);
  fs.chmodSync(unicodeContentPath, 0o600);
  fs.writeFileSync(unicodeContentPath, Buffer.from('greek-nested-mutated'));
  fs.chmodSync(unicodeContentPath, 0o400);
  assert.notEqual(digestDirectory(unicodeRoots[0], 'Unicode content mutation digest'), unicodeDigest);
  fs.chmodSync(unicodeContentPath, 0o600);
  fs.writeFileSync(unicodeContentPath, unicodeContentBytes);
  fs.chmodSync(unicodeContentPath, 0o400);
  assert.equal(digestDirectory(unicodeRoots[0], 'Unicode content restoration digest'), unicodeDigest);

  fs.chmodSync(unicodeContentPath, 0o500);
  assert.notEqual(digestDirectory(unicodeRoots[0], 'Unicode mode mutation digest'), unicodeDigest);
  fs.chmodSync(unicodeContentPath, 0o400);
  assert.equal(digestDirectory(unicodeRoots[0], 'Unicode mode restoration digest'), unicodeDigest);

  const unicodeOriginalName = path.join(unicodeRoots[0], 'Z-latin.txt');
  const unicodeMutatedName = path.join(unicodeRoots[0], 'Y-latin.txt');
  fs.chmodSync(unicodeRoots[0], 0o700);
  fs.renameSync(unicodeOriginalName, unicodeMutatedName);
  fs.chmodSync(unicodeRoots[0], 0o500);
  assert.notEqual(digestDirectory(unicodeRoots[0], 'Unicode name mutation digest'), unicodeDigest);
  fs.chmodSync(unicodeRoots[0], 0o700);
  fs.renameSync(unicodeMutatedName, unicodeOriginalName);
  fs.chmodSync(unicodeRoots[0], 0o500);
  assert.equal(digestDirectory(unicodeRoots[0], 'Unicode name restoration digest'), unicodeDigest);

  const unicodeEmptyDirectory = path.join(unicodeRoots[0], '\u03A9-container/empty');
  const unicodeEmptyParent = path.dirname(unicodeEmptyDirectory);
  fs.chmodSync(unicodeEmptyParent, 0o700);
  fs.rmdirSync(unicodeEmptyDirectory);
  fs.chmodSync(unicodeEmptyParent, 0o500);
  assert.notEqual(digestDirectory(unicodeRoots[0], 'Unicode empty-directory removal digest'), unicodeDigest);
  fs.chmodSync(unicodeEmptyParent, 0o700);
  fs.mkdirSync(unicodeEmptyDirectory, { mode: 0o500 });
  fs.chmodSync(unicodeEmptyParent, 0o500);
  assert.equal(digestDirectory(unicodeRoots[0], 'Unicode empty-directory restoration digest'), unicodeDigest);

  const rawRoots = [
    path.join(fixtureRoot, 'raw-byte-digest-forward'),
    path.join(fixtureRoot, 'raw-byte-digest-reverse'),
  ];
  const invalidRawNames = [Buffer.from('z-valid'), Buffer.from([0x80]), Buffer.from([0xff])];
  const rawPath = (root, name) => Buffer.concat([
    Buffer.from(root), Buffer.from(path.sep), name,
  ]);
  let invalidNamesCreated = false;
  try {
    for (const [index, root] of rawRoots.entries()) {
      fs.mkdirSync(root, { mode: 0o700 });
      rawByteFixtureRoots.push(root);
      const names = index === 0 ? invalidRawNames : [...invalidRawNames].reverse();
      for (const name of names) {
        const filename = rawPath(root, name);
        fs.writeFileSync(filename, Buffer.from(`raw-${name.toString('hex')}`), { mode: 0o400, flag: 'wx' });
        rawByteFixturePaths.push(filename);
      }
      fs.chmodSync(root, 0o500);
    }
    invalidNamesCreated = true;
  } catch (error) {
    assert.equal(process.platform, 'darwin');
    assert.ok(['EINVAL', 'EILSEQ', 'ENOTSUP'].includes(error?.code),
      `unexpected invalid UTF-8 filesystem failure: ${error?.code ?? error}`);
    invalidUtf8Disposition = `filesystem-unrepresentable:${error.code};target-parser-HOLD`;
  }
  if (invalidNamesCreated) {
    invalidUtf8Disposition = 'represented-and-byte-verified';
    const expectedRawNameHex = [...invalidRawNames].sort(Buffer.compare).map((name) => name.toString('hex'));
    const listedRawNameHex = fs.readdirSync(rawRoots[0], { encoding: 'buffer' })
      .sort(Buffer.compare).map((name) => name.toString('hex'));
    assert.deepEqual(listedRawNameHex, expectedRawNameHex);
    assert.deepEqual(enumerateRawPaths(rawRoots[0], 'invalid UTF-8 os.fsencode enumeration'),
      expectedRawNameHex);
    const rawDigest = digestDirectory(rawRoots[0], 'invalid UTF-8 forward-order digest');
    assert.equal(digestDirectory(rawRoots[1], 'invalid UTF-8 reverse-order digest'), rawDigest,
      'invalid UTF-8 digest must be deterministic across creation order');
    const originalRawPath = rawPath(rawRoots[0], Buffer.from([0x80]));
    const mutatedRawPath = rawPath(rawRoots[0], Buffer.from([0x81]));
    rawByteFixturePaths.push(mutatedRawPath);
    fs.chmodSync(rawRoots[0], 0o700);
    fs.renameSync(originalRawPath, mutatedRawPath);
    fs.chmodSync(rawRoots[0], 0o500);
    assert.notEqual(digestDirectory(rawRoots[0], 'invalid UTF-8 name mutation digest'), rawDigest);
    fs.chmodSync(rawRoots[0], 0o700);
    fs.renameSync(mutatedRawPath, originalRawPath);
    fs.chmodSync(rawRoots[0], 0o500);
    assert.equal(digestDirectory(rawRoots[0], 'invalid UTF-8 name restoration digest'), rawDigest);
  }

  const start = JSON.parse(runPython([
    workbenchPath,
    'start-prompt-only-scan',
    '--thread-id', 'setjoin-offline-workbench-fixture',
    '--target-path', exportRoot,
    '--scope', '.',
    '--mode', 'standard',
    '--scan-root', scanRoot,
  ], 'workbench start'));
  const scanId = start.scan.scanId;
  const scanDir = start.scan.scanDir;
  assert.match(scanId, /^[0-9a-f]{8}-[0-9a-f-]{27}$/);
  assert.equal(start.startDisposition, 'created');
  assert.equal(start.scan.targetRevision, 'unversioned');
  assert.equal(start.scan.progress.coverage.filesTotal, 219);
  assert.deepEqual(start.scan.contract.target.allowedKinds, ['directory_snapshot']);
  assert.equal(start.scan.contract.target.requiredSnapshotDigest, expectedDigest);
  assert.equal(start.scan.contract.scope.requestedPath, '.');
  assert.deepEqual(start.scan.contract.scope.requiredIncludePaths, ['.']);
  assert.deepEqual(start.scan.contract.scope.requiredExcludePaths, []);

  const draft = {
    manifest: {
      scan: {
        target: { kind: 'directory_snapshot' },
        scope: { includePaths: ['.'], excludePaths: [] },
      },
    },
    findings: { findings: [] },
    coverage: {
      completeness: 'complete',
      inventoryStrategy: 'directory',
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
      extensions: structuredClone(expectedExtension),
    },
  };
  requireExactReviewedSet(draft.coverage.extensions);
  const draftsDirectory = path.join(scanDir, 'drafts');
  fs.mkdirSync(draftsDirectory, { mode: 0o700 });
  const draftPath = path.join(draftsDirectory, `${crypto.randomUUID()}.json`);
  fs.writeFileSync(draftPath, `${JSON.stringify(draft, null, 2)}\n`, { mode: 0o600 });

  const draftResult = JSON.parse(runPython([
    workbenchPath,
    'write-scan-draft',
    '--scan-id', scanId,
    '--draft-path', draftPath,
  ], 'workbench draft'));
  assert.deepEqual(draftResult, { scanId, status: 'draft_written' });
  assert.deepEqual(JSON.parse(fs.readFileSync(draftPath, 'utf8')).coverage.extensions, expectedExtension);
  const canonicalDraft = JSON.parse(fs.readFileSync(path.join(scanDir, 'coverage.json'), 'utf8'));
  assert.deepEqual(canonicalDraft.extensions, expectedExtension);
  requireExactReviewedSet(canonicalDraft.extensions);

  const completed = JSON.parse(runPython([
    workbenchPath,
    'complete-scan',
    '--scan-id', scanId,
    '--cost-json', zeroCost,
  ], 'workbench completion'));
  assert.equal(completed.scan.scanId, scanId);
  assert.equal(completed.scan.progress.status, 'complete');
  assert.deepEqual(completed.scan.cost, JSON.parse(zeroCost));

  const sealedCoveragePath = path.join(scanDir, 'coverage.json');
  const sealedFindingsPath = path.join(scanDir, 'findings.json');
  const sealedManifestPath = path.join(scanDir, 'scan-manifest.json');
  const sealedCoverage = JSON.parse(fs.readFileSync(sealedCoveragePath, 'utf8'));
  const sealedManifest = JSON.parse(fs.readFileSync(sealedManifestPath, 'utf8'));
  assert.deepEqual(sealedCoverage.extensions, expectedExtension);
  requireExactReviewedSet(sealedCoverage.extensions);
  assert.equal(sealedCoverage.scanId, scanId);
  assert.equal(sealedCoverage.completeness, 'complete');
  assert.equal(sealedCoverage.mode, 'repository');
  assert.deepEqual(sealedCoverage.includePaths, ['.']);
  assert.deepEqual(sealedCoverage.excludePaths, []);
  assert.equal(sealedManifest.scan.id, scanId);
  assert.equal(sealedManifest.scan.status, 'completed');
  assert.equal(sealedManifest.scan.target.kind, 'directory_snapshot');
  assert.equal(sealedManifest.scan.target.snapshotDigest, expectedDigest);
  assert.deepEqual(sealedManifest.scan.scope.includePaths, ['.']);
  assert.deepEqual(sealedManifest.scan.scope.excludePaths, []);
  assert.equal(typeof sealedManifest.scan.sealedAt, 'string');

  const expectedArtifactPaths = ['coverage.json', 'findings.json'];
  assert.deepEqual(sealedManifest.scan.artifacts.map((artifact) => artifact.path).sort(), expectedArtifactPaths);
  for (const artifact of sealedManifest.scan.artifacts) {
    const artifactPath = path.join(scanDir, artifact.path);
    assert.equal(artifact.sha256, sha256File(artifactPath), `${artifact.path} digest must match sealed bytes`);
    assert.equal(artifact.mediaType, 'application/json');
  }
  assert.equal(sha256File(sealedCoveragePath), sealedManifest.scan.artifacts
    .find((artifact) => artifact.path === 'coverage.json').sha256);
  assert.deepEqual(JSON.parse(fs.readFileSync(sealedFindingsPath, 'utf8')).findings, []);

  for (const [label, mutant] of extensionMutants()) {
    const candidateCoverage = structuredClone(sealedCoverage);
    if (mutant === undefined) delete candidateCoverage.extensions;
    else candidateCoverage.extensions = mutant;
    expectSetjoinRejection(candidateCoverage.extensions, `sealed readback: ${label}`);
  }

  // Project the frozen S02/P01 tuples into a one-shard fixture authority so a
  // single admitted result can mechanically reconcile to PASS without claiming
  // credit for any path outside this integration fixture.
  const integrationTime = sealedManifest.scan.sealedAt;
  const exclusionPolicy = {
    schema: EXCLUSION_POLICY_SCHEMA, policyVersion: 'workbench-s02-fixture/v1', classes: [],
  };
  const integrationEpoch = buildEpochRecord({
    revision: shardArtifact.revision,
    sourceCommittedAt: sourceEpochArtifact.sourceCommittedAt,
    historicalCandidateCount: 219,
    treePathCount: 219,
    authorizedCount: 219,
    excludedCount: 0,
    inventorySha256: pilotShard.pathListSha256,
    exclusionPolicy,
    exclusionPolicySha256: hashJson(exclusionPolicy),
    authorizedPaths: structuredClone(pilotShard.paths),
    excludedPaths: [],
  });
  const integrationSections = buildSectionsRecord({
    revision: integrationEpoch.revision,
    inventorySha256: integrationEpoch.inventorySha256,
    catalogVersion: 'workbench-s02-fixture/v1',
    sections: [{
      id: 'S02', title: 'Exact S02 workbench fixture',
      selectorProvenance: 'frozen S02/P01 verification tuples',
      pathCount: 219, paths: structuredClone(pilotShard.paths),
    }],
  }, { epoch: integrationEpoch });
  const integrationShards = buildShardGenerationRecord({
    revision: integrationEpoch.revision,
    inventorySha256: integrationEpoch.inventorySha256,
    generationId: 'workbench-s02-fixture/v1',
    shards: [structuredClone(pilotShard)],
  }, { epoch: integrationEpoch, sections: integrationSections });

  const attemptId = 'attempt-workbench-s02-p01';
  const controlGenerationHash = sha256Hex('workbench-s02-control-generation/v1');
  const sourceFingerprint = sourceFingerprintBeforeLifecycle;
  const filesystem = fs.statfsSync(fixtureRoot);
  const availableBytes = Number(filesystem.bavail) * Number(filesystem.bsize);
  const hostRamBytes = os.totalmem();
  const exportCapacity = {
    schema: EXPORT_CAPACITY_SCHEMA,
    maxEntries: 500,
    maxBytes: 512 * 1024 * 1024,
    minimumFreeBytes: 1,
    maxBuildElapsedMs: 120_000,
    maxBuildPeakRssBytes: hostRamBytes,
    maxSnapshotElapsedMs: 120_000,
    maxSnapshotPeakRssBytes: hostRamBytes,
  };
  const routeContractSha256 = PINNED_STANDARD_ROUTE_CONTRACT_SHA256[
    STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT
  ];
  const pilotBudget = buildPilotBudgetRecord({
    budgetId: 'workbench-s02-pilot-v1',
    registeredAt: integrationTime,
    epochRevision: integrationEpoch.revision,
    inventorySha256: integrationEpoch.inventorySha256,
    shardGenerationId: integrationShards.generationId,
    pilotShardId: pilotShard.id,
    shardPathListSha256: pilotShard.pathListSha256,
    controlGenerationHash,
    pilotPathCount: 219,
    limits: {
      maxElapsedSeconds: 7_200, maxArtifactBytes: 1_000_000_000,
      maxPeakRssBytes: hostRamBytes, maxOperatorSeconds: 600,
      minCreditedFilesPerHour: 1, minFreeBytesAfter: 1, maxRetries: 0,
      wholeEpochMaxElapsedSeconds: 7_200,
      wholeEpochMaxArtifactBytes: 1_000_000_000,
      maxExportBytes: exportCapacity.maxBytes,
      maxExportEntries: exportCapacity.maxEntries,
      maxExportBuildSeconds: exportCapacity.maxBuildElapsedMs / 1_000,
      maxSnapshotSeconds: exportCapacity.maxSnapshotElapsedMs / 1_000,
    },
    host: {
      hostClass: 'fixture-macos', os: 'darwin', architecture: process.arch,
      cpuCount: os.cpus().length, ramBytes: hostRamBytes,
      diskFreeBytes: availableBytes, volumeId: 'fixture-volume',
    },
    scanner: {
      adapterVersion: TARGET_ADAPTER_VERSION,
      scannerSchemaVersion: 'scanner-schema/v1',
      configSha256: sha256Hex(canonicalJson({
        pluginVersion: '0.1.24', mode: 'standard', targetKind: 'directory_snapshot', scope: '.',
      })),
      standardRoute: STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
      routeContractSha256,
      pluginVersion: '0.1.24',
      targetForm: 'attested-directory-export',
      targetKind: 'directory_snapshot',
      productionEligible: true,
      deepScanMaxTimeHours: 6,
    },
    exportCapacity,
  }, { epoch: integrationEpoch, shards: integrationShards });

  const targetGitOperations = new Set([
    ['rev-parse', '--is-inside-work-tree'],
    ['rev-parse', '--show-toplevel'],
    ['rev-parse', '--verify', 'HEAD^{commit}'],
    ['symbolic-ref', '-q', 'HEAD'],
    ['status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=matching', '--ignore-submodules=none'],
    ['ls-tree', '-r', '-z', '--full-tree', integrationEpoch.revision],
  ].map((args) => JSON.stringify(args)));
  const targetGitRunner = async ({ repoRoot: requestedRoot, args }) => {
    assert.equal(requestedRoot, sourceCheckoutRoot);
    assert.equal(targetGitOperations.has(JSON.stringify(args)), true,
      `unexpected target authority Git operation ${args.join(' ')}`);
    const result = childProcess.spawnSync(gitLauncher, [
      '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
      '-C', requestedRoot, ...args,
    ], {
      encoding: null,
      env: sourceGitEnvironment,
      maxBuffer: 64 * 1024 * 1024,
    });
    return {
      status: result.status ?? 127,
      stdout: result.stdout ?? Buffer.alloc(0),
      stderr: result.stderr ?? Buffer.alloc(0),
    };
  };
  const macBackendRunner = ({ command, args, input }) => {
    const result = childProcess.spawnSync(command, args, {
      input, encoding: null, maxBuffer: 16 * 1024 * 1024,
      env: { ...baseChildEnvironment, PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
    });
    backendProcessStarts += 1;
    if (result.status === 0 && command === '/usr/bin/hdiutil' && args[0] === 'attach') {
      activeMountPath = args[args.indexOf('-mountpoint') + 1];
    } else if (result.status === 0 && command === '/usr/bin/hdiutil' && args[0] === 'detach') {
      activeMountPath = undefined;
    }
    return {
      status: result.status ?? 127,
      stdout: result.stdout ?? Buffer.alloc(0),
      stderr: result.stderr ?? Buffer.alloc(0),
    };
  };
  macReadOnlyBackend = createMacOsReadOnlyDiskImageBackend({ runner: macBackendRunner });
  const attemptBinding = {
    schema: 'setjoin.security-program.desktop-attempt-binding/v1',
    attemptId, sourceFingerprint, controlGenerationHash,
    budgetId: pilotBudget.budgetId, budgetSha256: pilotBudget.budgetSha256, exportCapacity,
  };
  const liveSourceFingerprintVerifier = async ({ repoRoot: requestedRoot }) => {
    assert.equal(requestedRoot, sourceCheckoutRoot);
    return { sourceFingerprint: await computeLiveSourceFingerprint(requestedRoot) };
  };
  const liveSourceFingerprintRevalidator = ({ repoRoot: requestedRoot }) => {
    assert.equal(requestedRoot, sourceCheckoutRoot);
    return { sourceFingerprint: computeLiveSourceFingerprintSync(requestedRoot) };
  };
  const driftProbePath = path.join(sourceCheckoutRoot, pilotShard.paths[0].path);
  const driftProbeBytes = fs.readFileSync(driftProbePath);
  const driftProbeMode = fs.statSync(driftProbePath).mode & 0o777;
  let driftInjected = false;
  try {
    await assert.rejects(prepareDesktopAttestedExportTarget({
      repoRoot: sourceCheckoutRoot,
      shardGeneration: integrationShards,
      shardId: pilotShard.id,
      stateDir: targetAuthorityRoot,
      exportParentDir: targetExportParent,
      pluginRoot,
      gitRunner: targetGitRunner,
      pluginDigestRunner: ({ pluginRoot: requestedPluginRoot, targetPath }) => ({
        digest: runPython(['-c', [
          'from pathlib import Path', 'import sys',
          'sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))',
          'from workbench_target import directory_content_digest',
          'print(directory_content_digest(Path(sys.argv[2]).resolve()))',
        ].join('\n'), requestedPluginRoot, targetPath], 'rejected drift target digest', targetPath),
      }),
      readOnlyBackend: macReadOnlyBackend,
      attemptBinding,
      sourceFingerprintVerifier: async ({ repoRoot: requestedRoot }) => {
        assert.equal(requestedRoot, sourceCheckoutRoot);
        fs.chmodSync(driftProbePath, 0o600);
        fs.appendFileSync(driftProbePath, '\nsource-fingerprint-drift-probe\n');
        driftInjected = true;
        return { sourceFingerprint: await computeLiveSourceFingerprint(requestedRoot) };
      },
      sourceFingerprintRevalidator: liveSourceFingerprintRevalidator,
    }), (error) => error instanceof SecurityProgramError
      && error.code === 'E_SECURITY_TARGET_FINGERPRINT_MISMATCH');
  } finally {
    if (driftInjected) {
      fs.writeFileSync(driftProbePath, driftProbeBytes);
      fs.chmodSync(driftProbePath, driftProbeMode);
    }
  }
  assert.equal(await computeLiveSourceFingerprint(sourceCheckoutRoot), sourceFingerprint,
    'source fingerprint must restore exactly after the live mutation rejection');
  preparedDesktopTarget = await prepareDesktopAttestedExportTarget({
    repoRoot: sourceCheckoutRoot,
    shardGeneration: integrationShards,
    shardId: pilotShard.id,
    stateDir: targetAuthorityRoot,
    exportParentDir: targetExportParent,
    pluginRoot,
    gitRunner: targetGitRunner,
    pluginDigestRunner: ({ pluginRoot: requestedPluginRoot, targetPath }) => ({
      digest: runPython(['-c', [
        'from pathlib import Path', 'import sys',
        'sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))',
        'from workbench_target import directory_content_digest',
        'print(directory_content_digest(Path(sys.argv[2]).resolve()))',
      ].join('\n'), requestedPluginRoot, targetPath], 'prepared Desktop target digest', targetPath),
    }),
    readOnlyBackend: macReadOnlyBackend,
    attemptBinding,
    sourceFingerprintVerifier: liveSourceFingerprintVerifier,
    sourceFingerprintRevalidator: liveSourceFingerprintRevalidator,
  });
  const targetAuthority = verifyPreparedTarget(preparedDesktopTarget);
  assert.equal(targetAuthority.productionEligible, true);
  assert.equal(targetAuthority.pathCount, 219);
  assert.equal(targetAuthority.pathListSha256, pilotShard.pathListSha256);
  assert.equal(targetAuthority.directorySnapshotDigest, expectedDigest);
  assert.equal(targetAuthority.budgetSha256, pilotBudget.budgetSha256);
  assert.equal(targetAuthority.routeContractSha256, routeContractSha256);

  fs.chmodSync(driftProbePath, 0o600);
  fs.appendFileSync(driftProbePath, '\npost-preparation-reservation-drift\n');
  assert.throws(() => buildReservedAttemptEvent({
    eventId: 'workbench-drifted-reservation', attemptId, recordedAt: integrationTime,
    sourceFingerprint, shardId: pilotShard.id, mode: 'Standard',
    targetForm: 'attested-directory-export', targetKind: 'directory_snapshot',
    controlGenerationHash, leaseOwner: 'fixture-coordinator',
    coordinatorVersion: 'workbench-fixture/v1', adapterVersion: TARGET_ADAPTER_VERSION,
    scannerSchemaVersion: 'scanner-schema/v1', fingerprintVersion: 'fingerprint/v2',
    controlSchemaSetVersion: 'workbench-controls/v1',
  }, { epoch: integrationEpoch, shards: integrationShards, target: preparedDesktopTarget }),
  (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_FINGERPRINT_MISMATCH');
  fs.writeFileSync(driftProbePath, driftProbeBytes);
  fs.chmodSync(driftProbePath, driftProbeMode);

  let journalEvent = buildReservedAttemptEvent({
    eventId: 'workbench-s02-0', attemptId, recordedAt: integrationTime,
    sourceFingerprint, shardId: pilotShard.id, mode: 'Standard',
    targetForm: 'attested-directory-export', targetKind: 'directory_snapshot',
    controlGenerationHash, leaseOwner: 'fixture-coordinator',
    coordinatorVersion: 'workbench-fixture/v1', adapterVersion: TARGET_ADAPTER_VERSION,
    scannerSchemaVersion: 'scanner-schema/v1', fingerprintVersion: 'fingerprint/v2',
    controlSchemaSetVersion: 'workbench-controls/v1',
  }, { epoch: integrationEpoch, shards: integrationShards, target: preparedDesktopTarget });
  journalEvent = appendAttemptEvent(journalPath, journalEvent);
  assert.throws(() => appendAttemptEvent(journalPath, nextAttemptEvent(journalEvent, 'START_REQUESTED', {
    eventId: 'workbench-unverified-start', recordedAt: integrationTime,
  })), (error) => error instanceof SecurityProgramError
    && error.code === 'E_SECURITY_PROGRAM_EVIDENCE_INVALID');
  fs.mkdirSync(`${journalPath}.lock`, { mode: 0o700 });
  assert.throws(() => appendSourceVerifiedStartEvent(journalPath, journalEvent, {
    eventId: 'workbench-lock-failed-start', recordedAt: integrationTime,
  }, { epoch: integrationEpoch, shards: integrationShards, target: preparedDesktopTarget }),
  (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_PROGRAM_LIVE_LEASE');
  fs.rmdirSync(`${journalPath}.lock`);
  fs.chmodSync(driftProbePath, 0o600);
  fs.appendFileSync(driftProbePath, '\npost-reservation-start-drift\n');
  assert.throws(() => appendSourceVerifiedStartEvent(journalPath, journalEvent, {
    eventId: 'workbench-drifted-start', recordedAt: integrationTime,
  }, { epoch: integrationEpoch, shards: integrationShards, target: preparedDesktopTarget }),
  (error) => error instanceof SecurityProgramError && error.code === 'E_SECURITY_TARGET_FINGERPRINT_MISMATCH');
  fs.writeFileSync(driftProbePath, driftProbeBytes);
  fs.chmodSync(driftProbePath, driftProbeMode);
  journalEvent = appendSourceVerifiedStartEvent(journalPath, journalEvent, {
    eventId: 'workbench-s02-1', recordedAt: integrationTime,
  }, { epoch: integrationEpoch, shards: integrationShards, target: preparedDesktopTarget });
  for (const [state, eventId, eventScanId] of [
    ['RUNNING', 'workbench-s02-2', scanId],
    ['COMPLETION_REQUESTED', 'workbench-s02-3', scanId],
    ['SEALED', 'workbench-s02-4', scanId],
    ['SOURCE_VERIFIED', 'workbench-s02-5', scanId],
    ['PUBLICATION_PENDING', 'workbench-s02-6', scanId],
  ]) {
    journalEvent = appendAttemptEvent(journalPath, nextAttemptEvent(journalEvent, state, {
      eventId, recordedAt: integrationTime, scanId: eventScanId,
    }));
  }

  for (const [name, source] of [
    ['coverage.json', sealedCoveragePath],
    ['findings.json', sealedFindingsPath],
    ['scan-manifest.json', sealedManifestPath],
  ]) fs.copyFileSync(source, path.join(bundleSource, name), fs.constants.COPYFILE_EXCL);
  for (const name of ['coverage.json', 'findings.json', 'scan-manifest.json']) {
    assert.deepEqual(fs.readFileSync(path.join(bundleSource, name)), fs.readFileSync(path.join(scanDir, name)));
  }
  const publishedBundle = publishImmutableBundle({
    sourceDirectory: bundleSource, attemptsDirectory, attemptId, now: new Date(integrationTime),
  });
  for (const [state, eventId] of [['PUBLISHED', 'workbench-s02-7'], ['ADMITTED', 'workbench-s02-8']]) {
    journalEvent = appendAttemptEvent(journalPath, nextAttemptEvent(journalEvent, state, {
      eventId, recordedAt: integrationTime, scanId,
    }));
  }
  const journalEvents = loadAttemptJournal(journalPath);
  assert.equal(journalEvents.length, 9);
  assert.equal(journalEvents.at(-1).state, 'ADMITTED');
  assert.deepEqual(journalEvents.map((event) => event.sequence), [0, 1, 2, 3, 4, 5, 6, 7, 8]);
  assert.equal(fs.statSync(journalPath).mode & 0o777, 0o600);

  const bundleReceipt = verifyImmutableBundle({ attemptsDirectory, attemptId });
  assert.equal(bundleReceipt.bundleHash, publishedBundle.bundleHash);
  assert.equal(bundleReceipt.files.length, 3);
  const resultArtifacts = bundleReceipt.files.map((entry) => ({
    artifactRef: `attempt-file:${attemptId}/${entry.path}`, sha256: entry.sha256, size: entry.size,
  }));
  const routeAuthority = {
    mode: 'Standard', adapterVersion: TARGET_ADAPTER_VERSION,
    targetForm: 'attested-directory-export', targetKind: 'directory_snapshot',
    scannerSchemaVersion: 'scanner-schema/v1',
    standardRoute: STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
    routeContractSha256, pluginVersion: targetAuthority.pluginVersion,
    productionEligible: true,
    directorySnapshotDigest: targetAuthority.directorySnapshotDigest,
    exportTreeSha256: targetAuthority.exportTreeSha256,
    stableSnapshotSha256: targetAuthority.stableSnapshotSha256,
    budgetId: pilotBudget.budgetId, budgetSha256: pilotBudget.budgetSha256, exportCapacity,
  };
  const resultClaim = buildResultClaimRecord({
    claimId: 'claim-workbench-s02-p01', attemptId, sectionId: 'S02', shardId: pilotShard.id,
    scanId, claimedAt: integrationTime, scannerState: 'SEALED',
    bundleRef: publishedBundle.artifactRef, bundleHash: publishedBundle.bundleHash,
    artifacts: resultArtifacts, reviewedPathCount: 219, missingPathCount: 0,
    claimedFileCoverage: 'complete', claimedProofCompleteness: 'complete',
    sourceRevision: integrationEpoch.revision, sourceFingerprint, controlGenerationHash,
    elapsedSeconds: 1, artifactBytes: resultArtifacts.reduce((sum, item) => sum + item.size, 0),
    operatorSeconds: 0, peakRssBytes: process.memoryUsage().rss,
    freeBytesAfter: availableBytes, retryCount: 0, workerCount: 1,
    tokenUsage: { availability: 'unavailable' }, claimedObservationCount: 0,
    ...routeAuthority,
  });
  const sourceFingerprintAtAdmission = await computeLiveSourceFingerprint(sourceCheckoutRoot);
  assert.equal(sourceFingerprintAtAdmission, sourceFingerprint,
    'admission must bind a live recomputation of the detached frozen source');
  const admission = {
    schema: ADMISSION_INPUT_SCHEMA, recordRole: RECORD_ROLES.VERIFIED_EVIDENCE,
    admissionId: 'admission-workbench-s02-p01', admittedAt: integrationTime,
    attemptId, sectionId: 'S02', shardId: pilotShard.id, scanId,
    journalEventId: journalEvent.eventId,
    journalEventHash: sha256Hex(canonicalJson(journalEvent)), journalState: 'ADMITTED',
    bundleRef: publishedBundle.artifactRef, bundleHash: publishedBundle.bundleHash,
    verifiedBundleHash: publishedBundle.bundleHash,
    controlGenerationHash, currentControlGenerationHash: controlGenerationHash,
    inventorySha256: integrationEpoch.inventorySha256,
    shardGenerationId: integrationShards.generationId,
    shardPathCount: 219, shardPathListSha256: pilotShard.pathListSha256,
    targetArtifactSha256: targetAuthority.artifactSha256,
    targetPathCount: 219, targetPathListSha256: targetAuthority.pathListSha256,
    sourceRevision: integrationEpoch.revision, currentSourceRevision: integrationEpoch.revision,
    sourceFingerprint, currentSourceFingerprint: sourceFingerprintAtAdmission,
    ...routeAuthority,
  };
  const capabilityArguments = {
    admission, resultClaim, budget: pilotBudget, epoch: integrationEpoch,
    shards: integrationShards, target: preparedDesktopTarget, journalPath,
  };
  fs.chmodSync(driftProbePath, 0o600);
  fs.appendFileSync(driftProbePath, '\npost-preparation-admission-drift\n');
  assert.throws(() => issueVerifiedAdmissionCapability({
    ...capabilityArguments, attemptsDirectory,
  }), (error) => error instanceof SecurityProgramError
    && error.code === 'E_SECURITY_TARGET_FINGERPRINT_MISMATCH');
  fs.writeFileSync(driftProbePath, driftProbeBytes);
  fs.chmodSync(driftProbePath, driftProbeMode);
  const initialCapability = issueVerifiedAdmissionCapability({
    ...capabilityArguments, attemptsDirectory,
  });

  const publishedCoveragePath = path.join(attemptsDirectory, attemptId, 'canonical', 'coverage.json');
  const publishedCoverageBytes = fs.readFileSync(publishedCoveragePath);
  const publishedCoverageMode = fs.statSync(publishedCoveragePath).mode & 0o777;
  fs.chmodSync(publishedCoveragePath, 0o600);
  fs.appendFileSync(publishedCoveragePath, '\npost-capability-tamper');
  assert.throws(
    () => buildPilotVerdictRecord({ evaluatedAt: integrationTime }, {
      admissionCapability: initialCapability,
    }),
    (error) => error instanceof SecurityProgramError
      && error.code === 'E_SECURITY_PROGRAM_EVIDENCE_INVALID',
  );
  fs.writeFileSync(publishedCoveragePath, publishedCoverageBytes);
  fs.chmodSync(publishedCoveragePath, publishedCoverageMode);
  assert.equal(verifyImmutableBundle({ attemptsDirectory, attemptId }).bundleHash,
    publishedBundle.bundleHash);
  const republishedBundle = publishImmutableBundle({
    sourceDirectory: bundleSource, attemptsDirectory: replayAttemptsDirectory,
    attemptId, now: new Date(integrationTime),
  });
  assert.equal(republishedBundle.bundleHash, publishedBundle.bundleHash);
  const admissionCapability = issueVerifiedAdmissionCapability({
    ...capabilityArguments, attemptsDirectory: replayAttemptsDirectory,
  });
  const pilotVerdict = buildPilotVerdictRecord(
    { evaluatedAt: integrationTime }, { admissionCapability },
  );
  assert.equal(pilotVerdict.verdict, 'GO_STANDARD');
  assert.equal(pilotVerdict.measurements.creditedPathCount, 219);

  const reviewedSet = buildReviewedSetRecord({
    evidenceId: 'reviewed-workbench-s02-p01', attemptId, sectionId: 'S02',
    shardId: pilotShard.id, scanId, verifiedAt: integrationTime,
    bundleRef: publishedBundle.artifactRef, bundleHash: publishedBundle.bundleHash,
    sourceRevision: integrationEpoch.revision, inventorySha256: integrationEpoch.inventorySha256,
    sourceFingerprint, controlGenerationHash, sealed: true, hashesValid: true,
    sourceFingerprintMatches: true, reviewedPathsPresent: true,
    reviewedPaths: [...reviewedFiles],
  });
  const reconciliation = buildReconciliationRecord({
    generationId: 'workbench-s02-reconciliation', generatedAt: integrationTime,
    epoch: integrationEpoch, sections: integrationSections, shards: integrationShards,
    resultClaims: [resultClaim], reviewedSets: [reviewedSet],
    admissionCapabilities: [admissionCapability],
  });
  assert.equal(reconciliation.uniqueReviewedCount, 219);
  assert.deepEqual(reconciliation.reviewedPaths, reviewedFiles);
  assert.deepEqual(reconciliation.missingPaths, []);
  assert.equal(reconciliation.claimed.state, 'COMPLETE');
  assert.equal(reconciliation.verified.fileCoverage, 'complete');
  assert.equal(reconciliation.verified.gateVerdict, 'PASS');

  const generationId = 'workbench-s02-verified-v1';
  const replayGenerationId = 'workbench-s02-verified-v1-recovered';
  const durableAuthorityState = {
    schema: 'setjoin.security-program.workbench-fresh-state/v1',
    integrationTime,
    epoch: integrationEpoch,
    sections: integrationSections,
    shards: integrationShards,
    budget: pilotBudget,
    attemptBinding,
    admission,
    resultClaim,
    reviewedSet,
    expectedTargetAuthority: targetAuthority,
    expectedPilotVerdict: pilotVerdict,
    expectedReconciliation: reconciliation,
  };
  const durableAuthorityBytes = Buffer.from(canonicalJson(durableAuthorityState));
  fs.writeFileSync(handoffStatePath, durableAuthorityBytes, { mode: 0o600, flag: 'wx' });
  assert.equal(fs.statSync(handoffStatePath).mode & 0o777, 0o600);
  const handoffBrief = {
    schema: 'setjoin.security-program.workbench-fresh-brief/v1',
    codeRoot: repositoryRoot,
    repoRoot: sourceCheckoutRoot,
    pluginRoot,
    pythonLauncher,
    gitLauncher,
    authorityStatePath: handoffStatePath,
    authorityStateSha256: sha256Hex(durableAuthorityBytes),
    attestationFile: preparedDesktopTarget.attestationFile,
    journalPath,
    attemptsDirectory: replayAttemptsDirectory,
    generationsDirectory,
    pointerPath,
    generationId,
    replayGenerationId,
    attemptId,
    scanId,
    targetArtifactSha256: targetAuthority.artifactSha256,
    bundleHash: publishedBundle.bundleHash,
  };
  const handoffBriefBytes = Buffer.from(canonicalJson(handoffBrief));
  fs.writeFileSync(handoffBriefPath, handoffBriefBytes, { mode: 0o600, flag: 'wx' });
  const handoffMetadata = fs.lstatSync(handoffBriefPath);
  assert.equal(handoffMetadata.isFile() && !handoffMetadata.isSymbolicLink(), true);
  assert.equal(handoffMetadata.nlink, 1);
  assert.equal(handoffMetadata.uid, process.getuid());
  assert.equal(handoffMetadata.mode & 0o777, 0o600);
  assert.deepEqual(Object.keys(handoffBrief).sort(), [
    'attemptId', 'attemptsDirectory', 'attestationFile', 'authorityStatePath',
    'authorityStateSha256', 'bundleHash', 'codeRoot', 'generationId', 'generationsDirectory',
    'gitLauncher', 'journalPath', 'pluginRoot', 'pointerPath', 'pythonLauncher',
    'replayGenerationId', 'repoRoot', 'scanId', 'schema', 'targetArtifactSha256',
  ]);

  const freshProcessProgram = String.raw`
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const mode = process.argv[1];
const briefPath = process.argv[2];
assert(['publish', 'replay', 'recover'].includes(mode));
for (const name of ['SETJOIN_WORKBENCH_CREDENTIAL_SENTINEL', 'AWS_SECRET_ACCESS_KEY']) {
  assert.equal(Object.hasOwn(process.env, name), false, name + ' leaked into fresh process');
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function readPrivateJson(filename, expectedSha256) {
  const metadata = fs.lstatSync(filename);
  assert.equal(metadata.isFile() && !metadata.isSymbolicLink(), true);
  assert.equal(metadata.nlink, 1);
  assert.equal(metadata.uid, process.getuid());
  assert.equal(metadata.mode & 0o777, 0o600);
  const bytes = fs.readFileSync(filename);
  if (expectedSha256 !== undefined) assert.equal(sha256(bytes), expectedSha256);
  return JSON.parse(bytes.toString('utf8'));
}

const brief = readPrivateJson(briefPath);
assert.equal(brief.schema, 'setjoin.security-program.workbench-fresh-brief/v1');
const state = readPrivateJson(brief.authorityStatePath, brief.authorityStateSha256);
assert.equal(state.schema, 'setjoin.security-program.workbench-fresh-state/v1');
const moduleUrl = (relative) => pathToFileURL(path.join(brief.codeRoot, ...relative.split('/'))).href;
const [records, targets, publication, json, attempts, source] = await Promise.all([
  import(moduleUrl('scripts/lib/security-program-records.mjs')),
  import(moduleUrl('scripts/lib/security-program-targets.mjs')),
  import(moduleUrl('scripts/lib/security-program-publication.mjs')),
  import(moduleUrl('scripts/lib/security-program-json.mjs')),
  import(moduleUrl('scripts/lib/security-program-attempts.mjs')),
  import(moduleUrl('scripts/lib/source-fingerprint.mjs')),
]);

const shard = state.shards.shards.find((candidate) => candidate.id === state.resultClaim.shardId);
assert(shard);
const backendEnvironment = {
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
  HOME: process.env.HOME,
  XDG_CONFIG_HOME: process.env.XDG_CONFIG_HOME,
  XDG_CACHE_HOME: process.env.XDG_CACHE_HOME,
  XDG_STATE_HOME: process.env.XDG_STATE_HOME,
  TMPDIR: process.env.TMPDIR,
  LC_ALL: 'C',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_TERMINAL_PROMPT: '0',
  GIT_OPTIONAL_LOCKS: '0',
};
const targetGitOperations = new Set([
  ['rev-parse', '--is-inside-work-tree'],
  ['rev-parse', '--show-toplevel'],
  ['rev-parse', '--verify', 'HEAD^{commit}'],
  ['symbolic-ref', '-q', 'HEAD'],
  ['status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=matching', '--ignore-submodules=none'],
  ['ls-tree', '-r', '-z', '--full-tree', state.epoch.revision],
].map((args) => JSON.stringify(args)));
const gitRunner = async ({ repoRoot, args }) => {
  assert.equal(repoRoot, brief.repoRoot);
  assert.equal(targetGitOperations.has(JSON.stringify(args)), true,
    'unexpected durable Git verification argv: ' + JSON.stringify(args));
  const result = childProcess.spawnSync(brief.gitLauncher, [
    '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
    '-C', repoRoot, ...args,
  ], { encoding: null, env: backendEnvironment, maxBuffer: 64 * 1024 * 1024 });
  const expectedStatus = args[0] === 'symbolic-ref' ? 1 : 0;
  assert.equal(result.status, expectedStatus,
    'sandboxed durable Git verification failed: ' + (result.stderr ?? Buffer.alloc(0)).toString('utf8'));
  return {
    status: result.status ?? 127,
    stdout: result.stdout ?? Buffer.alloc(0),
    stderr: result.stderr ?? Buffer.alloc(0),
  };
};
let backendProcessStarts = 0;
const backend = targets.createMacOsReadOnlyDiskImageBackend({
  runner: ({ command, args, input }) => {
    const result = childProcess.spawnSync(command, args, {
      input, encoding: null, maxBuffer: 16 * 1024 * 1024, env: backendEnvironment,
    });
    backendProcessStarts += 1;
    return {
      status: result.status ?? 127,
      stdout: result.stdout ?? Buffer.alloc(0),
      stderr: result.stderr ?? Buffer.alloc(0),
    };
  },
});
const allowedGitCommandsFor = (targetPath) => {
  const prefix = ['git', '-c', 'core.fsmonitor=false', '-c', 'i18n.logOutputEncoding=UTF-8', '-C', targetPath];
  return [
    [...prefix, 'rev-parse', '--git-dir'],
    [...prefix, 'rev-parse', '--is-inside-work-tree'],
    [...prefix, 'rev-parse', '--verify', 'HEAD'],
    [...prefix, 'rev-parse', 'HEAD'],
    [...prefix, 'rev-parse', '--show-toplevel'],
  ];
};
const pluginDigestRunner = ({ pluginRoot, targetPath }) => {
  assert.equal(pluginRoot, brief.pluginRoot);
  const result = childProcess.spawnSync(brief.pythonLauncher, ['-c', [
    'from pathlib import Path', 'import sys',
    'sys.path.insert(0, str(Path(sys.argv[1]) / "scripts"))',
    'from workbench_target import directory_content_digest',
    'print(directory_content_digest(Path(sys.argv[2]).resolve()))',
  ].join('\n'), pluginRoot, targetPath], {
    cwd: process.env.TMPDIR,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    env: {
      ...process.env,
      SETJOIN_WORKBENCH_ALLOWED_GIT_JSON: JSON.stringify(allowedGitCommandsFor(targetPath)),
    },
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return { digest: result.stdout.trim() };
};
const computeLiveSourceFingerprint = async (repoRoot) => {
  const previousPath = process.env.PATH;
  process.env.PATH = path.dirname(brief.gitLauncher);
  try {
    return await source.computeSourceFingerprint(repoRoot);
  } finally {
    process.env.PATH = previousPath;
  }
};
const preparedTarget = await targets.rehydrateDesktopAttestedExportTarget({
  repoRoot: brief.repoRoot,
  attestationFile: brief.attestationFile,
  shardGeneration: state.shards,
  shardId: shard.id,
  pluginRoot: brief.pluginRoot,
  pluginDigestRunner,
  readOnlyBackend: backend,
  attemptBinding: state.attemptBinding,
  gitRunner,
  sourceFingerprintVerifier: async ({ repoRoot }) => {
    assert.equal(repoRoot, brief.repoRoot);
    return { sourceFingerprint: await computeLiveSourceFingerprint(repoRoot) };
  },
  sourceFingerprintRevalidator: ({ repoRoot }) => {
    assert.equal(repoRoot, brief.repoRoot);
    return {
      sourceFingerprint: source.computeSourceFingerprintSync(repoRoot, {
        gitBinary: brief.gitLauncher,
        env: backendEnvironment,
      }),
    };
  },
});
const targetAuthority = targets.verifyPreparedTarget(preparedTarget);
assert.equal(json.canonicalJson(targetAuthority), json.canonicalJson(state.expectedTargetAuthority));
assert.equal(targetAuthority.artifactSha256, brief.targetArtifactSha256);
const journal = attempts.loadAttemptJournal(brief.journalPath);
assert.equal(journal.length, 9);
assert.equal(journal.at(-1).state, 'ADMITTED');
assert.equal(journal.at(-1).scanId, brief.scanId);
const bundle = publication.verifyImmutableBundle({
  attemptsDirectory: brief.attemptsDirectory,
  attemptId: brief.attemptId,
});
assert.equal(bundle.bundleHash, brief.bundleHash);
const sourceFingerprintAtAdmission = await computeLiveSourceFingerprint(brief.repoRoot);
assert.equal(sourceFingerprintAtAdmission, state.admission.currentSourceFingerprint,
  'fresh admission must recompute the detached source fingerprint live');
const admissionCapability = records.issueVerifiedAdmissionCapability({
  admission: state.admission,
  resultClaim: state.resultClaim,
  budget: state.budget,
  epoch: state.epoch,
  shards: state.shards,
  target: preparedTarget,
  journalPath: brief.journalPath,
  attemptsDirectory: brief.attemptsDirectory,
});
const pilotVerdict = records.buildPilotVerdictRecord(
  { evaluatedAt: state.integrationTime }, { admissionCapability },
);
const reconciliation = records.buildReconciliationRecord({
  generationId: state.expectedReconciliation.generationId,
  generatedAt: state.integrationTime,
  epoch: state.epoch,
  sections: state.sections,
  shards: state.shards,
  resultClaims: [state.resultClaim],
  reviewedSets: [state.reviewedSet],
  admissionCapabilities: [admissionCapability],
});
assert.equal(json.canonicalJson(pilotVerdict), json.canonicalJson(state.expectedPilotVerdict));
assert.equal(json.canonicalJson(reconciliation), json.canonicalJson(state.expectedReconciliation));
assert.equal(pilotVerdict.verdict, 'GO_STANDARD');
assert.equal(reconciliation.verified.gateVerdict, 'PASS');
assert.equal(reconciliation.uniqueReviewedCount, 219);
const generationFiles = {
  'admission.json': state.admission,
  'pilot-verdict.json': pilotVerdict,
  'reconciliation.json': reconciliation,
  'result-claim.json': state.resultClaim,
  'reviewed-set.json': state.reviewedSet,
};
let latest;
let pointerAdvanced;
let crashReplaySurvivor = false;
let identicalReplay = false;
let recoveryCompleted = false;
let retainedGenerationId = null;
let retainedGenerationHash = null;
let retainedReceiptSha256 = null;
if (mode === 'publish') {
  latest = publication.publishVerifiedGeneration({
    generationsDirectory: brief.generationsDirectory,
    pointerPath: brief.pointerPath,
    generationId: brief.generationId,
    files: generationFiles,
    expectedPrevious: null,
    now: new Date(state.integrationTime),
  });
  pointerAdvanced = true;
} else if (mode === 'replay') {
  const pointerBefore = fs.readFileSync(brief.pointerPath);
  const current = publication.readVerifiedLatest({
    generationsDirectory: brief.generationsDirectory,
    pointerPath: brief.pointerPath,
  });
  assert.equal(current.generationId, brief.generationId);
  const replayed = publication.publishVerifiedGeneration({
    generationsDirectory: brief.generationsDirectory,
    pointerPath: brief.pointerPath,
    generationId: brief.generationId,
    files: generationFiles,
    expectedPrevious: null,
    now: new Date(state.integrationTime),
  });
  assert.deepEqual(replayed, current,
    'identical generation replay must return the first verified result');
  identicalReplay = true;
  assert.deepEqual(fs.readFileSync(brief.pointerPath), pointerBefore);
  assert.throws(() => publication.publishVerifiedGeneration({
    generationsDirectory: brief.generationsDirectory,
    pointerPath: brief.pointerPath,
    generationId: brief.replayGenerationId,
    files: generationFiles,
    expectedPrevious: {
      generationId: current.generationId,
      generationHash: current.generationHash,
    },
    now: new Date(Date.parse(state.integrationTime) + 1_000),
    faultInjector: (point) => {
      if (point === 'before-pointer-rename') throw new Error('injected:fresh-process-before-pointer-rename');
    },
  }), /injected:fresh-process-before-pointer-rename/);
  assert.deepEqual(fs.readFileSync(brief.pointerPath), pointerBefore);
  latest = publication.readVerifiedLatest({
    generationsDirectory: brief.generationsDirectory,
    pointerPath: brief.pointerPath,
  });
  assert.equal(latest.generationId, brief.generationId);
  const retainedReceiptPath = path.join(
    brief.generationsDirectory, brief.replayGenerationId, 'generation-receipt.json',
  );
  const retainedReceiptBytes = fs.readFileSync(retainedReceiptPath);
  const retainedReceipt = JSON.parse(retainedReceiptBytes.toString('utf8'));
  assert.equal(retainedReceipt.generationId, brief.replayGenerationId);
  assert.equal(retainedReceipt.predecessorGenerationId, current.generationId);
  assert.equal(retainedReceipt.predecessorGenerationHash, current.generationHash);
  const preparedPointerPath = brief.pointerPath + '.tmp-' + brief.replayGenerationId;
  assert.equal(fs.statSync(retainedReceiptPath).mode & 0o777, 0o400);
  assert.equal(fs.statSync(preparedPointerPath).mode & 0o777, 0o400);
  retainedGenerationId = retainedReceipt.generationId;
  retainedGenerationHash = retainedReceipt.generationHash;
  retainedReceiptSha256 = sha256(retainedReceiptBytes);
  crashReplaySurvivor = true;
  pointerAdvanced = false;
} else {
  const pointerBefore = fs.readFileSync(brief.pointerPath);
  const predecessor = publication.readVerifiedLatest({
    generationsDirectory: brief.generationsDirectory,
    pointerPath: brief.pointerPath,
  });
  assert.equal(predecessor.generationId, brief.generationId);
  const retainedReceiptPath = path.join(
    brief.generationsDirectory, brief.replayGenerationId, 'generation-receipt.json',
  );
  const retainedReceiptBytes = fs.readFileSync(retainedReceiptPath);
  const retainedReceipt = JSON.parse(retainedReceiptBytes.toString('utf8'));
  const expectedPrevious = {
    generationId: predecessor.generationId,
    generationHash: predecessor.generationHash,
  };
  assert.equal(retainedReceipt.predecessorGenerationId, expectedPrevious.generationId);
  assert.equal(retainedReceipt.predecessorGenerationHash, expectedPrevious.generationHash);
  latest = publication.publishVerifiedGeneration({
    generationsDirectory: brief.generationsDirectory,
    pointerPath: brief.pointerPath,
    generationId: brief.replayGenerationId,
    files: generationFiles,
    expectedPrevious,
    now: new Date(Date.parse(state.integrationTime) + 60_000),
  });
  assert.equal(latest.generationId, brief.replayGenerationId);
  assert.equal(latest.generationHash, retainedReceipt.generationHash);
  assert.deepEqual(fs.readFileSync(retainedReceiptPath), retainedReceiptBytes,
    'recovery must publish the exact sealed receipt retained by the crash');
  const pointerAfterRecovery = fs.readFileSync(brief.pointerPath);
  assert.notDeepEqual(pointerAfterRecovery, pointerBefore);
  const replayedRecovery = publication.publishVerifiedGeneration({
    generationsDirectory: brief.generationsDirectory,
    pointerPath: brief.pointerPath,
    generationId: brief.replayGenerationId,
    files: generationFiles,
    expectedPrevious,
    now: new Date(Date.parse(state.integrationTime) + 120_000),
  });
  assert.deepEqual(replayedRecovery, latest,
    'completed retained-generation replay must return the same verified result');
  assert.deepEqual(fs.readFileSync(brief.pointerPath), pointerAfterRecovery,
    'completed replay must not advance the pointer a second time');
  identicalReplay = true;
  recoveryCompleted = true;
  pointerAdvanced = true;
  retainedGenerationId = retainedReceipt.generationId;
  retainedGenerationHash = retainedReceipt.generationHash;
  retainedReceiptSha256 = sha256(retainedReceiptBytes);
}
console.log(JSON.stringify({
  mode,
  attemptId: brief.attemptId,
  scanId: brief.scanId,
  targetArtifactSha256: targetAuthority.artifactSha256,
  bundleHash: bundle.bundleHash,
  generationId: latest.generationId,
  generationHash: latest.generationHash,
  pilotVerdictSha256: json.sha256Hex(json.canonicalJson(pilotVerdict)),
  reconciliationSha256: json.sha256Hex(json.canonicalJson(reconciliation)),
  pointerAdvanced,
  crashReplaySurvivor,
  identicalReplay,
  recoveryCompleted,
  retainedGenerationId,
  retainedGenerationHash,
  retainedReceiptSha256,
  backendProcessStarts,
}));
`;
  const freshProcessEnvironment = {
    ...baseChildEnvironment,
    OPENSSL_CONF: '/dev/null',
    TMPDIR: freshPublicationRoot,
    PYTHONPATH: guardRoot,
    SETJOIN_WORKBENCH_GUARD_AUDIT: guardAuditPath,
    SETJOIN_WORKBENCH_ALLOWED_GIT_JSON: JSON.stringify(allowedGitCommandsFor(exportRoot)),
  };
  const runFreshProcess = (mode) => {
    const result = childProcess.spawnSync(sandboxLauncher, [
      '-f', freshProcessSandboxProfilePath,
      nodeLauncher, '--input-type=module', '--eval', freshProcessProgram,
      '--', mode, handoffBriefPath,
    ], {
      cwd: fixtureRoot,
      encoding: 'utf8',
      env: freshProcessEnvironment,
      maxBuffer: 32 * 1024 * 1024,
    });
    assert.equal(result.status, 0,
      `fresh ${mode} process failed (signal=${result.signal}):\n${result.error?.stack ?? ''}\n${result.stderr || result.stdout}`);
    return JSON.parse(result.stdout.trim());
  };
  const freshPublished = runFreshProcess('publish');
  const pointerAfterPublish = fs.readFileSync(pointerPath);
  const freshReplayed = runFreshProcess('replay');
  const pointerAfterCrash = fs.readFileSync(pointerPath);
  const freshRecovered = runFreshProcess('recover');
  const pointerAfterRecovery = fs.readFileSync(pointerPath);
  assert.equal(freshPublished.pointerAdvanced, true);
  assert.equal(freshPublished.crashReplaySurvivor, false);
  assert.equal(freshPublished.identicalReplay, false);
  assert.equal(freshReplayed.pointerAdvanced, false);
  assert.equal(freshReplayed.crashReplaySurvivor, true);
  assert.equal(freshReplayed.identicalReplay, true);
  assert.equal(freshReplayed.recoveryCompleted, false);
  assert.equal(freshRecovered.pointerAdvanced, true);
  assert.equal(freshRecovered.crashReplaySurvivor, false);
  assert.equal(freshRecovered.identicalReplay, true);
  assert.equal(freshRecovered.recoveryCompleted, true);
  for (const key of [
    'attemptId', 'scanId', 'targetArtifactSha256', 'bundleHash', 'generationId',
    'generationHash', 'pilotVerdictSha256', 'reconciliationSha256',
  ]) assert.equal(freshReplayed[key], freshPublished[key], `fresh replay changed ${key}`);
  assert.deepEqual(pointerAfterCrash, pointerAfterPublish,
    'fresh replay/crash boundary must not advance the verified latest pointer');
  for (const key of [
    'attemptId', 'scanId', 'targetArtifactSha256', 'bundleHash',
    'pilotVerdictSha256', 'reconciliationSha256',
  ]) assert.equal(freshRecovered[key], freshPublished[key], `fresh recovery changed ${key}`);
  assert.equal(freshRecovered.generationId, freshReplayed.retainedGenerationId);
  assert.equal(freshRecovered.generationHash, freshReplayed.retainedGenerationHash);
  assert.equal(freshRecovered.retainedReceiptSha256, freshReplayed.retainedReceiptSha256);
  assert.notDeepEqual(pointerAfterRecovery, pointerAfterPublish,
    'fresh recovery must advance the pointer to the retained generation exactly once');
  const recoveredPointer = JSON.parse(pointerAfterRecovery.toString('utf8'));
  assert.equal(recoveredPointer.generationId, freshRecovered.generationId);
  assert.equal(recoveredPointer.generationHash, freshRecovered.generationHash);
  assert.equal(recoveredPointer.predecessorGenerationId, freshPublished.generationId);
  assert.equal(recoveredPointer.predecessorGenerationHash, freshPublished.generationHash);
  assert.equal(freshPublished.generationId, generationId);
  assert.equal(freshPublished.scanId, scanId);
  assert.equal(freshPublished.targetArtifactSha256, targetAuthority.artifactSha256);
  assert.equal(freshPublished.bundleHash, publishedBundle.bundleHash);
  assert.equal(await computeLiveSourceFingerprint(sourceCheckoutRoot), sourceFingerprint,
    'detached source fingerprint must remain stable after the full lifecycle and replay');

  const listed = JSON.parse(runPython([
    workbenchPath,
    'list-scans',
    '--scan-root', scanRoot,
    '--limit', '10',
  ], 'workbench scan inventory'));
  assert.equal(listed.scans.length, 1, 'disposable workbench must contain exactly one scan');
  assert.equal(listed.scans[0].scanId, scanId);
  assert.equal(listed.scans[0].progress.status, 'complete');

  const audit = fs.readFileSync(guardAuditPath, 'utf8').trim().split('\n');
  networkStarts = audit.filter((entry) => entry === 'network-denied').length;
  scannerStarts = audit.filter((entry) => entry === 'scanner-or-process-denied').length;
  const allowedGitAuditEntries = audit.filter((entry) => entry.startsWith('local-git-allowed:'));
  const guardedProcessCount = audit.filter((entry) => entry === 'guard-active').length;
  assert.ok(guardedProcessCount >= 9,
    'all nine top-level Python helpers must load the offline guard');
  assert.equal(audit.filter((entry) => entry === 'credentials-absent').length, guardedProcessCount,
    'every guarded helper process must prove parent credential sentinels are inaccessible');
  assert.equal(audit.filter((entry) => entry === 'credential-leak').length, 0);
  const observedGitSuffixes = new Set(allowedGitAuditEntries
    .map((entry) => JSON.stringify(JSON.parse(entry.slice('local-git-allowed:'.length)))));
  assert.deepEqual(observedGitSuffixes, new Set([
    JSON.stringify(['rev-parse', '--git-dir']),
    JSON.stringify(['rev-parse', '--is-inside-work-tree']),
    JSON.stringify(['--verify', 'HEAD']),
    JSON.stringify(['rev-parse', 'HEAD']),
    JSON.stringify(['rev-parse', '--show-toplevel']),
  ]), 'Python may invoke only the exact observed read-only Git probes');
  assert.equal(networkStarts, 0, 'workbench fixture must not attempt network access');
  assert.equal(scannerStarts, 0, 'workbench fixture must not attempt a scanner or non-local helper');
  assert.equal(workbenchStarts, 4, 'fixture must run start, draft, complete, and one read-only inventory command');

  console.log(`security-program-workbench test: PASS (paths=219 credited=219 verdict=${pilotVerdict.verdict} reconciliation=${reconciliation.verified.gateVerdict} source=live-detached-stable mutation=rejected unicode=raw-byte-deterministic invalid-utf8=${invalidUtf8Disposition} fresh-process=publish+idempotent-replay+crash-recovery generation=${freshRecovered.generationId} pointer=single-recovery-advance receipt=retained-identical scanIds=1 scanner=${scannerStarts} network=${networkStarts} workbench=${workbenchStarts} backend=${backendProcessStarts + freshPublished.backendProcessStarts + freshReplayed.backendProcessStarts + freshRecovered.backendProcessStarts} seatbelt=deny-default)`);
} finally {
  if (macReadOnlyBackend && (preparedDesktopTarget?.targetPath ?? activeMountPath)) {
    macReadOnlyBackend.detach({
      targetPath: preparedDesktopTarget?.targetPath ?? activeMountPath,
    });
  }
  for (const filename of new Set(rawByteFixturePaths)) {
    if (!fs.existsSync(filename)) continue;
    fs.chmodSync(filename, 0o600);
    fs.unlinkSync(filename);
  }
  for (const directory of [...new Set(rawByteFixtureRoots)].reverse()) {
    if (!fs.existsSync(directory)) continue;
    fs.chmodSync(directory, 0o700);
    fs.rmdirSync(directory);
  }
  restoreFixturePermissions(fixtureRoot);
  fs.rmSync(fixtureRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  for (const [name, value] of Object.entries(savedSentinels)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
}
