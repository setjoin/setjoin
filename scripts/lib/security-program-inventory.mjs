import childProcess from 'node:child_process';
import crypto from 'node:crypto';
import path from 'node:path';
import { TextDecoder } from 'node:util';

export const INVENTORY_SCHEMA = 'setjoin.security-program.epoch/v1';
export const SECTIONS_SCHEMA = 'setjoin.security-program.sections/v1';
export const SHARDS_SCHEMA = 'setjoin.security-program.shards/v1';
export const EXCLUSION_POLICY_SCHEMA = 'setjoin.security-program.exclusion-policy/v1';
export const INVENTORY_DECISION_SCHEMA = 'setjoin.security-program.inventory-decision/v1';
export const INVENTORY_DECISION_VERSION = 'inventory-denominator/v1';

const utf8 = new TextDecoder('utf-8', { fatal: true });
const supportedModes = new Map([
  ['100644', 'file'],
  ['100755', 'executable'],
  ['120000', 'symlink'],
  ['160000', 'submodule'],
]);
const INVENTORY_HASH_DOMAIN = Buffer.from(
  'setjoin.security-program.inventory/path-object-mode-kind/v2', 'utf8',
);

export class InventoryError extends Error {
  constructor(code, message, details = {}) {
    super(`${code}: ${message}`);
    this.name = 'InventoryError';
    this.code = code;
    this.details = details;
  }
}

function hold(code, message, details = {}) {
  throw new InventoryError(code, message, details);
}

function byteKey(bytes) {
  return bytes.toString('hex');
}

function compareTextBytes(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function updateFrame(hash, bytes) {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  hash.update(length);
  hash.update(bytes);
}

function assertPlainObject(value, code, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    hold(code, `${label} must be an object`);
  }
}

function assertExactKeys(value, allowed, code, label) {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key)).sort(compareTextBytes);
  if (unknown.length > 0) hold(code, `${label} has unknown fields`, { unknownFields: unknown });
}

function assertNormalizedText(value, code, label) {
  if (typeof value !== 'string' || value.normalize('NFC') !== value) {
    hold(code, `${label} must be NFC-normalized text`);
  }
}

export function validateGitPath(pathBytes) {
  if (!Buffer.isBuffer(pathBytes)) hold('C0_PATH_TYPE', 'Git path must be a Buffer');
  if (pathBytes.length === 0) hold('C0_PATH_EMPTY', 'Git path is empty');
  if (pathBytes.includes(0)) hold('C0_PATH_NUL', 'Git path contains NUL');

  let decoded;
  try {
    decoded = utf8.decode(pathBytes);
  } catch {
    hold('C0_PATH_UTF8', 'Git path is not strict UTF-8', { pathHex: byteKey(pathBytes) });
  }
  if (!Buffer.from(decoded, 'utf8').equals(pathBytes)) {
    hold('C0_PATH_UTF8_LOSSY', 'Git path does not round-trip through UTF-8', { pathHex: byteKey(pathBytes) });
  }
  if (JSON.parse(JSON.stringify(decoded)) !== decoded) {
    hold('C0_PATH_JSON_LOSSY', 'Git path does not round-trip through JSON', { pathHex: byteKey(pathBytes) });
  }
  if (decoded.startsWith('/') || decoded.endsWith('/') || decoded.includes('//')) {
    hold('C0_PATH_SEPARATOR', 'Git path has an empty or absolute path segment', { path: decoded });
  }
  if (decoded.includes('\\')) {
    hold('C0_PATH_SEPARATOR', 'Git path contains a platform-ambiguous separator', { path: decoded });
  }
  if (decoded.split('/').some((segment) => segment === '.' || segment === '..')) {
    hold('C0_PATH_SEGMENT', 'Git path contains dot traversal segment', { path: decoded });
  }
  for (const value of pathBytes) {
    if (value < 0x20 || value === 0x7f) {
      hold('C0_PATH_CONTROL', 'Git path contains an unsupported control byte', {
        pathHex: byteKey(pathBytes), byte: value,
      });
    }
  }
  return decoded;
}

function validateTreeEntry(entry) {
  const kind = supportedModes.get(entry.mode);
  if (!kind) hold('C0_MODE_UNSUPPORTED', `unsupported Git mode ${entry.mode}`, { path: entry.path });
  if ((entry.mode === '160000') !== (entry.objectType === 'commit')) {
    hold('C0_MODE_TYPE', 'submodule mode must name a commit and only a submodule may name a commit', {
      path: entry.path, mode: entry.mode, objectType: entry.objectType,
    });
  }
  if (entry.mode !== '160000' && entry.objectType !== 'blob') {
    hold('C0_MODE_TYPE', 'tracked non-submodule entry must name a blob', {
      path: entry.path, mode: entry.mode, objectType: entry.objectType,
    });
  }
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(entry.objectId)) {
    hold('C0_OBJECT_ID', 'object ID must be lowercase SHA-1 or SHA-256 hex', { path: entry.path });
  }
  return { ...entry, kind };
}

function validateInventoryEntry(entry) {
  assertPlainObject(entry, 'C0_ENTRY_SCHEMA', 'inventory entry');
  const decodedPath = validateGitPath(entry.pathBytes);
  if (entry.path !== decodedPath) {
    hold('C0_ENTRY_PATH', 'entry path text does not equal its raw Git path bytes', {
      path: entry.path, pathHex: byteKey(entry.pathBytes),
    });
  }
  const validated = validateTreeEntry(entry);
  if (entry.kind !== undefined && entry.kind !== validated.kind) {
    hold('C0_MODE_TYPE', 'entry kind disagrees with Git mode', {
      path: entry.path, mode: entry.mode, kind: entry.kind,
    });
  }
  return validated;
}

export function parseGitTreeZ(output) {
  if (!Buffer.isBuffer(output)) hold('C0_TREE_TYPE', 'git ls-tree output must be a Buffer');
  if (output.length > 0 && output.at(-1) !== 0) hold('C0_TREE_TRUNCATED', 'NUL-terminated tree output is truncated');
  const entries = [];
  let offset = 0;
  while (offset < output.length) {
    const end = output.indexOf(0, offset);
    if (end < 0) hold('C0_TREE_TRUNCATED', 'NUL-terminated tree output is truncated');
    const record = output.subarray(offset, end);
    offset = end + 1;
    if (record.length === 0) hold('C0_TREE_RECORD', 'empty Git tree record');
    const tab = record.indexOf(0x09);
    if (tab < 0) hold('C0_TREE_RECORD', 'Git tree record has no path separator');
    const header = record.subarray(0, tab).toString('ascii');
    const match = /^(\d{6}) (blob|commit) ([0-9a-f]+)$/.exec(header);
    if (!match) hold('C0_TREE_RECORD', 'Git tree record header is malformed', { header });
    const pathBytes = Buffer.from(record.subarray(tab + 1));
    const decodedPath = validateGitPath(pathBytes);
    entries.push(validateTreeEntry({
      mode: match[1], objectType: match[2], objectId: match[3],
      path: decodedPath, pathBytes,
    }));
  }
  entries.sort((left, right) => Buffer.compare(left.pathBytes, right.pathBytes));
  for (let index = 1; index < entries.length; index += 1) {
    if (entries[index - 1].pathBytes.equals(entries[index].pathBytes)) {
      hold('C0_PATH_DUPLICATE', 'Git tree contains a duplicate byte-identical path', { path: entries[index].path });
    }
  }
  const folded = new Map();
  for (const entry of entries) {
    const fold = entry.path.normalize('NFC').toLowerCase();
    const prior = folded.get(fold);
    if (prior && prior !== entry.path) {
      hold('C0_PATH_CASEFOLD', 'Git paths collide after Unicode normalization and case folding', {
        paths: [prior, entry.path].sort(),
      });
    }
    folded.set(fold, entry.path);
  }
  return entries;
}

function runGit(repoRoot, args, encoding = null) {
  const result = childProcess.spawnSync('git', ['-C', repoRoot, ...args], {
    encoding, maxBuffer: 1024 * 1024 * 256,
  });
  if (result.error) hold('C0_GIT_EXEC', result.error.message);
  if (result.status !== 0) {
    hold('C0_GIT_FAILED', `git ${args[0]} failed`, {
      status: result.status, stderr: Buffer.isBuffer(result.stderr) ? result.stderr.toString('utf8') : result.stderr,
    });
  }
  return result.stdout;
}

export function enumerateGitTree({ repoRoot, revision }) {
  if (typeof repoRoot !== 'string' || repoRoot.length === 0) hold('C0_REPO_ROOT', 'repoRoot is required');
  if (typeof revision !== 'string' || revision.length === 0 || revision.startsWith('-')) {
    hold('C0_REVISION', 'an explicit, non-option revision is required');
  }
  const resolvedRevision = runGit(path.resolve(repoRoot), ['rev-parse', '--verify', `${revision}^{commit}`], 'utf8').trim();
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(resolvedRevision)) {
    hold('C0_REVISION', 'Git did not resolve revision to a full object ID', { resolvedRevision });
  }
  const committedSecondsText = runGit(path.resolve(repoRoot), ['show', '-s', '--format=%ct', resolvedRevision], 'utf8').trim();
  if (!/^[0-9]+$/.test(committedSecondsText)) hold('C0_REVISION_TIME', 'Git commit timestamp is malformed');
  const committedSeconds = Number(committedSecondsText);
  if (!Number.isSafeInteger(committedSeconds) || committedSeconds < 0) hold('C0_REVISION_TIME', 'Git commit timestamp is out of range');
  const committedAt = new Date(committedSeconds * 1000).toISOString();
  const output = runGit(path.resolve(repoRoot), ['ls-tree', '-r', '-z', '--full-tree', resolvedRevision]);
  const entries = parseGitTreeZ(output);
  if (entries.length === 0) hold('C0_INVENTORY_EMPTY', 'revision has no tracked paths', { resolvedRevision });
  return { revision: resolvedRevision, committedAt, entries };
}

function normalizeSelector(selector) {
  assertPlainObject(selector, 'C0_POLICY_SELECTOR', 'exclusion selector');
  assertExactKeys(selector, ['kind', 'value'], 'C0_POLICY_SELECTOR', 'exclusion selector');
  if (!['exact', 'prefix'].includes(selector.kind)) hold('C0_POLICY_SELECTOR', `unknown selector kind ${selector.kind}`);
  if (typeof selector.value !== 'string' || selector.value.length === 0) {
    hold('C0_POLICY_SELECTOR', 'selector value must be a nonempty string');
  }
  assertNormalizedText(selector.value, 'C0_POLICY_SELECTOR', 'selector value');
  if (selector.kind === 'prefix' && !selector.value.endsWith('/')) {
    hold('C0_POLICY_SELECTOR', 'prefix selector must end in /', { value: selector.value });
  }
  if (selector.kind === 'exact' && selector.value.endsWith('/')) {
    hold('C0_POLICY_SELECTOR', 'exact selector must not end in /', { value: selector.value });
  }
  const pathForm = selector.kind === 'prefix' ? selector.value.slice(0, -1) : selector.value;
  validateGitPath(Buffer.from(pathForm, 'utf8'));
  return { kind: selector.kind, value: selector.value };
}

export function normalizeExclusionPolicy(policy) {
  assertPlainObject(policy, 'C0_POLICY_SCHEMA', 'exclusion policy');
  assertExactKeys(policy, ['schema', 'policyVersion', 'classes'], 'C0_POLICY_SCHEMA', 'exclusion policy');
  if (policy.schema !== EXCLUSION_POLICY_SCHEMA) hold('C0_POLICY_SCHEMA', `expected ${EXCLUSION_POLICY_SCHEMA}`);
  if (!/^[a-z0-9][a-z0-9._/-]*\/v[1-9][0-9]*$/.test(policy.policyVersion ?? '')) {
    hold('C0_POLICY_VERSION', 'policyVersion must be a stable namespaced /vN identifier');
  }
  if (!Array.isArray(policy.classes)) hold('C0_POLICY_SCHEMA', 'policy classes must be an array');
  const ids = new Set();
  const selectorKeys = new Set();
  const classes = policy.classes.map((item) => {
    assertPlainObject(item, 'C0_POLICY_CLASS', 'exclusion class');
    assertExactKeys(item, ['id', 'reason', 'expectedCount', 'selectors'], 'C0_POLICY_CLASS', 'exclusion class');
    if (!/^[a-z][a-z0-9-]*$/.test(item.id ?? '') || ids.has(item.id)) {
      hold('C0_POLICY_CLASS', `invalid or duplicate exclusion class ${item.id}`);
    }
    ids.add(item.id);
    if (typeof item.reason !== 'string' || item.reason.length < 1 || item.reason.length > 160 || item.reason.trim() !== item.reason) {
      hold('C0_POLICY_CLASS', `exclusion class ${item.id} needs a reason`);
    }
    assertNormalizedText(item.reason, 'C0_POLICY_REASON', `exclusion class ${item.id} reason`);
    if (/[\r\n\u0000-\u001f\u007f]/u.test(item.reason)) {
      hold('C0_POLICY_REASON', `exclusion class ${item.id} reason must be one privacy-safe line`);
    }
    if (/(?:^|[^A-Za-z0-9._~-])(?:~\/|\/(?:[^/\s]+\/)*[^/\s]+|[A-Za-z]:[\\/][^\s]*)/u.test(item.reason)
      || /(?:DSS_SCAN_BUNDLE_DIR|CODEX_HOME|(?:^|[^A-Z])HOME\s*=)/iu.test(item.reason)) {
      hold('C0_POLICY_REASON', `exclusion class ${item.id} reason contains an absolute home or bundle path`);
    }
    if (/(?:sk-[A-Za-z0-9_-]{12,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:password|passwd|secret|access[_-]?token|api[_-]?key)\s*[=:([{<]{1,4}\s*\S+)/iu.test(item.reason)) {
      hold('C0_POLICY_REASON', `exclusion class ${item.id} reason contains secret-shaped content`);
    }
    if (!Array.isArray(item.selectors) || item.selectors.length === 0) {
      hold('C0_POLICY_CLASS', `exclusion class ${item.id} needs selectors`);
    }
    if (!Number.isSafeInteger(item.expectedCount) || item.expectedCount < 0) {
      hold('C0_POLICY_COUNT', `invalid expectedCount for ${item.id}`);
    }
    const selectors = item.selectors.map(normalizeSelector).sort((a, b) =>
      compareTextBytes(a.kind, b.kind) || compareTextBytes(a.value, b.value));
    for (const selector of selectors) {
      const key = `${selector.kind}\0${selector.value}`;
      if (selectorKeys.has(key)) hold('C0_POLICY_SELECTOR', 'duplicate exclusion selector', { selector });
      selectorKeys.add(key);
    }
    return {
      id: item.id, reason: item.reason, expectedCount: item.expectedCount, selectors,
    };
  }).sort((a, b) => compareTextBytes(a.id, b.id));
  return { schema: policy.schema, policyVersion: policy.policyVersion, classes };
}

function selectorMatches(pathname, selector) {
  return selector.kind === 'exact' ? pathname === selector.value : pathname.startsWith(selector.value);
}

export function applyExclusionPolicy(entries, policyInput) {
  const policy = normalizeExclusionPolicy(policyInput);
  const authorized = [];
  const excluded = [];
  const counts = new Map(policy.classes.map((item) => [item.id, 0]));
  for (const candidate of entries) {
    const entry = validateInventoryEntry(candidate);
    const matches = policy.classes.filter((item) => item.selectors.some((selector) => selectorMatches(entry.path, selector)));
    if (matches.length > 1) {
      hold('C0_POLICY_OVERLAP', 'path matches multiple exclusion classes', {
        path: entry.path, classes: matches.map((item) => item.id),
      });
    }
    if (matches.length === 0) authorized.push(entry);
    else {
      const owner = matches[0];
      counts.set(owner.id, counts.get(owner.id) + 1);
      excluded.push({ ...entry, exclusionClass: owner.id, exclusionReason: owner.reason });
    }
  }
  const countMismatches = policy.classes.flatMap((item) =>
    item.expectedCount === counts.get(item.id) ? [] : [{
      classId: item.id, expected: item.expectedCount, actual: counts.get(item.id),
    }]);
  if (countMismatches.length > 0) hold('C0_POLICY_COUNT', 'exclusion class counts do not match policy', { mismatches: countMismatches });
  return { policy, policyHash: hashJson(policy), authorized, excluded, exclusionCounts: Object.fromEntries(counts) };
}

function startsAny(pathname, prefixes) {
  return prefixes.some((prefix) => pathname.startsWith(prefix));
}

const internalGroups = {
  S05: ['admin'],
  S06: ['jmap', 'user'],
  S07: ['auth', 'middleware', 'smtp', 'imap', 'ldap', 'caldav', 'carddav'],
  S08: ['drive', 'blob', 'storage', 'office', 'preview'],
  S09: ['updater', 'updates', 'appmarket', 'backup', 'restore', 'deploy'],
  S10: ['migration'],
  S11: ['chat', 'meet', 'federation', 'ws', 'notify'],
};

const privilegedMailCommands = ['mailserver/cmd/setjoin-updater/', 'mailserver/cmd/setjoin-recovery/'];
const operationalMailCommands = ['mailserver/cmd/unit-catalog-gen/'];

const reducerGroups = [
  ['S15', /(?:identity|admin|auth|access|role|permission|user|account|session|token|mfa|tenant|organization|directory|device|policy|audit)/i],
  ['S16', /(?:mail|message|mailbox|search|spam|rule|delivery|smtp|thread|draft|tag|label|outbox|inbox)/i],
  ['S17', /(?:calendar|contact|task|booking|room|collab|event)/i],
];

const webmailGroups = [
  ['S19', /(?:^|\/)(?:auth|admin|security|session|settings?|identity)(?:\/|[._-])/i],
  ['S20', /(?:^|\/)(?:mail|calendar|contacts?|tasks?|inbox|compose|search)(?:\/|[._-])/i],
  ['S21', /(?:^|\/)(?:drive|chat|meet|office|guest)(?:\/|[._-])/i],
];

function isFirstPatternMatch(groups, id, pathname) {
  const first = groups.find(([, pattern]) => pattern.test(pathname));
  return first?.[0] === id;
}

function section(id, title, provenance, matches) {
  return Object.freeze({ id, title, provenance, matches });
}

export const PROVISIONAL_SECTION_CATALOG = Object.freeze([
  section('S01', 'Shared threat evaluation, policy, abuse and revocation', 'shared/threat/**', (p) => p.startsWith('shared/threat/')),
  section('S02', 'Shared identity and validation foundations', 'remaining shared/**', (p) => p.startsWith('shared/') && !p.startsWith('shared/threat/')),
  section('S03', 'Authserver handlers and authentication', 'authserver/cmd/** and selected authserver/internal/**', (p) => p.startsWith('authserver/cmd/') || startsAny(p, ['handlers', 'authn', 'token', 'middleware', 'device'].map((d) => `authserver/internal/${d}/`))),
  section('S04', 'Authserver federation, connectors, configuration and SQL authority', 'remaining authserver/**', (p) => p.startsWith('authserver/') && !(p.startsWith('authserver/cmd/') || startsAny(p, ['handlers', 'authn', 'token', 'middleware', 'device'].map((d) => `authserver/internal/${d}/`)))),
  ...Object.entries(internalGroups).map(([id, directories]) => section(id, `Mailserver internal authority ${id}`, `mailserver/internal/{${directories.join(',')}}/**${id === 'S09' ? ' plus updater/recovery commands' : ''}`, (p) => startsAny(p, directories.map((d) => `mailserver/internal/${d}/`)) || (id === 'S09' && startsAny(p, privilegedMailCommands)))),
  section('S12', 'Device, directory, governance and background workers', 'remaining mailserver/internal/**', (p) => p.startsWith('mailserver/internal/') && !Object.values(internalGroups).flat().some((d) => p.startsWith(`mailserver/internal/${d}/`))),
  section('S13', 'Mailserver commands, API contracts and runtime configuration', 'remaining mailserver root, cmd and api paths', (p) => (p.startsWith('mailserver/cmd/') && !startsAny(p, [...privilegedMailCommands, ...operationalMailCommands])) || p.startsWith('mailserver/api/') || (/^mailserver\/[^/]+$/.test(p) && !p.startsWith('mailserver/deploy'))),
  section('S14', 'Database schema, generated SQL and roles', 'mailserver/sql except reducers and matched pgTAP', (p) => p.startsWith('mailserver/sql/') && !p.startsWith('mailserver/sql/reducers/') && !p.startsWith('mailserver/sql/tests/')),
  ...reducerGroups.map(([id, pattern]) => section(id, `Reducer authority ${id}`, `ordered reducer/test filename group ${pattern}`, (p) => (p.startsWith('mailserver/sql/reducers/') || p.startsWith('mailserver/sql/tests/')) && isFirstPatternMatch(reducerGroups, id, p.slice(p.lastIndexOf('/') + 1)))),
  section('S18', 'Remaining reducers and pgTAP', 'remaining mailserver/sql reducers and tests', (p) => (p.startsWith('mailserver/sql/reducers/') || p.startsWith('mailserver/sql/tests/')) && !reducerGroups.some(([, pattern]) => pattern.test(p.slice(p.lastIndexOf('/') + 1)))),
  ...webmailGroups.map(([id, pattern]) => section(id, `Webmail authority ${id}`, `ordered webmail feature group ${pattern}`, (p) => p.startsWith('mailserver/webmail/') && isFirstPatternMatch(webmailGroups, id, p.slice('mailserver/webmail/'.length)))),
  section('S22', 'Remaining webmail and static assets', 'remaining mailserver/webmail/**', (p) => p.startsWith('mailserver/webmail/') && !webmailGroups.some(([, pattern]) => pattern.test(p.slice('mailserver/webmail/'.length)))),
  section('S23', 'Electron desktop shell', 'clients/desktop/**', (p) => p.startsWith('clients/desktop/')),
  section('S24', 'Shared Rust and native security crates', 'remaining clients/** except HarmonyOS', (p) => p.startsWith('clients/') && !p.startsWith('clients/desktop/') && !p.startsWith('clients/harmonyos/')),
  section('S25', 'HarmonyOS client', 'clients/harmonyos/**', (p) => p.startsWith('clients/harmonyos/')),
  section('S26', 'Administration CLI', 'mailctl/**', (p) => p.startsWith('mailctl/')),
  section('S27', 'ASR bot and small tools/apps/examples', 'asrbot/**, tools/**, apps/**, examples/**', (p) => startsAny(p, ['asrbot/', 'tools/', 'apps/', 'examples/'])),
  section('S28', 'Install, deployment, CI and operational automation', 'scripts/**, config/**, .github/**, mailserver/deploy/**, deploysources and operational generators', (p) => startsAny(p, ['scripts/', 'config/', '.github/', 'mailserver/deploy/', 'mailserver/deploysources/', ...operationalMailCommands])),
  section('S29', 'Current documentation and plans', 'docs/** and first-party planning records', (p) => p.startsWith('docs/') || p.startsWith('.superpowers/') || p === 'G1-review-fold-report.md'),
  section('S30', 'Root governance and metadata', 'root and .codex/.claude metadata', (p) => (!p.includes('/') && p !== 'G1-review-fold-report.md') || p.startsWith('.codex/') || p.startsWith('.claude/')),
]);

function validateCatalog(catalog) {
  if (!Array.isArray(catalog) || catalog.length === 0) hold('C0_CATALOG', 'section catalog must be nonempty');
  const ids = new Set();
  for (const item of catalog) {
    if (!/^S(?:0[1-9]|[12][0-9]|30)$/.test(item.id ?? '') || ids.has(item.id) || typeof item.matches !== 'function') {
      hold('C0_CATALOG', `invalid or duplicate section ${item.id}`);
    }
    ids.add(item.id);
  }
  return catalog;
}

export function validateOwnership(entries, ownerSections) {
  entries.forEach(validateInventoryEntry);
  const inventory = new Map(entries.map((entry) => [byteKey(entry.pathBytes), entry]));
  if (inventory.size !== entries.length) hold('C0_INVENTORY_DUPLICATE', 'authorized inventory contains duplicate paths');
  const seen = new Map();
  const extras = [];
  for (const owner of ownerSections) {
    if (!Array.isArray(owner.entries)) hold('C0_OWNER_SCHEMA', `section ${owner.id} entries must be an array`);
    for (const entry of owner.entries) {
      const key = byteKey(entry.pathBytes);
      if (!inventory.has(key)) extras.push(entry.path);
      const prior = seen.get(key) ?? [];
      prior.push(owner.id);
      seen.set(key, prior);
    }
  }
  const orphans = entries.filter((entry) => !seen.has(byteKey(entry.pathBytes))).map((entry) => entry.path).sort(compareTextBytes);
  const duplicates = [...seen.entries()].filter(([, owners]) => owners.length > 1).map(([key, owners]) => ({
    path: inventory.get(key)?.path ?? `<hex:${key}>`, owners,
  })).sort((a, b) => compareTextBytes(a.path, b.path));
  if (orphans.length || duplicates.length || extras.length) {
    hold('C0_OWNERSHIP_HOLD', 'owner sections are not an exact disjoint union of the authorized inventory', {
      orphans, duplicates, extras: extras.sort(),
    });
  }
  return { authorizedCount: entries.length, ownedCount: seen.size };
}

export function classifyOwnership(entries, catalogInput = PROVISIONAL_SECTION_CATALOG) {
  entries.forEach(validateInventoryEntry);
  const catalog = validateCatalog(catalogInput);
  const byId = new Map(catalog.map((item) => [item.id, { ...item, entries: [] }]));
  const orphans = [];
  const duplicates = [];
  for (const entry of entries) {
    const matches = catalog.filter((item) => item.matches(entry.path, entry)).map((item) => item.id);
    if (matches.length === 0) orphans.push(entry.path);
    else if (matches.length > 1) duplicates.push({ path: entry.path, owners: matches });
    else byId.get(matches[0]).entries.push(entry);
  }
  if (orphans.length || duplicates.length) {
    hold('C0_CLASSIFICATION_HOLD', 'provisional selectors do not uniquely own every authorized path', {
      orphans: orphans.sort(compareTextBytes), duplicates: duplicates.sort((a, b) => compareTextBytes(a.path, b.path)),
    });
  }
  const ownerSections = catalog.map((item) => byId.get(item.id));
  validateOwnership(entries, ownerSections);
  return ownerSections;
}

export function hashInventory(entries) {
  const hash = createInventoryHashState();
  const sorted = [...entries].sort((a, b) => Buffer.compare(a.pathBytes, b.pathBytes));
  for (const candidate of sorted) {
    const entry = validateInventoryEntry(candidate);
    updateInventoryHashState(hash, entry);
  }
  return hash.digest('hex');
}

function createInventoryHashState() {
  const hash = crypto.createHash('sha256');
  updateFrame(hash, INVENTORY_HASH_DOMAIN);
  return hash;
}

function updateInventoryHashState(hash, entry) {
  updateFrame(hash, entry.pathBytes);
  updateFrame(hash, Buffer.from(entry.objectId, 'hex'));
  updateFrame(hash, Buffer.from(entry.mode, 'ascii'));
  updateFrame(hash, Buffer.from(entry.kind, 'ascii'));
}

export function createStreamingInventoryHasher() {
  const hash = createInventoryHashState();
  let previousPathBytes;
  let pathCount = 0;
  let state = 'OPEN';

  function assertOpen() {
    if (state === 'FAILED') hold('C0_INVENTORY_STREAM_FAILED', 'streaming inventory hasher is poisoned after a rejected tuple');
    if (state === 'FINALIZED') hold('C0_INVENTORY_STREAM_FINALIZED', 'streaming inventory hasher is already finalized');
  }

  function add(candidate) {
    assertOpen();
    try {
      const entry = validateInventoryEntry(candidate);
      if (previousPathBytes !== undefined) {
        const order = Buffer.compare(previousPathBytes, entry.pathBytes);
        if (order === 0) hold('C0_INVENTORY_DUPLICATE', 'streaming inventory contains a duplicate path', {
          path: entry.path,
        });
        if (order > 0) hold('C0_INVENTORY_ORDER', 'streaming inventory is not globally raw-byte sorted', {
          previousPath: previousPathBytes.toString('hex'), path: entry.path,
        });
      }
      if (!Number.isSafeInteger(pathCount + 1)) {
        hold('C0_INVENTORY_COUNT', 'streaming inventory path count exceeds safe integer precision');
      }
      updateInventoryHashState(hash, entry);
      previousPathBytes = Buffer.from(entry.pathBytes);
      pathCount += 1;
      return api;
    } catch (error) {
      state = 'FAILED';
      throw error;
    }
  }

  function addChunk(entries) {
    assertOpen();
    if (!Array.isArray(entries)) {
      state = 'FAILED';
      hold('C0_INVENTORY_STREAM_CHUNK', 'streaming inventory chunk must be an array');
    }
    for (const entry of entries) add(entry);
    return api;
  }

  function finalize() {
    assertOpen();
    if (pathCount === 0) {
      state = 'FAILED';
      hold('C0_INVENTORY_EMPTY', 'streaming inventory is empty');
    }
    state = 'FINALIZED';
    return Object.freeze({
      inventorySha256: hash.digest('hex'),
      pathCount,
    });
  }

  const api = Object.freeze({ update: add, updateChunk: addChunk, finalize });
  return api;
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object' && !Buffer.isBuffer(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  }
  return value;
}

export function stringifyJsonDocument(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

export function hashJson(value) {
  return crypto.createHash('sha256').update(stringifyJsonDocument(value), 'utf8').digest('hex');
}

export function validateInventoryDecision(decision, binding) {
  assertPlainObject(decision, 'C0_DENOMINATOR_DECISION', 'inventory decision');
  const keys = [
    'schema', 'decisionVersion', 'decidedAt', 'revision', 'historicalCandidateCount',
    'acceptedAuthorizedCount', 'exclusionPolicySha256', 'inventorySha256', 'rationaleToken',
  ];
  assertExactKeys(decision, keys, 'C0_DECISION_SCHEMA', 'inventory decision');
  for (const key of keys) {
    if (!Object.hasOwn(decision, key)) hold('C0_DECISION_SCHEMA', `inventory decision is missing ${key}`);
  }
  if (decision.schema !== INVENTORY_DECISION_SCHEMA) hold('C0_DECISION_SCHEMA', `expected ${INVENTORY_DECISION_SCHEMA}`);
  if (decision.decisionVersion !== INVENTORY_DECISION_VERSION) {
    hold('C0_DECISION_VERSION', `expected ${INVENTORY_DECISION_VERSION}`);
  }
  if (typeof decision.decidedAt !== 'string') hold('C0_DECISION_TIME', 'decidedAt must be an ISO-8601 UTC timestamp');
  const decidedTime = Date.parse(decision.decidedAt);
  if (!Number.isFinite(decidedTime) || new Date(decidedTime).toISOString() !== decision.decidedAt) {
    hold('C0_DECISION_TIME', 'decidedAt must be a normalized ISO-8601 UTC timestamp');
  }
  const committedTime = Date.parse(binding.committedAt);
  if (decidedTime < committedTime) {
    hold('C0_DECISION_STALE', 'inventory decision predates the immutable source revision', {
      decidedAt: decision.decidedAt, sourceCommittedAt: binding.committedAt,
    });
  }
  if (decidedTime > Date.now() + 5 * 60 * 1000) hold('C0_DECISION_TIME', 'inventory decision timestamp is in the future');
  if (!/^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,7}$/.test(decision.rationaleToken ?? '') || decision.rationaleToken.length > 80) {
    hold('C0_DECISION_RATIONALE', 'rationaleToken must be a bounded opaque uppercase token');
  }
  const bindingFields = [
    'revision', 'historicalCandidateCount', 'acceptedAuthorizedCount',
    'exclusionPolicySha256', 'inventorySha256',
  ];
  const mismatches = bindingFields.flatMap((key) => decision[key] === binding[key] ? [] : [{
    field: key, expected: binding[key], actual: decision[key],
  }]);
  if (mismatches.length > 0) hold('C0_DECISION_BINDING', 'inventory decision does not match the compiled inventory', { mismatches });
  return { ...decision };
}

function publicEntry(entry) {
  return { path: entry.path, objectId: entry.objectId, mode: entry.mode, kind: entry.kind };
}

export function buildEpochDocument({
  revision,
  sourceCommittedAt,
  treeEntries,
  authorized,
  excluded,
  policy,
  policyHash,
  historicalCandidateCount,
  inventoryDecision,
}) {
  return {
    schema: INVENTORY_SCHEMA,
    revision,
    sourceCommittedAt,
    historicalCandidateCount,
    treePathCount: treeEntries.length,
    authorizedCount: authorized.length,
    excludedCount: excluded.length,
    inventorySha256: hashInventory(authorized),
    exclusionPolicy: policy,
    exclusionPolicySha256: policyHash,
    ...(inventoryDecision === undefined ? {} : { inventoryDecision }),
    authorizedPaths: authorized.map(publicEntry),
    excludedPaths: excluded.map((entry) => ({ ...publicEntry(entry), exclusionClass: entry.exclusionClass })),
  };
}

export function buildSectionsDocument({ revision, inventorySha256, ownerSections, catalogVersion = 'provisional-catalog/v1' }) {
  return {
    schema: SECTIONS_SCHEMA,
    revision,
    inventorySha256,
    catalogVersion,
    sections: ownerSections.map((owner) => ({
      id: owner.id, title: owner.title, selectorProvenance: owner.provenance,
      pathCount: owner.entries.length, paths: owner.entries.map(publicEntry),
    })),
  };
}

export function buildShardGeneration({ revision, inventorySha256, ownerSections, generationId = 'owners-as-shards/v1', shards }) {
  const ownerById = new Map(ownerSections.map((owner) => [owner.id, owner]));
  const actualShards = shards ?? ownerSections.map((owner) => ({ id: `${owner.id}/P01`, ownerSectionId: owner.id, entries: owner.entries }));
  const grouped = new Map(ownerSections.map((owner) => [owner.id, []]));
  for (const shard of actualShards) {
    if (!ownerById.has(shard.ownerSectionId) || !Array.isArray(shard.entries)) {
      hold('C0_SHARD_SCHEMA', `invalid shard ${shard.id}`);
    }
    grouped.get(shard.ownerSectionId).push({ id: shard.id, entries: shard.entries });
  }
  for (const owner of ownerSections) {
    validateOwnership(owner.entries, grouped.get(owner.id).map((shard) => ({ id: shard.id, entries: shard.entries })));
  }
  return {
    schema: SHARDS_SCHEMA, revision, inventorySha256, generationId,
    shards: actualShards.map((shard) => ({
      id: shard.id, ownerSectionId: shard.ownerSectionId,
      pathCount: shard.entries.length, pathListSha256: hashInventory(shard.entries), paths: shard.entries.map(publicEntry),
    })),
  };
}

export function compileInventory({
  repoRoot, revision, exclusionPolicy, sectionCatalog = PROVISIONAL_SECTION_CATALOG,
  historicalCandidateCount, inventoryDecision,
}) {
  if (!Number.isSafeInteger(historicalCandidateCount) || historicalCandidateCount < 1) {
    hold('C0_DENOMINATOR_CANDIDATE', 'historicalCandidateCount is mandatory and must be a positive safe integer');
  }
  const tree = enumerateGitTree({ repoRoot, revision });
  const applied = applyExclusionPolicy(tree.entries, exclusionPolicy);
  if (applied.authorized.length === 0) hold('C0_INVENTORY_EMPTY', 'exclusion policy removed every tracked path');
  const ownerSections = classifyOwnership(applied.authorized, sectionCatalog);
  const inventorySha256 = hashInventory(applied.authorized);
  let acceptedDecision;
  if (historicalCandidateCount !== applied.authorized.length) {
    if (inventoryDecision === undefined) {
      hold('C0_DENOMINATOR_DECISION', 'compiled denominator differs from the historical candidate and has no explicit decision', {
        historicalCandidateCount,
        compiledAuthorizedCount: applied.authorized.length,
        delta: applied.authorized.length - historicalCandidateCount,
        excludedPaths: applied.excluded.map((entry) => entry.path),
        inventorySha256,
      });
    }
    acceptedDecision = validateInventoryDecision(inventoryDecision, {
      revision: tree.revision,
      committedAt: tree.committedAt,
      historicalCandidateCount,
      acceptedAuthorizedCount: applied.authorized.length,
      exclusionPolicySha256: applied.policyHash,
      inventorySha256,
    });
  } else if (inventoryDecision !== undefined) {
    hold('C0_DECISION_UNNEEDED', 'inventory decision is only valid for an alternate denominator');
  }
  const epoch = buildEpochDocument({
    revision: tree.revision, sourceCommittedAt: tree.committedAt, treeEntries: tree.entries,
    authorized: applied.authorized, excluded: applied.excluded,
    policy: applied.policy, policyHash: applied.policyHash, historicalCandidateCount,
    inventoryDecision: acceptedDecision,
  });
  const sections = buildSectionsDocument({
    revision: tree.revision, inventorySha256: epoch.inventorySha256, ownerSections,
  });
  const shards = buildShardGeneration({
    revision: tree.revision, inventorySha256: epoch.inventorySha256, ownerSections,
  });
  return { tree: tree.entries, authorized: applied.authorized, excluded: applied.excluded, ownerSections, epoch, sections, shards };
}
