import fs from 'node:fs';
import path from 'node:path';

import {
  SecurityProgramError,
  assertClosedSchema,
  assertRepositoryRelativePath,
  canonicalJson,
  parseStrictJson,
  sha256Hex,
} from './security-program-json.mjs';
import {
  INVENTORY_SCHEMA,
  SECTIONS_SCHEMA,
  SHARDS_SCHEMA,
  hashInventory,
  hashJson,
  normalizeExclusionPolicy,
  validateInventoryDecision,
} from './security-program-inventory.mjs';
import { parseFingerprint } from './source-fingerprint.mjs';
import {
  loadAttemptJournal,
  validateAttemptAuthority,
  validateAttemptEvent,
} from './security-program-attempts.mjs';
import { verifyImmutableBundle } from './security-program-publication.mjs';
import {
  EXPORT_CAPACITY_SCHEMA,
  PINNED_STANDARD_ROUTE_CONTRACT_SHA256,
  STANDARD_TARGET_ROUTES,
  TARGET_ADAPTER_VERSION,
  verifyPreparedTarget,
} from './security-program-targets.mjs';

export const EPOCH_SCHEMA = INVENTORY_SCHEMA;
export const OWNER_SECTIONS_SCHEMA = SECTIONS_SCHEMA;
export const SHARD_GENERATION_SCHEMA = SHARDS_SCHEMA;
export const PILOT_BUDGET_SCHEMA = 'setjoin.security-program.pilot-budget/v1';
export const PILOT_VERDICT_SCHEMA = 'setjoin.security-program.pilot-verdict/v1';
export const RESULT_CLAIM_SCHEMA = 'setjoin.security-program.result-claim/v1';
export const REVIEWED_SET_SCHEMA = 'setjoin.security-program.reviewed-set/v1';
export const REVIEWED_SET_EXTENSION_KEY = 'setjoin.security-program.reviewed-set/v1';
export const REVIEWED_SET_PATH_HASH_DOMAIN = 'setjoin.security-program.reviewed-set.path-list/v1';
export const ADMISSION_INPUT_SCHEMA = 'setjoin.security-program.admission-input/v1';
export const OBSERVATION_SCHEMA = 'setjoin.security-program.observation/v1';
export const DEEP_PROMOTION_SCHEMA = 'setjoin.security-program.deep-promotion/v1';
export const RECONCILIATION_SCHEMA = 'setjoin.security-program.reconciliation/v1';
export const STATUS_SCHEMA = 'setjoin.security-program.status/v1';

export const RECORD_ROLES = Object.freeze({
  AUTHORITY: 'authority',
  OPERATIONAL_CLAIM: 'operational-claim',
  VERIFIED_EVIDENCE: 'verified-evidence',
  DERIVED: 'derived',
});

const HASH = /^[0-9a-f]{64}$/;
const OBJECT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._-]*\/v[1-9][0-9]*$/;
const SHARD_ID = /^S(?:0[1-9]|[12][0-9]|30)\/P(?:0[1-9]|[1-9][0-9]*)$/;
const SECTION_ID = /^S(?:0[1-9]|[12][0-9]|30)$/;
const PRIVATE_TEXT = /(?:^|[\s("'=])(?:\/(?!\/)[^\s]+|[A-Za-z]:\\[^\s]+)|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:password|passwd|secret|api[_-]?key|access[_-]?token|bearer)\s*[:=]/i;

const PATH_KINDS = new Map([
  ['100644', 'file'],
  ['100755', 'executable'],
  ['120000', 'symlink'],
  ['160000', 'submodule'],
]);
const verifiedAdmissionCapabilities = new WeakMap();
const verifiedDeepFallbackAuthorities = new WeakMap();
const STANDARD_ROUTE_FIELDS = Object.freeze([
  'standardRoute', 'routeContractSha256', 'pluginVersion', 'productionEligible',
  'directorySnapshotDigest', 'exportTreeSha256', 'stableSnapshotSha256',
  'budgetId', 'budgetSha256', 'exportCapacity',
]);
const RECORD_ROUTE_FIELDS = Object.freeze([
  'mode', 'adapterVersion', 'targetForm', 'targetKind', 'scannerSchemaVersion',
  ...STANDARD_ROUTE_FIELDS,
]);

function fail(message, details) {
  throw new SecurityProgramError('E_SECURITY_PROGRAM_EVIDENCE_INVALID', message, details);
}

function schemaUnsupported(message, details) {
  throw new SecurityProgramError('E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED', message, details);
}

function closed(value, required, optional, name) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${name} must be an object`);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(`${name} contains an unknown field`, { fieldHash: sha256Hex(key).slice(0, 12) });
  }
  for (const key of required) if (!Object.hasOwn(value, key)) fail(`${name} is missing ${key}`);
  return value;
}

function topLevel(value, schema, role, required, optional, name) {
  assertClosedSchema(value, { schema, required: ['recordRole', ...required], optional, name });
  if (value.recordRole !== role) fail(`${name} must have recordRole ${role}`);
  return value;
}

function text(value, name, { max = 240, allowSpace = false } = {}) {
  if (typeof value !== 'string' || value.length === 0 || value.length > max || /[\0\r\n]/.test(value)) {
    fail(`${name} must be a bounded single-line string`);
  }
  if (!allowSpace && !TOKEN.test(value)) fail(`${name} must be a logical token`);
  if (PRIVATE_TEXT.test(value)) fail(`${name} contains private or secret-shaped text`);
  return value;
}

function token(value, name) { return text(value, name); }

function version(value, name) {
  if (typeof value !== 'string' || !VERSION.test(value) || PRIVATE_TEXT.test(value)) fail(`${name} must be a namespaced /vN identifier`);
  return value;
}

function hash(value, name) {
  if (typeof value !== 'string' || !HASH.test(value)) fail(`${name} must be lowercase SHA-256 hex`);
  return value;
}

function objectId(value, name) {
  if (typeof value !== 'string' || !OBJECT_ID.test(value)) fail(`${name} must be a lowercase Git object ID`);
  return value;
}

function fingerprint(value, name, expectedCommit) {
  let parsed;
  try { parsed = parseFingerprint(value); }
  catch (error) { fail(`${name} must use the authoritative v2:<commit>:<sha256> shape`, { causeCode: error.code ?? 'UNKNOWN' }); }
  if (expectedCommit !== undefined && parsed.commit !== expectedCommit) fail(`${name} commit does not match sourceRevision`);
  return parsed;
}

function isoTime(value, name) {
  const match = typeof value === 'string'
    ? /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3}|\d{6})Z$/.exec(value)
    : null;
  if (match === null) fail(`${name} must be a canonical UTC timestamp`);
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > daysInMonth[month - 1]
      || hour > 23 || minute > 59 || second > 59 || !Number.isFinite(Date.parse(value))) {
    fail(`${name} must be a canonical UTC timestamp`);
  }
  return value;
}

function timestampSortKey(value) {
  return value.replace(/\.(\d{3})Z$/, (_match, milliseconds) => `.${milliseconds}000Z`);
}

function count(value, name, { positive = false } = {}) {
  if (!Number.isSafeInteger(value) || value < (positive ? 1 : 0)) fail(`${name} must be a ${positive ? 'positive' : 'non-negative'} safe integer`);
  return value;
}

function finite(value, name, { positive = false } = {}) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < (positive ? Number.MIN_VALUE : 0)) {
    fail(`${name} must be a ${positive ? 'positive' : 'non-negative'} finite number`);
  }
  return value;
}

function bool(value, name) {
  if (typeof value !== 'boolean') fail(`${name} must be boolean`);
  return value;
}

function oneOf(value, allowed, name) {
  if (!allowed.includes(value)) fail(`${name} has an unsupported value`);
  return value;
}

function sectionId(value, name = 'sectionId') {
  if (typeof value !== 'string' || !SECTION_ID.test(value)) fail(`${name} is invalid`);
  return value;
}

function shardId(value, name = 'shardId') {
  if (typeof value !== 'string' || !SHARD_ID.test(value)) fail(`${name} is invalid`);
  return value;
}

function logicalRef(value, name) {
  if (typeof value !== 'string' || value.length > 240 || !/^[a-z][a-z0-9-]*:[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/.test(value)) {
    fail(`${name} must be a logical artifact reference`);
  }
  if (PRIVATE_TEXT.test(value)) fail(`${name} contains private or secret-shaped text`);
  return value;
}

function repositoryPath(value, name) {
  try { return assertRepositoryRelativePath(value, name); }
  catch (error) {
    if (error instanceof SecurityProgramError) fail(`${name} must be a safe repository-relative path`);
    throw error;
  }
}

function assertUnique(values, identity, name) {
  const seen = new Set();
  for (const value of values) {
    const key = identity(value);
    if (seen.has(key)) fail(`${name} contains duplicate identity`, { identityHash: sha256Hex(key).slice(0, 16) });
    seen.add(key);
  }
}

function compareBytes(left, right) { return Buffer.from(left, 'utf8').compare(Buffer.from(right, 'utf8')); }

function frame(bytes) {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  return Buffer.concat([length, bytes]);
}

export function hashReviewedFilePaths(paths) {
  if (!Array.isArray(paths)) fail('reviewed file paths must be an array');
  paths.forEach((item, index) => repositoryPath(item, `reviewed file paths[${index}]`));
  assertUnique(paths, (item) => item, 'reviewed file paths');
  assertByteSorted(paths, (item) => item, 'reviewed file paths');
  return sha256Hex(Buffer.concat([
    frame(Buffer.from(REVIEWED_SET_PATH_HASH_DOMAIN, 'utf8')),
    ...paths.map((item) => frame(Buffer.from(item, 'utf8'))),
  ]));
}

function validateExportCapacity(value, name = 'exportCapacity') {
  assertClosedSchema(value, {
    schema: EXPORT_CAPACITY_SCHEMA,
    required: [
      'maxEntries', 'maxBytes', 'minimumFreeBytes', 'maxBuildElapsedMs',
      'maxBuildPeakRssBytes', 'maxSnapshotElapsedMs', 'maxSnapshotPeakRssBytes',
    ],
    name,
  });
  for (const field of [
    'maxEntries', 'maxBytes', 'maxBuildElapsedMs', 'maxBuildPeakRssBytes',
    'maxSnapshotElapsedMs', 'maxSnapshotPeakRssBytes',
  ]) count(value[field], `${name}.${field}`, { positive: true });
  count(value.minimumFreeBytes, `${name}.minimumFreeBytes`);
  return value;
}

function validateRecordRoute(record, name, {
  allowSdkBudget = false,
  requireDesktopBudget = true,
  requireDesktopDigests = true,
} = {}) {
  oneOf(record.mode, ['Standard', 'Deep'], `${name}.mode`);
  if (record.adapterVersion !== TARGET_ADAPTER_VERSION) fail(`${name}.adapterVersion is unsupported`);
  version(record.scannerSchemaVersion, `${name}.scannerSchemaVersion`);
  if (record.mode === 'Deep') {
    if (record.targetForm !== 'real-directory' || record.targetKind !== 'git_revision'
        || STANDARD_ROUTE_FIELDS.some((field) => Object.hasOwn(record, field))) {
      fail(`${name} Deep route shape is invalid`);
    }
    return record;
  }
  oneOf(record.standardRoute, Object.values(STANDARD_TARGET_ROUTES), `${name}.standardRoute`);
  hash(record.routeContractSha256, `${name}.routeContractSha256`);
  if (record.routeContractSha256 !== PINNED_STANDARD_ROUTE_CONTRACT_SHA256[record.standardRoute]) {
    schemaUnsupported(`${name} route contract does not match the pinned implementation`);
  }
  if (record.pluginVersion !== '0.1.24') schemaUnsupported(`${name} plugin version is unsupported`);
  if (record.productionEligible !== true) fail(`${name} is not production eligible`);
  if (record.standardRoute === STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS) {
    if (record.targetForm !== 'exact-paths-file' || record.targetKind !== 'git_revision'
        || ['directorySnapshotDigest', 'exportTreeSha256', 'stableSnapshotSha256',
          'exportCapacity', ...(allowSdkBudget ? [] : ['budgetId', 'budgetSha256'])]
          .some((field) => Object.hasOwn(record, field))) {
      fail(`${name} SDK exact-path route shape is invalid`);
    }
    return record;
  }
  if (record.targetForm !== 'attested-directory-export' || record.targetKind !== 'directory_snapshot') {
    fail(`${name} Desktop attested-export route shape is invalid`);
  }
  if (requireDesktopDigests) {
    if (typeof record.directorySnapshotDigest !== 'string'
        || !/^codex-security-snapshot\/v1:sha256:[0-9a-f]{64}$/.test(record.directorySnapshotDigest)) {
      fail(`${name} Desktop directory snapshot digest is invalid`);
    }
    for (const field of ['exportTreeSha256', 'stableSnapshotSha256']) {
      hash(record[field], `${name}.${field}`);
    }
  } else if (['directorySnapshotDigest', 'exportTreeSha256', 'stableSnapshotSha256']
    .some((field) => Object.hasOwn(record, field))) {
    fail(`${name} must not duplicate Desktop target digest authority`);
  }
  if (requireDesktopBudget) {
    hash(record.budgetSha256, `${name}.budgetSha256`);
    token(record.budgetId, `${name}.budgetId`);
    validateExportCapacity(record.exportCapacity, `${name}.exportCapacity`);
  } else if (['budgetId', 'budgetSha256', 'exportCapacity'].some((field) => Object.hasOwn(record, field))) {
    fail(`${name} must not duplicate Desktop attempt budget authority`);
  }
  return record;
}

function preparedRouteAuthority(target, scannerSchemaVersion) {
  const verified = verifyPreparedTarget(target);
  const common = {
    mode: target.mode === 'deep' ? 'Deep' : 'Standard',
    adapterVersion: target.adapterVersion,
    targetForm: target.mode === 'deep' ? 'real-directory'
      : (verified.standardRoute === STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS
        ? 'exact-paths-file' : 'attested-directory-export'),
    targetKind: target.mode === 'deep' ? 'git_revision'
      : (verified.standardRoute === STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS ? 'git_revision' : 'directory_snapshot'),
    scannerSchemaVersion,
  };
  if (target.mode === 'deep') return Object.freeze(common);
  const authority = {
    ...common,
    standardRoute: verified.standardRoute,
    routeContractSha256: verified.routeContractSha256,
    pluginVersion: verified.pluginVersion,
    productionEligible: verified.productionEligible,
  };
  if (verified.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT) {
    Object.assign(authority, {
      directorySnapshotDigest: verified.directorySnapshotDigest,
      exportTreeSha256: verified.exportTreeSha256,
      stableSnapshotSha256: verified.stableSnapshotSha256,
      budgetId: verified.budgetId,
      budgetSha256: verified.budgetSha256,
      exportCapacity: verified.exportCapacity,
    });
  }
  validateRecordRoute(authority, 'prepared target authority');
  return Object.freeze(authority);
}

function assertRouteAuthorityMatches(record, authority, name, {
  includeBudget = true,
  includeProductionEligibility = true,
} = {}) {
  const omitted = new Set([
    ...(includeBudget ? [] : ['budgetId', 'budgetSha256', 'exportCapacity']),
    ...(includeProductionEligibility ? [] : ['productionEligible']),
  ]);
  const fields = RECORD_ROUTE_FIELDS.filter((field) => !omitted.has(field));
  for (const field of fields) {
    const hasRecord = Object.hasOwn(record, field);
    const hasAuthority = Object.hasOwn(authority, field);
    const equal = !hasRecord || !hasAuthority ? false : (field === 'exportCapacity'
      ? canonicalJson(record[field]) === canonicalJson(authority[field])
      : record[field] === authority[field]);
    if (hasRecord !== hasAuthority || (hasRecord && !equal)) fail(`${name} route authority does not match ${field}`);
  }
}

function assertByteSorted(values, project, name) {
  for (let index = 1; index < values.length; index += 1) {
    if (compareBytes(project(values[index - 1]), project(values[index])) >= 0) fail(`${name} must be unique and bytewise sorted`);
  }
}

function publicPathEntry(value, name, { excluded = false } = {}) {
  const required = ['path', 'objectId', 'mode', 'kind', ...(excluded ? ['exclusionClass'] : [])];
  closed(value, required, [], name);
  repositoryPath(value.path, `${name}.path`);
  objectId(value.objectId, `${name}.objectId`);
  if (!PATH_KINDS.has(value.mode) || PATH_KINDS.get(value.mode) !== value.kind) fail(`${name} has inconsistent Git mode and kind`);
  if (excluded) token(value.exclusionClass, `${name}.exclusionClass`);
  return value;
}

function inventoryEntries(entries, name, options) {
  if (!Array.isArray(entries)) fail(`${name} must be an array`);
  for (const [index, entry] of entries.entries()) publicPathEntry(entry, `${name}[${index}]`, options);
  assertUnique(entries, (entry) => entry.path, name);
  assertByteSorted(entries, (entry) => entry.path, name);
  return entries;
}

function hashPublicInventory(entries) {
  return hashInventory(entries.map((entry) => ({
    ...entry,
    pathBytes: Buffer.from(entry.path, 'utf8'),
    objectType: entry.mode === '160000' ? 'commit' : 'blob',
  })));
}

function publicInventoryTuples(entries) {
  return entries.map(({ path: pathname, objectId: oid, mode, kind }) => ({
    path: pathname,
    objectId: oid,
    mode,
    kind,
  })).sort((left, right) => compareBytes(left.path, right.path));
}

function normalizeAndCheckPolicy(policy) {
  let normalized;
  try { normalized = normalizeExclusionPolicy(policy); }
  catch (error) { fail('epoch exclusion policy is invalid', { causeCode: error.code ?? 'UNKNOWN' }); }
  if (canonicalJson(normalized) !== canonicalJson(policy)) fail('epoch exclusion policy is not closed and normalized');
  return normalized;
}

function withFixed(fields, schema, recordRole) {
  return { ...fields, schema, recordRole };
}

export function validateEpochRecord(record) {
  topLevel(record, EPOCH_SCHEMA, RECORD_ROLES.AUTHORITY, [
    'revision', 'sourceCommittedAt', 'historicalCandidateCount', 'treePathCount', 'authorizedCount', 'excludedCount', 'inventorySha256',
    'exclusionPolicy', 'exclusionPolicySha256', 'authorizedPaths', 'excludedPaths',
  ], ['inventoryDecision'], 'epoch record');
  objectId(record.revision, 'epoch revision');
  isoTime(record.sourceCommittedAt, 'epoch sourceCommittedAt');
  count(record.historicalCandidateCount, 'historicalCandidateCount', { positive: true });
  count(record.treePathCount, 'treePathCount', { positive: true });
  count(record.authorizedCount, 'authorizedCount', { positive: true });
  count(record.excludedCount, 'excludedCount');
  hash(record.inventorySha256, 'inventorySha256');
  hash(record.exclusionPolicySha256, 'exclusionPolicySha256');
  const policy = normalizeAndCheckPolicy(record.exclusionPolicy);
  const authorized = inventoryEntries(record.authorizedPaths, 'authorizedPaths');
  const excluded = inventoryEntries(record.excludedPaths, 'excludedPaths', { excluded: true });
  assertUnique([...authorized, ...excluded], (entry) => entry.path, 'epoch paths');
  if (record.authorizedCount !== authorized.length || record.excludedCount !== excluded.length
      || record.treePathCount !== authorized.length + excluded.length) fail('epoch path counts do not match path arrays');
  if (record.inventorySha256 !== hashPublicInventory(authorized)) fail('epoch inventory hash does not match authorized paths');
  if (record.exclusionPolicySha256 !== hashJson(policy)) fail('epoch exclusion policy hash does not match policy');
  const classIds = new Set(policy.classes.map((item) => item.id));
  if (excluded.some((entry) => !classIds.has(entry.exclusionClass))) fail('excluded path names an unknown exclusion class');
  for (const policyClass of policy.classes) {
    if (policyClass.expectedCount !== undefined
        && excluded.filter((entry) => entry.exclusionClass === policyClass.id).length !== policyClass.expectedCount) {
      fail('excluded path count does not match policy expectedCount');
    }
  }
  const alternateDenominator = record.authorizedCount !== record.historicalCandidateCount;
  if (alternateDenominator && record.inventoryDecision === undefined) {
    fail('epoch requires an inventory decision when authorizedCount differs from historicalCandidateCount');
  }
  if (!alternateDenominator && record.inventoryDecision !== undefined) {
    fail('epoch must omit inventoryDecision when authorizedCount equals historicalCandidateCount');
  }
  if (record.inventoryDecision !== undefined) {
    let acceptedDecision;
    try {
      acceptedDecision = validateInventoryDecision(record.inventoryDecision, {
        revision: record.revision,
        committedAt: record.sourceCommittedAt,
        historicalCandidateCount: record.historicalCandidateCount,
        acceptedAuthorizedCount: record.authorizedCount,
        exclusionPolicySha256: record.exclusionPolicySha256,
        inventorySha256: record.inventorySha256,
      });
    } catch (error) {
      fail('epoch inventory decision is invalid or does not bind the compiled inventory', {
        causeCode: error.code ?? 'UNKNOWN',
      });
    }
    if (canonicalJson(acceptedDecision) !== canonicalJson(record.inventoryDecision)) {
      fail('epoch inventory decision did not round-trip exactly');
    }
  }
  return record;
}

export function buildEpochRecord(document) {
  return validateEpochRecord(withFixed(document, EPOCH_SCHEMA, RECORD_ROLES.AUTHORITY));
}

function validateSection(section, name) {
  closed(section, ['id', 'title', 'selectorProvenance', 'pathCount', 'paths'], [], name);
  sectionId(section.id, `${name}.id`);
  text(section.title, `${name}.title`, { allowSpace: true });
  text(section.selectorProvenance, `${name}.selectorProvenance`, { max: 500, allowSpace: true });
  count(section.pathCount, `${name}.pathCount`);
  inventoryEntries(section.paths, `${name}.paths`);
  if (section.pathCount !== section.paths.length) fail(`${name}.pathCount does not match paths`);
  return section;
}

export function validateSectionsRecord(record, { epoch } = {}) {
  topLevel(record, OWNER_SECTIONS_SCHEMA, RECORD_ROLES.AUTHORITY,
    ['revision', 'inventorySha256', 'catalogVersion', 'sections'], [], 'owner sections record');
  objectId(record.revision, 'sections revision');
  hash(record.inventorySha256, 'sections inventorySha256');
  version(record.catalogVersion, 'catalogVersion');
  if (!Array.isArray(record.sections) || record.sections.length === 0) fail('sections must be a non-empty array');
  record.sections.forEach((item, index) => validateSection(item, `sections[${index}]`));
  assertUnique(record.sections, (item) => item.id, 'sections');
  assertByteSorted(record.sections, (item) => item.id, 'sections');
  const ownedPaths = record.sections.flatMap((item) => item.paths);
  assertUnique(ownedPaths, (entry) => entry.path, 'owned paths');
  if (epoch !== undefined) {
    validateEpochRecord(epoch);
    if (record.revision !== epoch.revision || record.inventorySha256 !== epoch.inventorySha256) fail('sections do not bind the epoch identity');
    const expected = publicInventoryTuples(epoch.authorizedPaths);
    const actual = publicInventoryTuples(ownedPaths);
    if (canonicalJson(actual) !== canonicalJson(expected)) fail('sections are not an exact union of epoch authorized paths');
  }
  return record;
}

export function buildSectionsRecord(document, options) {
  return validateSectionsRecord(withFixed(document, OWNER_SECTIONS_SCHEMA, RECORD_ROLES.AUTHORITY), options);
}

function validateShard(shard, name) {
  closed(shard, ['id', 'ownerSectionId', 'pathCount', 'pathListSha256', 'paths'], [], name);
  shardId(shard.id, `${name}.id`);
  sectionId(shard.ownerSectionId, `${name}.ownerSectionId`);
  if (!shard.id.startsWith(`${shard.ownerSectionId}/`)) fail(`${name}.id must be namespaced by ownerSectionId`);
  count(shard.pathCount, `${name}.pathCount`);
  hash(shard.pathListSha256, `${name}.pathListSha256`);
  inventoryEntries(shard.paths, `${name}.paths`);
  if (shard.pathCount !== shard.paths.length || shard.pathListSha256 !== hashPublicInventory(shard.paths)) {
    fail(`${name} count or hash does not match paths`);
  }
  return shard;
}

export function validateShardGenerationRecord(record, { epoch, sections } = {}) {
  topLevel(record, SHARD_GENERATION_SCHEMA, RECORD_ROLES.AUTHORITY,
    ['revision', 'inventorySha256', 'generationId', 'shards'], [], 'shard generation record');
  objectId(record.revision, 'shard revision');
  hash(record.inventorySha256, 'shard inventorySha256');
  version(record.generationId, 'shard generationId');
  if (!Array.isArray(record.shards) || record.shards.length === 0) fail('shards must be a non-empty array');
  record.shards.forEach((item, index) => validateShard(item, `shards[${index}]`));
  assertUnique(record.shards, (item) => item.id, 'shards');
  assertByteSorted(record.shards, (item) => item.id, 'shards');
  if (epoch !== undefined) {
    validateEpochRecord(epoch);
    if (record.revision !== epoch.revision || record.inventorySha256 !== epoch.inventorySha256) fail('shards do not bind the epoch identity');
  }
  if (sections !== undefined) {
    validateSectionsRecord(sections, { epoch });
    if (record.revision !== sections.revision || record.inventorySha256 !== sections.inventorySha256) fail('shards do not bind owner sections');
    for (const section of sections.sections) {
      const expected = publicInventoryTuples(section.paths);
      const actualEntries = record.shards.filter((item) => item.ownerSectionId === section.id).flatMap((item) => item.paths);
      assertUnique(actualEntries, (entry) => entry.path, `shards for ${section.id}`);
      const actual = publicInventoryTuples(actualEntries);
      if (canonicalJson(actual) !== canonicalJson(expected)) fail(`shards are not an exact union of owner section ${section.id}`);
    }
    if (record.shards.some((item) => !sections.sections.some((section) => section.id === item.ownerSectionId))) {
      fail('shard names an unknown owner section');
    }
  }
  return record;
}

export function buildShardGenerationRecord(document, options) {
  return validateShardGenerationRecord(withFixed(document, SHARD_GENERATION_SCHEMA, RECORD_ROLES.AUTHORITY), options);
}

function validatePilotLimits(limits, standardRoute) {
  const commonFields = [
    'maxElapsedSeconds', 'maxArtifactBytes', 'maxPeakRssBytes', 'maxOperatorSeconds',
    'minCreditedFilesPerHour', 'minFreeBytesAfter', 'maxRetries',
    'wholeEpochMaxElapsedSeconds', 'wholeEpochMaxArtifactBytes',
  ];
  const exportFields = [
    'maxExportBytes', 'maxExportEntries', 'maxExportBuildSeconds', 'maxSnapshotSeconds',
  ];
  const fields = standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT
    ? [...commonFields, ...exportFields] : commonFields;
  closed(limits, fields, [], 'pilot limits');
  for (const field of fields) finite(limits[field], `pilot limits.${field}`, { positive: field !== 'maxRetries' });
  if (!Number.isSafeInteger(limits.maxRetries) || limits.maxRetries !== 0) fail('pilot maxRetries must equal zero');
  return limits;
}

function validatePilotHost(host) {
  closed(host, ['hostClass', 'os', 'architecture', 'cpuCount', 'ramBytes', 'diskFreeBytes', 'volumeId'], [], 'pilot host');
  for (const field of ['hostClass', 'os', 'architecture', 'volumeId']) token(host[field], `pilot host.${field}`);
  count(host.cpuCount, 'pilot host.cpuCount', { positive: true });
  count(host.ramBytes, 'pilot host.ramBytes', { positive: true });
  count(host.diskFreeBytes, 'pilot host.diskFreeBytes', { positive: true });
  return host;
}

function validatePilotScanner(scanner) {
  closed(scanner, [
    'adapterVersion', 'scannerSchemaVersion', 'configSha256', 'standardRoute',
    'routeContractSha256', 'pluginVersion', 'targetForm', 'targetKind',
    'productionEligible', 'deepScanMaxTimeHours',
  ], [], 'pilot scanner');
  version(scanner.adapterVersion, 'pilot scanner.adapterVersion');
  version(scanner.scannerSchemaVersion, 'pilot scanner.scannerSchemaVersion');
  hash(scanner.configSha256, 'pilot scanner.configSha256');
  validateRecordRoute({ ...scanner, mode: 'Standard' }, 'pilot scanner', {
    requireDesktopBudget: false,
    requireDesktopDigests: false,
  });
  finite(scanner.deepScanMaxTimeHours, 'pilot scanner.deepScanMaxTimeHours', { positive: true });
  if (scanner.deepScanMaxTimeHours !== 6) fail('pilot deepScanMaxTimeHours must equal the approved six-hour baseline');
  return scanner;
}

function hashPilotBudget(record) {
  const copy = { ...record };
  delete copy.budgetSha256;
  return sha256Hex(canonicalJson(copy));
}

function validatePilotBudgetShape(record) {
  topLevel(record, PILOT_BUDGET_SCHEMA, RECORD_ROLES.AUTHORITY,
    [
      'budgetId', 'registeredAt', 'epochRevision', 'inventorySha256',
      'shardGenerationId', 'pilotShardId', 'shardPathListSha256',
      'controlGenerationHash', 'pilotPathCount', 'limits', 'host', 'scanner', 'budgetSha256',
    ], ['exportCapacity'], 'pilot budget record');
  token(record.budgetId, 'pilot budgetId');
  isoTime(record.registeredAt, 'pilot registeredAt');
  objectId(record.epochRevision, 'pilot epochRevision');
  hash(record.inventorySha256, 'pilot inventorySha256');
  version(record.shardGenerationId, 'pilot shardGenerationId');
  shardId(record.pilotShardId, 'pilot shardId');
  hash(record.shardPathListSha256, 'pilot shardPathListSha256');
  hash(record.controlGenerationHash, 'pilot controlGenerationHash');
  hash(record.budgetSha256, 'pilot budgetSha256');
  count(record.pilotPathCount, 'pilot path count', { positive: true });
  if (record.pilotPathCount < 200 || record.pilotPathCount > 300) fail('pilot path count must be within the approved 200-300 range');
  validatePilotHost(record.host);
  validatePilotScanner(record.scanner);
  validatePilotLimits(record.limits, record.scanner.standardRoute);
  if (record.host.ramBytes < record.limits.maxPeakRssBytes
      || record.host.diskFreeBytes < record.limits.minFreeBytesAfter) {
    fail('pilot host declaration cannot satisfy the immutable resource limits');
  }
  if (record.scanner.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT) {
    validateExportCapacity(record.exportCapacity, 'pilot exportCapacity');
    if (record.limits.maxExportBytes !== record.exportCapacity.maxBytes
        || record.limits.maxExportEntries !== record.exportCapacity.maxEntries
        || record.limits.maxExportBuildSeconds * 1000 !== record.exportCapacity.maxBuildElapsedMs
        || record.limits.maxSnapshotSeconds * 1000 !== record.exportCapacity.maxSnapshotElapsedMs
        || record.limits.maxPeakRssBytes !== record.exportCapacity.maxBuildPeakRssBytes
        || record.limits.maxPeakRssBytes !== record.exportCapacity.maxSnapshotPeakRssBytes
        || record.limits.minFreeBytesAfter !== record.exportCapacity.minimumFreeBytes) {
      fail('pilot export limits do not exactly bind the target export capacity');
    }
  } else if (record.exportCapacity !== undefined) {
    fail('SDK exact-path pilot budget must not carry export capacity');
  }
  if (record.budgetSha256 !== hashPilotBudget(record)) fail('pilot budgetSha256 does not match the immutable budget');
  return record;
}

export function validatePilotBudgetBindings(record, { epoch, shards } = {}) {
  validatePilotBudgetShape(record);
  if (epoch === undefined || shards === undefined) {
    fail('pilot budget authority requires the live epoch and shard generation');
  }
  validateEpochRecord(epoch);
  if (record.epochRevision !== epoch.revision || record.inventorySha256 !== epoch.inventorySha256) {
    fail('pilot budget does not bind the supplied epoch');
  }
  validateShardGenerationRecord(shards, { epoch });
  const shard = shards.shards.find((item) => item.id === record.pilotShardId);
  if (!shard || record.shardGenerationId !== shards.generationId
      || record.epochRevision !== shards.revision || record.inventorySha256 !== shards.inventorySha256
      || record.shardPathListSha256 !== shard.pathListSha256 || record.pilotPathCount !== shard.pathCount) {
    fail('pilot budget does not bind the supplied shard generation and exact pilot shard');
  }
  return record;
}

export function validatePilotBudgetRecord(record, options) {
  return validatePilotBudgetBindings(record, options);
}

export function buildPilotBudgetRecord(fields, options) {
  const record = withFixed({ ...fields, budgetSha256: '0'.repeat(64) }, PILOT_BUDGET_SCHEMA, RECORD_ROLES.AUTHORITY);
  record.budgetSha256 = hashPilotBudget(record);
  return validatePilotBudgetBindings(
    record,
    options,
  );
}

const PILOT_CHECKS = [
  'reviewedSetPresent', 'exactReviewedSet', 'scannerSchemaAccepted', 'sourceUnchanged',
  'sameIdResumeProven', 'sealedHashesValid', 'transactionalPublicationPass',
  'checksumReplayPass', 'attemptLimitsPass', 'wholeEpochLimitsPass',
  'standardEconomical', 'hostCapacityPass', 'exportCapacityPass',
];

const PILOT_MEASUREMENTS = [
  'creditedPathCount', 'elapsedSeconds', 'artifactBytes', 'operatorSeconds',
  'peakRssBytes', 'freeBytesAfter', 'retryCount', 'creditedFilesPerHour',
  'wholeEpochQuanta', 'projectedWholeEpochElapsedSeconds',
  'projectedWholeEpochArtifactBytes',
];

function validatePilotChecks(checks) {
  closed(checks, PILOT_CHECKS, [], 'pilot verdict checks');
  for (const field of PILOT_CHECKS) bool(checks[field], `pilot verdict checks.${field}`);
  return checks;
}

function validatePilotMeasurements(measurements) {
  closed(measurements, PILOT_MEASUREMENTS, [], 'pilot verdict measurements');
  for (const field of PILOT_MEASUREMENTS) {
    finite(measurements[field], `pilot verdict measurements.${field}`);
  }
  for (const field of [
    'creditedPathCount', 'artifactBytes', 'peakRssBytes', 'freeBytesAfter',
    'retryCount', 'wholeEpochQuanta', 'projectedWholeEpochArtifactBytes',
  ]) {
    if (!Number.isSafeInteger(measurements[field]) || measurements[field] < 0) {
      fail(`pilot verdict measurements.${field} must be a non-negative safe integer`);
    }
  }
  if (measurements.wholeEpochQuanta < 1) fail('pilot verdict wholeEpochQuanta must be positive');
  return measurements;
}

function pilotReasonCode(field) {
  return `FAILED_${field.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase()}`;
}

function pilotFallbackSafetyPass(checks) {
  return [
    'sourceUnchanged', 'sameIdResumeProven', 'sealedHashesValid',
    'transactionalPublicationPass', 'checksumReplayPass', 'hostCapacityPass',
    'exportCapacityPass',
  ].every((field) => checks[field]);
}

function pilotCreditDefensible(checks) {
  return pilotFallbackSafetyPass(checks)
    && checks.reviewedSetPresent && checks.exactReviewedSet && checks.scannerSchemaAccepted;
}

function derivePilotEvaluation(verified, deepFallback) {
  const { admission, budget, resultClaim, reviewedFiles, events, verification } = verified;
  if (budget === undefined) fail('pilot verdict requires an immutable budget bound into its admission capability');
  const elapsedHours = resultClaim.elapsedSeconds / 3600;
  const wholeEpochQuanta = Math.ceil(verified.epoch.authorizedCount / budget.pilotPathCount);
  const creditedFilesPerHour = elapsedHours === 0
    ? (reviewedFiles.length === 0 ? 0 : Number.MAX_SAFE_INTEGER)
    : reviewedFiles.length / elapsedHours;
  const measurements = {
    creditedPathCount: reviewedFiles.length,
    elapsedSeconds: resultClaim.elapsedSeconds,
    artifactBytes: resultClaim.artifactBytes,
    operatorSeconds: resultClaim.operatorSeconds,
    peakRssBytes: resultClaim.peakRssBytes,
    freeBytesAfter: resultClaim.freeBytesAfter,
    retryCount: resultClaim.retryCount,
    creditedFilesPerHour,
    wholeEpochQuanta,
    projectedWholeEpochElapsedSeconds: resultClaim.elapsedSeconds * wholeEpochQuanta,
    projectedWholeEpochArtifactBytes: resultClaim.artifactBytes * wholeEpochQuanta,
  };
  const shard = verified.shards.shards.find((item) => item.id === admission.shardId);
  const exactReviewedSet = shard !== undefined
    && canonicalJson(reviewedFiles) === canonicalJson(shard.paths.map((item) => item.path));
  const scanEvents = events.filter((event) => event.attemptId === admission.attemptId
    && event.scanId !== undefined);
  const sameIdResumeProven = scanEvents.length >= 3
    && scanEvents.every((event) => event.scanId === admission.scanId)
    && ['RUNNING', 'SEALED', 'ADMITTED'].every((state) => scanEvents.some((event) => event.state === state));
  const scannerSchemaAccepted = [
    'adapterVersion', 'scannerSchemaVersion', 'standardRoute', 'routeContractSha256',
    'pluginVersion', 'targetForm', 'targetKind', 'productionEligible',
  ].every((field) => admission[field] === budget.scanner[field]);
  const sourceUnchanged = admission.sourceRevision === verified.epoch.revision
    && admission.inventorySha256 === verified.epoch.inventorySha256
    && admission.sourceRevision === admission.currentSourceRevision
    && admission.sourceFingerprint === admission.currentSourceFingerprint;
  const attemptLimitsPass = measurements.elapsedSeconds <= budget.limits.maxElapsedSeconds
    && measurements.artifactBytes <= budget.limits.maxArtifactBytes
    && measurements.operatorSeconds <= budget.limits.maxOperatorSeconds
    && measurements.peakRssBytes <= budget.limits.maxPeakRssBytes
    && measurements.freeBytesAfter >= budget.limits.minFreeBytesAfter
    && measurements.retryCount <= budget.limits.maxRetries;
  const wholeEpochLimitsPass = measurements.projectedWholeEpochElapsedSeconds
      <= budget.limits.wholeEpochMaxElapsedSeconds
    && measurements.projectedWholeEpochArtifactBytes <= budget.limits.wholeEpochMaxArtifactBytes;
  const standardEconomical = measurements.creditedFilesPerHour >= budget.limits.minCreditedFilesPerHour;
  const hostCapacityPass = measurements.peakRssBytes <= budget.host.ramBytes
    && measurements.freeBytesAfter >= budget.limits.minFreeBytesAfter;
  const exportCapacityPass = admission.standardRoute === STANDARD_TARGET_ROUTES.SDK_EXACT_PATHS
    || (canonicalJson(admission.exportCapacity) === canonicalJson(budget.exportCapacity)
      && budget.limits.maxExportBytes === budget.exportCapacity.maxBytes
      && budget.limits.maxExportEntries === budget.exportCapacity.maxEntries
      && budget.limits.maxExportBuildSeconds * 1000 === budget.exportCapacity.maxBuildElapsedMs
      && budget.limits.maxSnapshotSeconds * 1000 === budget.exportCapacity.maxSnapshotElapsedMs
      && budget.limits.maxPeakRssBytes === budget.exportCapacity.maxBuildPeakRssBytes
      && budget.limits.maxPeakRssBytes === budget.exportCapacity.maxSnapshotPeakRssBytes);
  const checks = {
    reviewedSetPresent: reviewedFiles.length > 0,
    exactReviewedSet,
    scannerSchemaAccepted,
    sourceUnchanged,
    sameIdResumeProven,
    sealedHashesValid: verification.hashesValid,
    transactionalPublicationPass: verification.sealed,
    checksumReplayPass: verification.canonicalFilesStable,
    attemptLimitsPass,
    wholeEpochLimitsPass,
    standardEconomical,
    hostCapacityPass,
    exportCapacityPass,
  };
  const failed = PILOT_CHECKS.filter((field) => !checks[field]);
  const defensibleWithoutAttemptLimits = failed.length === 1 && failed[0] === 'attemptLimitsPass';
  const fallbackBasis = pilotFallbackSafetyPass(checks)
    && (!pilotCreditDefensible(checks) || !checks.standardEconomical);
  const verdict = failed.length === 0 ? 'GO_STANDARD'
    : (defensibleWithoutAttemptLimits ? 'REPARTITION'
      : (fallbackBasis && deepFallback !== undefined ? 'BOUNDED_DEEP_FALLBACK' : 'HOLD'));
  const reasonCodes = failed.length === 0 ? ['PILOT_LIMITS_PASS']
    : (fallbackBasis && deepFallback === undefined
      ? [...failed.map(pilotReasonCode), 'DEEP_FALLBACK_AUTHORITY_REQUIRED']
      : failed.map(pilotReasonCode));
  return Object.freeze({
    verdict,
    checks: Object.freeze(checks),
    measurements: Object.freeze(measurements),
    reasonCodes: Object.freeze(reasonCodes),
    ...(verdict === 'BOUNDED_DEEP_FALLBACK' ? {
      deepPromotionId: deepFallback.promotion.promotionId,
      deepDirectoryTarget: deepFallback.promotion.targetDirectory,
    } : {}),
  });
}

export function validatePilotVerdictRecord(record, {
  admissionCapability,
  deepFallbackAuthority,
} = {}) {
  topLevel(record, PILOT_VERDICT_SCHEMA, RECORD_ROLES.DERIVED,
    [
      'budgetId', 'attemptId', 'resultClaimId', 'resultClaimHash', 'evaluatedAt',
      'epochRevision', 'inventorySha256', 'shardGenerationId', 'shardId',
      'shardPathListSha256', 'controlGenerationHash', 'budgetSha256',
      'mode', 'adapterVersion', 'targetForm', 'targetKind', 'scannerSchemaVersion',
      'verdict', 'checks', 'measurements', 'reasonCodes',
    ], ['deepPromotionId', 'deepDirectoryTarget', ...STANDARD_ROUTE_FIELDS], 'pilot verdict record');
  token(record.budgetId, 'pilot verdict budgetId');
  token(record.attemptId, 'pilot verdict attemptId');
  token(record.resultClaimId, 'pilot verdict resultClaimId');
  hash(record.resultClaimHash, 'pilot verdict resultClaimHash');
  isoTime(record.evaluatedAt, 'pilot verdict evaluatedAt');
  objectId(record.epochRevision, 'pilot verdict epochRevision');
  hash(record.inventorySha256, 'pilot verdict inventorySha256');
  version(record.shardGenerationId, 'pilot verdict shardGenerationId');
  shardId(record.shardId, 'pilot verdict shardId');
  hash(record.shardPathListSha256, 'pilot verdict shardPathListSha256');
  hash(record.controlGenerationHash, 'pilot verdict controlGenerationHash');
  hash(record.budgetSha256, 'pilot verdict budgetSha256');
  validateRecordRoute(record, 'pilot verdict', { allowSdkBudget: true });
  oneOf(record.verdict, ['GO_STANDARD', 'REPARTITION', 'BOUNDED_DEEP_FALLBACK', 'HOLD'], 'pilot verdict');
  validatePilotChecks(record.checks);
  validatePilotMeasurements(record.measurements);
  if (!Array.isArray(record.reasonCodes) || record.reasonCodes.length === 0) fail('pilot verdict reasonCodes must be a non-empty array');
  record.reasonCodes.forEach((item, index) => token(item, `pilot reasonCodes[${index}]`));
  assertUnique(record.reasonCodes, (item) => item, 'pilot reasonCodes');
  if ((record.deepPromotionId === undefined) !== (record.deepDirectoryTarget === undefined)) {
    fail('pilot Deep fallback identity must be present or absent as one authority pair');
  }
  if (record.deepPromotionId !== undefined) {
    token(record.deepPromotionId, 'pilot deepPromotionId');
    repositoryPath(record.deepDirectoryTarget, 'pilot deepDirectoryTarget');
  }
  if ((record.verdict === 'BOUNDED_DEEP_FALLBACK') !== (record.deepPromotionId !== undefined)) {
    fail('pilot Deep fallback verdict requires exactly one derived promotion authority');
  }
  const verified = admissionFromCapability(admissionCapability);
  const deepFallback = deepFallbackAuthority === undefined ? undefined
    : deepFallbackFromCapability(deepFallbackAuthority, admissionCapability);
  const { budget, resultClaim, admission } = verified;
  if (budget === undefined) fail('pilot verdict admission capability does not bind an immutable budget');
  validatePilotBudgetBindings(budget, { epoch: verified.epoch, shards: verified.shards });
  if (record.budgetId !== budget.budgetId || record.epochRevision !== budget.epochRevision
      || record.inventorySha256 !== budget.inventorySha256
      || record.shardGenerationId !== budget.shardGenerationId
      || record.shardId !== budget.pilotShardId
      || record.shardPathListSha256 !== budget.shardPathListSha256
      || record.controlGenerationHash !== budget.controlGenerationHash
      || record.budgetSha256 !== budget.budgetSha256) {
    fail('pilot verdict does not bind the supplied pilot budget');
  }
  validateResultClaimRecord(resultClaim);
  if (record.attemptId !== resultClaim.attemptId || record.resultClaimId !== resultClaim.claimId
      || record.resultClaimHash !== resultClaim.claimHash || record.shardId !== resultClaim.shardId
      || record.epochRevision !== resultClaim.sourceRevision
      || record.controlGenerationHash !== resultClaim.controlGenerationHash) {
    fail('pilot verdict does not bind the supplied pilot result claim');
  }
  const includeRouteBudget = record.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT;
  assertRouteAuthorityMatches(record, admission, 'pilot verdict/admission', { includeBudget: includeRouteBudget });
  assertRouteAuthorityMatches(record, resultClaim, 'pilot verdict/result claim', { includeBudget: includeRouteBudget });
  if (budget.scanner.adapterVersion !== record.adapterVersion
      || budget.scanner.scannerSchemaVersion !== record.scannerSchemaVersion
      || budget.scanner.standardRoute !== record.standardRoute
      || budget.scanner.routeContractSha256 !== record.routeContractSha256
      || budget.scanner.pluginVersion !== record.pluginVersion
      || budget.scanner.targetForm !== record.targetForm
      || budget.scanner.targetKind !== record.targetKind
      || budget.scanner.productionEligible !== record.productionEligible) {
    fail('pilot verdict route authority does not match the immutable budget');
  }
  const derived = derivePilotEvaluation(verified, deepFallback);
  if (record.verdict !== derived.verdict
      || canonicalJson(record.checks) !== canonicalJson(derived.checks)
      || canonicalJson(record.measurements) !== canonicalJson(derived.measurements)
      || canonicalJson(record.reasonCodes) !== canonicalJson(derived.reasonCodes)
      || record.deepPromotionId !== derived.deepPromotionId
      || record.deepDirectoryTarget !== derived.deepDirectoryTarget) {
    fail('pilot verdict is not the mechanical projection of verified admission evidence');
  }
  return record;
}

export function buildPilotVerdictRecord(fields, options) {
  closed(fields, ['evaluatedAt'], [], 'pilot verdict builder input');
  const verified = admissionFromCapability(options?.admissionCapability);
  const deepFallback = options?.deepFallbackAuthority === undefined ? undefined
    : deepFallbackFromCapability(options.deepFallbackAuthority, options?.admissionCapability);
  const { admission, budget, resultClaim } = verified;
  if (budget === undefined) fail('pilot verdict requires an immutable budget bound into its admission capability');
  const derived = derivePilotEvaluation(verified, deepFallback);
  const route = Object.fromEntries(RECORD_ROUTE_FIELDS
    .filter((field) => Object.hasOwn(admission, field))
    .map((field) => [field, admission[field]]));
  return validatePilotVerdictRecord(withFixed({
    budgetId: budget.budgetId,
    attemptId: admission.attemptId,
    resultClaimId: resultClaim.claimId,
    resultClaimHash: resultClaim.claimHash,
    evaluatedAt: fields.evaluatedAt,
    epochRevision: budget.epochRevision,
    inventorySha256: budget.inventorySha256,
    shardGenerationId: budget.shardGenerationId,
    shardId: budget.pilotShardId,
    shardPathListSha256: budget.shardPathListSha256,
    controlGenerationHash: budget.controlGenerationHash,
    budgetSha256: budget.budgetSha256,
    ...route,
    ...derived,
  }, PILOT_VERDICT_SCHEMA, RECORD_ROLES.DERIVED), {
    admissionCapability: options?.admissionCapability,
    deepFallbackAuthority: options?.deepFallbackAuthority,
  });
}

function validateArtifactHash(value, name) {
  closed(value, ['artifactRef', 'sha256', 'size'], [], name);
  logicalRef(value.artifactRef, `${name}.artifactRef`);
  hash(value.sha256, `${name}.sha256`);
  count(value.size, `${name}.size`);
  return value;
}

function validateTokenUsage(value) {
  closed(value, ['availability'], ['value'], 'tokenUsage');
  oneOf(value.availability, ['unavailable', 'measured'], 'tokenUsage.availability');
  if (value.availability === 'unavailable' && Object.hasOwn(value, 'value')) fail('unavailable tokenUsage must not invent a value');
  if (value.availability === 'measured') count(value.value, 'tokenUsage.value', { positive: true });
  return value;
}

function hashRecord(record, field) {
  const copy = { ...record };
  delete copy[field];
  return sha256Hex(canonicalJson(copy));
}

export function validateResultClaimRecord(record) {
  topLevel(record, RESULT_CLAIM_SCHEMA, RECORD_ROLES.OPERATIONAL_CLAIM, [
    'claimId', 'claimHash', 'attemptId', 'sectionId', 'shardId', 'scanId', 'claimedAt',
    'scannerState', 'reviewedPathCount', 'missingPathCount',
    'claimedFileCoverage', 'claimedProofCompleteness', 'sourceRevision', 'sourceFingerprint',
    'controlGenerationHash', 'elapsedSeconds', 'artifactBytes', 'operatorSeconds',
    'peakRssBytes', 'freeBytesAfter', 'retryCount',
    'workerCount', 'tokenUsage', 'claimedObservationCount',
    'mode', 'adapterVersion', 'targetForm', 'targetKind', 'scannerSchemaVersion',
  ], ['bundleRef', 'bundleHash', 'artifacts', ...STANDARD_ROUTE_FIELDS], 'result claim record');
  for (const field of ['claimId', 'attemptId', 'scanId']) token(record[field], `result claim ${field}`);
  hash(record.claimHash, 'result claimHash');
  sectionId(record.sectionId);
  shardId(record.shardId);
  if (!record.shardId.startsWith(`${record.sectionId}/`)) fail('result claim shard does not belong to section');
  isoTime(record.claimedAt, 'result claimedAt');
  oneOf(record.scannerState, ['SEALED', 'TERMINAL_FAILED', 'CANCELED', 'COMPLETION_UNKNOWN'], 'result scannerState');
  if (record.scannerState === 'SEALED') {
    logicalRef(record.bundleRef, 'result bundleRef');
    hash(record.bundleHash, 'result bundleHash');
    if (!Array.isArray(record.artifacts) || record.artifacts.length === 0) fail('sealed result artifacts must be a non-empty array');
    record.artifacts.forEach((item, index) => validateArtifactHash(item, `artifacts[${index}]`));
    assertUnique(record.artifacts, (item) => item.artifactRef, 'result artifacts');
  } else if (Object.hasOwn(record, 'bundleRef') || Object.hasOwn(record, 'bundleHash') || Object.hasOwn(record, 'artifacts')) {
    fail('non-sealed result claims must not invent bundle or artifact references');
  }
  for (const field of ['reviewedPathCount', 'missingPathCount', 'workerCount', 'claimedObservationCount']) count(record[field], `result ${field}`);
  oneOf(record.claimedFileCoverage, ['none', 'partial', 'complete'], 'claimedFileCoverage');
  oneOf(record.claimedProofCompleteness, ['open', 'blocked', 'complete'], 'claimedProofCompleteness');
  if (record.claimedFileCoverage === 'none' && record.reviewedPathCount !== 0) fail('none file coverage contradicts reviewedPathCount');
  if (record.claimedFileCoverage === 'complete' && record.missingPathCount !== 0) fail('complete file coverage contradicts missingPathCount');
  if (record.scannerState !== 'SEALED' && record.claimedFileCoverage === 'complete') fail('non-sealed result cannot claim complete file coverage');
  objectId(record.sourceRevision, 'result sourceRevision');
  fingerprint(record.sourceFingerprint, 'result sourceFingerprint', record.sourceRevision);
  hash(record.controlGenerationHash, 'result controlGenerationHash');
  validateRecordRoute(record, 'result claim');
  finite(record.elapsedSeconds, 'result elapsedSeconds');
  count(record.artifactBytes, 'result artifactBytes');
  finite(record.operatorSeconds, 'result operatorSeconds');
  count(record.peakRssBytes, 'result peakRssBytes', { positive: true });
  count(record.freeBytesAfter, 'result freeBytesAfter');
  count(record.retryCount, 'result retryCount');
  validateTokenUsage(record.tokenUsage);
  const artifactBytes = (record.artifacts ?? []).reduce((sum, item) => sum + item.size, 0);
  if (!Number.isSafeInteger(artifactBytes) || artifactBytes !== record.artifactBytes) fail('result artifactBytes does not match artifact hashes');
  if (record.claimHash !== hashRecord(record, 'claimHash')) fail('result claimHash does not match record');
  return record;
}

export function buildResultClaimRecord(fields) {
  const record = withFixed({ ...fields, claimHash: '0'.repeat(64) }, RESULT_CLAIM_SCHEMA, RECORD_ROLES.OPERATIONAL_CLAIM);
  record.claimHash = hashRecord(record, 'claimHash');
  return validateResultClaimRecord(record);
}

function validateSourceKey(value) {
  closed(value, ['path'], ['line', 'symbol'], 'observation sourceKey');
  repositoryPath(value.path, 'observation sourceKey.path');
  if (value.line !== undefined) count(value.line, 'observation sourceKey.line', { positive: true });
  if (value.symbol !== undefined) {
    text(value.symbol, 'observation sourceKey.symbol', { max: 200, allowSpace: true });
    if (!/^[A-Za-z0-9_.:*()[\]-]+$/.test(value.symbol)) fail('observation source symbol must not contain prose or path separators');
  }
  return value;
}

export function validateObservationRecord(record) {
  topLevel(record, OBSERVATION_SCHEMA, RECORD_ROLES.AUTHORITY, [
    'recordId', 'recordHash', 'sourceKey', 'sectionId', 'attemptId', 'scanId',
    'bundleRef', 'type', 'disposition', 'observedAt',
  ], ['supersededByAttemptId'], 'observation record');
  for (const field of ['recordId', 'attemptId', 'scanId']) token(record[field], `observation ${field}`);
  hash(record.recordHash, 'observation recordHash');
  validateSourceKey(record.sourceKey);
  sectionId(record.sectionId);
  logicalRef(record.bundleRef, 'observation bundleRef');
  oneOf(record.type, ['finding', 'rejection', 'deferred', 'open-question'], 'observation type');
  oneOf(record.disposition, ['open', 'blocked', 'accepted', 'rejected', 'superseded', 'external-proof-gap'], 'observation disposition');
  isoTime(record.observedAt, 'observation observedAt');
  if (record.supersededByAttemptId !== undefined) token(record.supersededByAttemptId, 'observation supersededByAttemptId');
  if ((record.disposition === 'superseded') !== (record.supersededByAttemptId !== undefined)) {
    fail('observation supersession disposition and attempt link must agree');
  }
  if (record.recordHash !== hashRecord(record, 'recordHash')) fail('observation recordHash does not match record');
  return record;
}

export function buildObservationRecord(fields) {
  const record = withFixed({ ...fields, recordHash: '0'.repeat(64) }, OBSERVATION_SCHEMA, RECORD_ROLES.AUTHORITY);
  record.recordHash = hashRecord(record, 'recordHash');
  return validateObservationRecord(record);
}

export function validateObservationRecords(records, { liveAttemptIds = [] } = {}) {
  if (!Array.isArray(records)) fail('observation records must be an array');
  records.forEach(validateObservationRecord);
  assertUnique(records, (item) => item.recordId, 'observation records');
  assertUnique(records, (item) => item.recordHash, 'observation record hashes');
  const live = new Set(liveAttemptIds);
  const liveRecords = records.filter((item) => live.has(item.attemptId));
  assertUnique(liveRecords, (item) => canonicalJson({ type: item.type, sourceKey: item.sourceKey, attemptId: item.attemptId }), 'live observation identities');
  return records;
}

export function validateReviewedSetRecord(record) {
  topLevel(record, REVIEWED_SET_SCHEMA, RECORD_ROLES.VERIFIED_EVIDENCE, [
    'evidenceId', 'attemptId', 'sectionId', 'shardId', 'scanId', 'verifiedAt',
    'bundleRef', 'bundleHash',
    'sourceRevision', 'inventorySha256', 'sourceFingerprint', 'controlGenerationHash',
    'sealed', 'hashesValid', 'sourceFingerprintMatches', 'reviewedPathsPresent',
  ], ['reviewedPaths'], 'reviewed set record');
  for (const field of ['evidenceId', 'attemptId', 'scanId']) token(record[field], `reviewed set ${field}`);
  sectionId(record.sectionId);
  shardId(record.shardId);
  if (!record.shardId.startsWith(`${record.sectionId}/`)) fail('reviewed set shard does not belong to section');
  isoTime(record.verifiedAt, 'reviewed set verifiedAt');
  logicalRef(record.bundleRef, 'reviewed set bundleRef');
  hash(record.bundleHash, 'reviewed set bundleHash');
  objectId(record.sourceRevision, 'reviewed set sourceRevision');
  hash(record.inventorySha256, 'reviewed set inventorySha256');
  fingerprint(record.sourceFingerprint, 'reviewed set sourceFingerprint', record.sourceRevision);
  hash(record.controlGenerationHash, 'reviewed set controlGenerationHash');
  for (const field of ['sealed', 'hashesValid', 'sourceFingerprintMatches', 'reviewedPathsPresent']) bool(record[field], `reviewed set ${field}`);
  if (record.reviewedPathsPresent) {
    if (!Array.isArray(record.reviewedPaths) || record.reviewedPaths.length === 0) fail('present reviewed set must contain paths');
    record.reviewedPaths.forEach((item, index) => repositoryPath(item, `reviewedPaths[${index}]`));
    assertUnique(record.reviewedPaths, (item) => item, 'reviewedPaths');
    assertByteSorted(record.reviewedPaths, (item) => item, 'reviewedPaths');
  } else if (Object.hasOwn(record, 'reviewedPaths')) {
    fail('missing reviewed set must omit reviewedPaths rather than use an empty or guessed list');
  }
  return record;
}

export function buildReviewedSetRecord(fields) {
  return validateReviewedSetRecord(withFixed(fields, REVIEWED_SET_SCHEMA, RECORD_ROLES.VERIFIED_EVIDENCE));
}

export function validateReviewedSetExtension(extensions) {
  if (extensions === null || typeof extensions !== 'object' || Array.isArray(extensions)) {
    schemaUnsupported('canonical coverage extensions must be an object');
  }
  const keys = Object.keys(extensions);
  if (keys.length !== 1 || keys[0] !== REVIEWED_SET_EXTENSION_KEY) {
    schemaUnsupported('canonical coverage must contain only the pinned Setjoin reviewed-set extension');
  }
  const extension = extensions[REVIEWED_SET_EXTENSION_KEY];
  try {
    closed(extension, ['fully_reviewed_files', 'count', 'path_list_sha256'], [], 'reviewed-set extension');
  } catch (error) {
    if (error instanceof SecurityProgramError) {
      schemaUnsupported('canonical reviewed-set extension member names are unsupported');
    }
    throw error;
  }
  if (!Array.isArray(extension.fully_reviewed_files)) {
    schemaUnsupported('canonical reviewed-set extension fully_reviewed_files must be an array');
  }
  const reviewedFiles = [...extension.fully_reviewed_files];
  reviewedFiles.forEach((item, index) => repositoryPath(item, `reviewed-set extension fully_reviewed_files[${index}]`));
  assertUnique(reviewedFiles, (item) => item, 'reviewed-set extension fully_reviewed_files');
  assertByteSorted(reviewedFiles, (item) => item, 'reviewed-set extension fully_reviewed_files');
  count(extension.count, 'reviewed-set extension count');
  hash(extension.path_list_sha256, 'reviewed-set extension path_list_sha256');
  if (extension.count !== reviewedFiles.length
      || extension.path_list_sha256 !== hashReviewedFilePaths(reviewedFiles)) {
    fail('canonical reviewed-set extension count or framed path-list hash does not match');
  }
  return Object.freeze({
    reviewedFiles: Object.freeze(reviewedFiles),
    count: extension.count,
    pathListSha256: extension.path_list_sha256,
  });
}

export function validateAdmissionInputRecord(record) {
  topLevel(record, ADMISSION_INPUT_SCHEMA, RECORD_ROLES.VERIFIED_EVIDENCE, [
    'admissionId', 'admittedAt', 'attemptId', 'sectionId', 'shardId', 'scanId',
    'journalEventId', 'journalEventHash', 'journalState',
    'bundleRef', 'bundleHash', 'verifiedBundleHash',
    'controlGenerationHash', 'currentControlGenerationHash',
    'inventorySha256', 'shardGenerationId', 'shardPathCount', 'shardPathListSha256',
    'targetArtifactSha256', 'targetPathCount', 'targetPathListSha256',
    'sourceRevision', 'currentSourceRevision',
    'sourceFingerprint', 'currentSourceFingerprint',
    'mode', 'adapterVersion', 'targetForm', 'targetKind', 'scannerSchemaVersion',
  ], STANDARD_ROUTE_FIELDS, 'admission input record');
  for (const field of ['admissionId', 'attemptId', 'scanId', 'journalEventId']) {
    token(record[field], `admission ${field}`);
  }
  isoTime(record.admittedAt, 'admission admittedAt');
  sectionId(record.sectionId, 'admission sectionId');
  shardId(record.shardId, 'admission shardId');
  if (!record.shardId.startsWith(`${record.sectionId}/`)) fail('admission shard does not belong to section');
  hash(record.journalEventHash, 'admission journalEventHash');
  if (record.journalState !== 'ADMITTED') fail('admission requires an ADMITTED attempt-journal state');
  logicalRef(record.bundleRef, 'admission bundleRef');
  hash(record.bundleHash, 'admission bundleHash');
  hash(record.verifiedBundleHash, 'admission verifiedBundleHash');
  hash(record.controlGenerationHash, 'admission controlGenerationHash');
  hash(record.currentControlGenerationHash, 'admission currentControlGenerationHash');
  hash(record.inventorySha256, 'admission inventorySha256');
  version(record.shardGenerationId, 'admission shardGenerationId');
  count(record.shardPathCount, 'admission shardPathCount', { positive: true });
  hash(record.shardPathListSha256, 'admission shardPathListSha256');
  hash(record.targetArtifactSha256, 'admission targetArtifactSha256');
  count(record.targetPathCount, 'admission targetPathCount', { positive: true });
  hash(record.targetPathListSha256, 'admission targetPathListSha256');
  objectId(record.sourceRevision, 'admission sourceRevision');
  objectId(record.currentSourceRevision, 'admission currentSourceRevision');
  fingerprint(record.sourceFingerprint, 'admission sourceFingerprint', record.sourceRevision);
  fingerprint(record.currentSourceFingerprint, 'admission currentSourceFingerprint', record.currentSourceRevision);
  validateRecordRoute(record, 'admission');
  if (record.bundleHash !== record.verifiedBundleHash) fail('admission bundle hash is not verified');
  if (record.controlGenerationHash !== record.currentControlGenerationHash) fail('admission control generation is stale');
  if (record.sourceRevision !== record.currentSourceRevision
      || record.sourceFingerprint !== record.currentSourceFingerprint) fail('admission source proof is stale');
  return record;
}

function stableFileSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mode === right.mode && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function canonicalFileIdentity(attemptsDirectory, attemptId, relativePath) {
  const filename = path.join(attemptsDirectory, attemptId, 'canonical', ...relativePath.split('/'));
  const stat = fs.lstatSync(filename, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`canonical ${relativePath} must be a regular file`);
  return Object.freeze({
    path: relativePath,
    dev: stat.dev,
    ino: stat.ino,
    size: stat.size,
    mode: stat.mode,
    mtimeNs: stat.mtimeNs,
    ctimeNs: stat.ctimeNs,
  });
}

function sameCanonicalFileIdentity(left, right) {
  return left.path === right.path && stableFileSnapshot(left, right);
}

function detachedJson(value) {
  return value === undefined ? undefined : parseStrictJson(canonicalJson(value));
}

function readHashVerifiedCanonicalJson({ attemptsDirectory, attemptId, receipt, relativePath }) {
  const receiptEntry = receipt.files.find((entry) => entry.path === relativePath);
  if (!receiptEntry) fail(`immutable bundle omits required canonical ${relativePath}`);
  if (receiptEntry.size > 32 * 1024 * 1024) fail(`canonical ${relativePath} exceeds the bounded structured-artifact size`);
  const filename = path.join(attemptsDirectory, attemptId, 'canonical', ...relativePath.split('/'));
  const beforePath = fs.lstatSync(filename, { bigint: true });
  if (!beforePath.isFile() || beforePath.isSymbolicLink()) fail(`canonical ${relativePath} must be a regular file`);
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!stableFileSnapshot(beforePath, before)) fail(`canonical ${relativePath} changed before parsing`);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    const afterPath = fs.lstatSync(filename, { bigint: true });
    if (!stableFileSnapshot(before, after) || !stableFileSnapshot(after, afterPath)
        || bytes.length !== receiptEntry.size || sha256Hex(bytes) !== receiptEntry.sha256) {
      fail(`canonical ${relativePath} changed or does not match the immutable receipt`);
    }
    return parseStrictJson(bytes.toString('utf8'));
  } finally {
    fs.closeSync(descriptor);
  }
}

function canonicalCoverageAuthority(coverage, manifest, admission, receipt, expectedShardPaths) {
  closed(manifest, ['schemaVersion', 'documentType', 'scan'], [], 'canonical scan manifest');
  closed(manifest.scan, [
    'id', 'producer', 'status', 'startedAt', 'completedAt', 'sealedAt', 'target', 'scope',
    'coverageRef', 'findingsRef', 'artifacts',
  ], ['threatModel', 'hardening', 'preservedSources'], 'canonical manifest scan');
  closed(manifest.scan.producer, ['name', 'version'], [], 'canonical manifest producer');
  closed(manifest.scan.target, ['kind', 'targetId', 'displayName'], [
    'remote', 'revision', 'baseRevision', 'headRevision', 'snapshotDigest',
  ], 'canonical manifest target');
  closed(manifest.scan.scope, ['includePaths', 'excludePaths'], [
    'summary', 'artifactsReviewed', 'runtimeStatus', 'validationMode', 'context', 'limitations',
    'scope', 'targetPath', 'contexts', 'reducerInputs', 'runtimeStatuses', 'sourceScopes',
    'sourceSnapshots', 'validationModes',
  ], 'canonical manifest scope');
  token(manifest.scan.id, 'canonical manifest scan id');
  text(manifest.scan.target.targetId, 'canonical manifest targetId', { allowSpace: true });
  text(manifest.scan.target.displayName, 'canonical manifest displayName', { allowSpace: true });
  isoTime(manifest.scan.startedAt, 'canonical manifest startedAt');
  isoTime(manifest.scan.completedAt, 'canonical manifest completedAt');
  isoTime(manifest.scan.sealedAt, 'canonical manifest sealedAt');
  if (manifest.schemaVersion !== '1.0' || manifest.documentType !== 'codex-security.scan-manifest'
      || manifest.scan.status !== 'completed' || manifest.scan.target.kind !== admission.targetKind
      || manifest.scan.coverageRef !== 'coverage.json' || manifest.scan.findingsRef !== 'findings.json'
      || !Array.isArray(manifest.scan.scope.includePaths) || !Array.isArray(manifest.scan.scope.excludePaths)
      || timestampSortKey(manifest.scan.completedAt) < timestampSortKey(manifest.scan.startedAt)
      || timestampSortKey(manifest.scan.sealedAt) < timestampSortKey(manifest.scan.completedAt)
      || !Array.isArray(manifest.scan.artifacts)) {
    fail('canonical scan manifest is not sealed structured evidence');
  }
  if (manifest.scan.id !== admission.scanId) {
    fail('canonical scan manifest does not bind the admitted scan');
  }
  if (manifest.scan.producer.name !== 'codex-security-plugin'
      || manifest.scan.producer.version !== admission.pluginVersion
      || admission.pluginVersion !== '0.1.24') {
    schemaUnsupported('canonical scan manifest producer version does not match the admitted plugin');
  }
  const expectedScope = admission.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT
    ? ['.'] : expectedShardPaths;
  if (admission.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT) {
    if (Object.hasOwn(manifest.scan.target, 'revision')
        || manifest.scan.target.snapshotDigest !== admission.directorySnapshotDigest
        || manifest.scan.scope.excludePaths.length !== 0
        || canonicalJson(manifest.scan.scope.includePaths) !== canonicalJson(expectedScope)) {
      fail('canonical Desktop target does not bind the admitted read-only directory snapshot');
    }
  } else {
    objectId(manifest.scan.target.revision, 'canonical manifest revision');
    if (manifest.scan.target.revision !== admission.sourceRevision
        || Object.hasOwn(manifest.scan.target, 'snapshotDigest')
        || canonicalJson(manifest.scan.scope.includePaths) !== canonicalJson(expectedScope)
        || manifest.scan.scope.excludePaths.length !== 0) {
      fail('canonical SDK exact-path target does not bind the admitted Git revision and shard scope');
    }
  }
  const artifactPaths = manifest.scan.artifacts.map((artifact, index) => {
    closed(artifact, ['path', 'sha256', 'mediaType'], [], `canonical manifest artifact[${index}]`);
    repositoryPath(artifact.path, `canonical manifest artifact[${index}].path`);
    hash(artifact.sha256, `canonical manifest artifact[${index}].sha256`);
    text(artifact.mediaType, `canonical manifest artifact[${index}].mediaType`, { allowSpace: true });
    const receiptEntry = receipt.files.find((entry) => entry.path === artifact.path);
    if (!receiptEntry || receiptEntry.sha256 !== artifact.sha256
        || artifact.mediaType !== 'application/json') {
      fail('canonical manifest artifact hash does not match the immutable bundle receipt');
    }
    return artifact.path;
  }).sort(compareBytes);
  if (canonicalJson(artifactPaths) !== canonicalJson(['coverage.json', 'findings.json'])) {
    fail('canonical manifest must bind exactly the structured coverage and findings artifacts');
  }
  closed(coverage, [
    'documentType', 'schemaVersion', 'scanId', 'mode', 'completeness', 'inventoryStrategy',
    'includePaths', 'excludePaths', 'surfaces', 'explicitExclusions', 'deferred', 'extensions',
  ], ['openQuestions'], 'canonical coverage');
  if (coverage.documentType !== 'codex-security.coverage' || coverage.schemaVersion !== '1.0'
      || !['complete', 'partial'].includes(coverage.completeness)
      || !Array.isArray(coverage.includePaths) || !Array.isArray(coverage.excludePaths)
      || !Array.isArray(coverage.surfaces) || !Array.isArray(coverage.explicitExclusions)
      || !Array.isArray(coverage.deferred)) {
    fail('canonical coverage required fields are malformed');
  }
  token(coverage.scanId, 'canonical coverage scanId');
  const expectedMode = admission.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT
    ? 'repository' : 'scoped_path';
  const expectedInventoryStrategy = admission.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT
    ? 'directory' : 'scoped_path';
  if (coverage.scanId !== admission.scanId || coverage.mode !== expectedMode
      || coverage.inventoryStrategy !== expectedInventoryStrategy
      || canonicalJson(coverage.includePaths) !== canonicalJson(manifest.scan.scope.includePaths)
      || canonicalJson(coverage.excludePaths) !== canonicalJson(manifest.scan.scope.excludePaths)
      || canonicalJson(coverage.includePaths) !== canonicalJson(expectedScope)
      || coverage.excludePaths.length !== 0 || coverage.explicitExclusions.length !== 0
      || coverage.deferred.length !== 0
      || coverage.surfaces.some((surface) => surface?.disposition === 'needs_follow_up')) {
    fail('canonical coverage does not bind the admitted route, scope, and complete exclusion posture');
  }
  const extension = validateReviewedSetExtension(coverage.extensions);
  const reviewedFiles = [...extension.reviewedFiles];
  if (admission.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT
      && (coverage.completeness !== 'complete'
        || canonicalJson(reviewedFiles) !== canonicalJson(expectedShardPaths))) {
    fail('Desktop attested-export admission requires complete review of the exact shard');
  }
  return Object.freeze({ reviewedFiles: Object.freeze(reviewedFiles), completeness: coverage.completeness });
}

export function issueVerifiedAdmissionCapability({
  admission,
  resultClaim,
  budget,
  epoch,
  shards,
  target,
  journalPath,
  attemptsDirectory,
} = {}) {
  validateAdmissionInputRecord(admission);
  validateResultClaimRecord(resultClaim);
  if (epoch === undefined || shards === undefined || target === undefined) {
    fail('verified admission requires live epoch, shard, and opaque target authority');
  }
  if (typeof journalPath !== 'string' || journalPath.length === 0
      || typeof attemptsDirectory !== 'string' || attemptsDirectory.length === 0) {
    fail('verified admission requires live journal and immutable-bundle locations');
  }
  const events = loadAttemptJournal(journalPath);
  if (!Array.isArray(events) || events.length === 0) fail('verified admission journal is empty or invalid');
  events.forEach(validateAttemptEvent);
  const matchingEvents = events.filter((event) => event.attemptId === admission.attemptId);
  if (matchingEvents.length === 0) fail('verified admission does not exist in the live journal');
  const latest = matchingEvents.reduce((left, right) => left.sequence > right.sequence ? left : right);
  validateAttemptAuthority(latest, { epoch, shards, target });
  if (latest.state !== 'ADMITTED' || latest.eventId !== admission.journalEventId
      || sha256Hex(canonicalJson(latest)) !== admission.journalEventHash
      || latest.sectionId !== admission.sectionId || latest.shardId !== admission.shardId
      || latest.scanId !== admission.scanId
      || latest.controlGenerationHash !== admission.controlGenerationHash
      || latest.epochRevision !== admission.sourceRevision
      || latest.sourceFingerprint !== admission.sourceFingerprint
      || latest.inventorySha256 !== admission.inventorySha256
      || latest.shardGenerationId !== admission.shardGenerationId
      || latest.shardPathCount !== admission.shardPathCount
      || latest.shardPathListSha256 !== admission.shardPathListSha256
      || latest.targetArtifactSha256 !== admission.targetArtifactSha256
      || latest.targetPathCount !== admission.targetPathCount
      || latest.targetPathListSha256 !== admission.targetPathListSha256) {
    fail('verified admission contradicts the live ADMITTED journal event');
  }
  assertRouteAuthorityMatches(admission, latest, 'admission/journal', {
    includeProductionEligibility: admission.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT,
  });
  if (resultClaim.attemptId !== admission.attemptId || resultClaim.sectionId !== admission.sectionId
      || resultClaim.shardId !== admission.shardId || resultClaim.scanId !== admission.scanId
      || resultClaim.scannerState !== 'SEALED' || resultClaim.bundleRef !== admission.bundleRef
      || resultClaim.bundleHash !== admission.bundleHash
      || resultClaim.sourceRevision !== admission.sourceRevision
      || resultClaim.sourceFingerprint !== admission.sourceFingerprint
      || resultClaim.controlGenerationHash !== admission.controlGenerationHash) {
    fail('verified admission contradicts its sealed result claim');
  }
  assertRouteAuthorityMatches(admission, resultClaim, 'admission/result claim');
  const routeAuthority = preparedRouteAuthority(target, latest.scannerSchemaVersion);
  assertRouteAuthorityMatches(admission, routeAuthority, 'admission/target');
  if (admission.standardRoute === STANDARD_TARGET_ROUTES.DESKTOP_ATTESTED_EXPORT) {
    validatePilotBudgetBindings(budget, { epoch, shards });
    if (budget.budgetId !== admission.budgetId || budget.budgetSha256 !== admission.budgetSha256
        || budget.scanner.standardRoute !== admission.standardRoute
        || budget.scanner.routeContractSha256 !== admission.routeContractSha256
        || budget.scanner.pluginVersion !== admission.pluginVersion
        || budget.scanner.adapterVersion !== admission.adapterVersion
        || budget.scanner.scannerSchemaVersion !== admission.scannerSchemaVersion
        || budget.scanner.targetForm !== admission.targetForm
        || budget.scanner.targetKind !== admission.targetKind
        || budget.scanner.productionEligible !== admission.productionEligible
        || canonicalJson(budget.exportCapacity) !== canonicalJson(admission.exportCapacity)) {
      fail('verified Desktop admission contradicts its immutable pilot budget');
    }
  } else if (budget !== undefined) {
    validatePilotBudgetBindings(budget, { epoch, shards });
    if (budget.scanner.standardRoute !== admission.standardRoute
        || budget.scanner.routeContractSha256 !== admission.routeContractSha256
        || budget.scanner.pluginVersion !== admission.pluginVersion
        || budget.scanner.adapterVersion !== admission.adapterVersion
        || budget.scanner.scannerSchemaVersion !== admission.scannerSchemaVersion
        || budget.scanner.targetForm !== admission.targetForm
        || budget.scanner.targetKind !== admission.targetKind
        || budget.scanner.productionEligible !== admission.productionEligible) {
      fail('verified admission route contradicts its immutable pilot budget');
    }
  }
  const receipt = verifyImmutableBundle({ attemptsDirectory, attemptId: admission.attemptId });
  if (admission.bundleRef !== `attempt:${admission.attemptId}` || receipt.bundleHash !== admission.bundleHash) {
    fail('verified admission contradicts the immutable bundle publication');
  }
  const retainedArtifacts = receipt.files.map((entry) => ({
    artifactRef: `attempt-file:${admission.attemptId}/${entry.path}`,
    sha256: entry.sha256,
    size: entry.size,
  })).sort((left, right) => compareBytes(left.artifactRef, right.artifactRef));
  const claimedArtifacts = [...resultClaim.artifacts]
    .sort((left, right) => compareBytes(left.artifactRef, right.artifactRef));
  if (canonicalJson(claimedArtifacts) !== canonicalJson(retainedArtifacts)
      || resultClaim.artifactBytes !== retainedArtifacts.reduce((sum, item) => sum + item.size, 0)) {
    fail('sealed result artifact measurements do not exactly match the immutable bundle receipt');
  }
  const manifest = readHashVerifiedCanonicalJson({
    attemptsDirectory, attemptId: admission.attemptId, receipt, relativePath: 'scan-manifest.json',
  });
  const coverage = readHashVerifiedCanonicalJson({
    attemptsDirectory, attemptId: admission.attemptId, receipt, relativePath: 'coverage.json',
  });
  const shard = shards.shards.find((item) => item.id === admission.shardId);
  const expectedShardPaths = shard.paths.map((item) => item.path);
  const canonical = canonicalCoverageAuthority(coverage, manifest, admission, receipt, expectedShardPaths);
  const shardPathSet = new Set(expectedShardPaths);
  const expectedMissingPathCount = expectedShardPaths.length - canonical.reviewedFiles.length;
  const expectedFileCoverage = canonical.reviewedFiles.length === 0 ? 'none'
    : (expectedMissingPathCount === 0 ? 'complete' : 'partial');
  if (canonical.reviewedFiles.some((pathname) => !shardPathSet.has(pathname))
      || expectedMissingPathCount < 0
      || resultClaim.reviewedPathCount !== canonical.reviewedFiles.length
      || resultClaim.missingPathCount !== expectedMissingPathCount
      || resultClaim.claimedFileCoverage !== expectedFileCoverage
      || (canonical.completeness === 'complete') !== (expectedFileCoverage === 'complete')) {
    fail('sealed result coverage claim does not exactly match the canonical reviewed set and admitted shard');
  }
  const capability = Object.freeze(Object.create(null));
  const canonicalFileIdentities = Object.freeze(['scan-manifest.json', 'coverage.json']
    .map((relativePath) => canonicalFileIdentity(attemptsDirectory, admission.attemptId, relativePath)));
  verifiedAdmissionCapabilities.set(capability, Object.freeze({
    admission: Object.freeze(detachedJson(admission)),
    resultClaim: Object.freeze(detachedJson(resultClaim)),
    budget: budget === undefined ? undefined : Object.freeze(detachedJson(budget)),
    epoch: Object.freeze(detachedJson(epoch)),
    shards: Object.freeze(detachedJson(shards)),
    events: Object.freeze(detachedJson(matchingEvents)),
    target,
    journalPath,
    attemptsDirectory,
    canonicalFileIdentities,
    resultClaimId: resultClaim.claimId,
    resultClaimHash: resultClaim.claimHash,
    reviewedFiles: canonical.reviewedFiles,
    completeness: canonical.completeness,
    verification: Object.freeze({ sealed: true, hashesValid: true, canonicalFilesStable: true }),
  }));
  return capability;
}

function admissionFromCapability(capability) {
  const issued = verifiedAdmissionCapabilities.get(capability);
  if (issued === undefined) {
    fail('reconciliation requires an in-process live-verified admission capability');
  }
  const replayCapability = issueVerifiedAdmissionCapability({
    admission: issued.admission,
    resultClaim: issued.resultClaim,
    budget: issued.budget,
    epoch: issued.epoch,
    shards: issued.shards,
    target: issued.target,
    journalPath: issued.journalPath,
    attemptsDirectory: issued.attemptsDirectory,
  });
  const replayed = verifiedAdmissionCapabilities.get(replayCapability);
  if (replayed.canonicalFileIdentities.length !== issued.canonicalFileIdentities.length
      || replayed.canonicalFileIdentities.some((identity, index) => (
        !sameCanonicalFileIdentity(identity, issued.canonicalFileIdentities[index])
      ))) {
    fail('canonical admission files were replaced or changed after capability issuance');
  }
  return replayed;
}

export function validateDeepPromotionRecord(record) {
  topLevel(record, DEEP_PROMOTION_SCHEMA, RECORD_ROLES.AUTHORITY, [
    'promotionId', 'recordHash', 'createdAt', 'sectionId', 'targetDirectory',
    'reasonCodes', 'standardEvidenceRefs', 'programPromotionCap',
    'deepRunCap', 'deepScanMaxTimeHours', 'state', 'conflictCount', 'disposition',
  ], ['attemptId', 'supersededByPromotionId'], 'Deep promotion record');
  token(record.promotionId, 'promotionId');
  hash(record.recordHash, 'promotion recordHash');
  isoTime(record.createdAt, 'promotion createdAt');
  sectionId(record.sectionId);
  repositoryPath(record.targetDirectory, 'promotion targetDirectory');
  if (!Array.isArray(record.reasonCodes) || record.reasonCodes.length === 0) fail('promotion reasonCodes must be non-empty');
  record.reasonCodes.forEach((item, index) => token(item, `promotion reasonCodes[${index}]`));
  assertUnique(record.reasonCodes, (item) => item, 'promotion reasonCodes');
  if (!Array.isArray(record.standardEvidenceRefs) || record.standardEvidenceRefs.length === 0) fail('promotion requires Standard evidence references');
  record.standardEvidenceRefs.forEach((item, index) => logicalRef(item, `promotion evidence[${index}]`));
  assertUnique(record.standardEvidenceRefs, (item) => item, 'promotion evidence');
  if (record.programPromotionCap !== 8 || record.deepRunCap !== 1 || record.deepScanMaxTimeHours !== 6) {
    fail('promotion caps must match the approved eight-directory, one-run, six-hour policy');
  }
  oneOf(record.state, ['PLANNED', 'ATTEMPT_ACTIVE', 'COMPLETED', 'BLOCKED'], 'promotion state');
  count(record.conflictCount, 'promotion conflictCount');
  oneOf(record.disposition, ['pending', 'corroborates', 'conflicts', 'unique-evidence', 'blocked'], 'promotion disposition');
  if (record.attemptId !== undefined) token(record.attemptId, 'promotion attemptId');
  if (record.supersededByPromotionId !== undefined) token(record.supersededByPromotionId, 'promotion supersededByPromotionId');
  if (['ATTEMPT_ACTIVE', 'COMPLETED'].includes(record.state) && record.attemptId === undefined) fail('active or completed promotion requires attemptId');
  if (record.state === 'COMPLETED' && record.disposition === 'pending') fail('completed promotion requires a terminal disposition');
  if ((record.conflictCount > 0) !== (record.disposition === 'conflicts')) fail('promotion conflict count and disposition contradict');
  if (record.recordHash !== hashRecord(record, 'recordHash')) fail('promotion recordHash does not match record');
  return record;
}

export function buildDeepPromotionRecord(fields) {
  const record = withFixed({ ...fields, recordHash: '0'.repeat(64) }, DEEP_PROMOTION_SCHEMA, RECORD_ROLES.AUTHORITY);
  record.recordHash = hashRecord(record, 'recordHash');
  return validateDeepPromotionRecord(record);
}

export function validateDeepPromotions(records) {
  if (!Array.isArray(records)) fail('Deep promotions must be an array');
  records.forEach(validateDeepPromotionRecord);
  assertUnique(records, (item) => item.promotionId, 'Deep promotions');
  const live = records.filter((item) => item.supersededByPromotionId === undefined);
  assertUnique(live, (item) => item.targetDirectory, 'live Deep promotion targets');
  if (live.length > 8) fail('Deep promotions exceed the approved cap of eight directories');
  return records;
}

function verifyDeepFallbackAuthorityInputs({
  standardAdmissionCapability,
  promotions,
  promotionId,
  target,
}) {
  const standard = admissionFromCapability(standardAdmissionCapability);
  if (standard.budget === undefined) fail('Deep fallback authority requires the immutable Standard pilot budget');
  const standardEvaluation = derivePilotEvaluation(standard);
  const fallbackBasis = pilotFallbackSafetyPass(standardEvaluation.checks)
    && (!pilotCreditDefensible(standardEvaluation.checks)
      || !standardEvaluation.checks.standardEconomical);
  if (!fallbackBasis) {
    fail('Deep fallback authority lacks a safe verified Standard fallback basis');
  }
  validateDeepPromotions(promotions);
  token(promotionId, 'Deep fallback promotionId');
  const promotion = promotions.find((item) => item.promotionId === promotionId);
  if (promotion === undefined || promotion.supersededByPromotionId !== undefined
      || promotion.state !== 'PLANNED' || promotion.disposition !== 'pending'
      || promotion.attemptId !== undefined) {
    fail('Deep fallback requires one live, unstarted, planned promotion authority');
  }
  if (promotion.sectionId !== standard.admission.sectionId
      || !promotion.standardEvidenceRefs.includes(`claim:${standard.resultClaim.claimId}`)) {
    fail('Deep fallback promotion does not bind the verified Standard pilot evidence');
  }
  const expectedReasons = [
    ...(!pilotCreditDefensible(standardEvaluation.checks) ? ['STANDARD_EVIDENCE_NOT_DEFENSIBLE'] : []),
    ...(!standardEvaluation.checks.standardEconomical ? ['STANDARD_UNECONOMICAL'] : []),
  ];
  if (!expectedReasons.some((reason) => promotion.reasonCodes.includes(reason))) {
    fail('Deep fallback promotion does not state its mechanically verified fallback basis');
  }
  if (promotion.deepScanMaxTimeHours !== standard.budget.scanner.deepScanMaxTimeHours) {
    fail('Deep fallback promotion changes the preregistered Deep time cap');
  }
  const targetAuthority = verifyPreparedTarget(target);
  const shard = standard.shards.shards.find((item) => item.id === standard.admission.shardId);
  if (target?.mode !== 'deep' || target.scope !== '.'
      || target.revision !== standard.admission.sourceRevision
      || target.shardId !== standard.admission.shardId
      || target.pathCount !== shard?.pathCount
      || target.pathListSha256 !== shard?.pathListSha256
      || targetAuthority.pathCount !== shard?.pathCount
      || targetAuthority.pathListSha256 !== shard?.pathListSha256) {
    fail('Deep fallback target is not the exact verified real-directory pilot shard');
  }
  const normalizedDirectory = promotion.targetDirectory.split('/').join(path.sep);
  if (!target.targetPath.endsWith(`${path.sep}${normalizedDirectory}`)
      || shard.paths.some((entry) => !entry.path.startsWith(`${promotion.targetDirectory}/`))) {
    fail('Deep fallback target directory does not exactly match its promotion authority');
  }
  return Object.freeze({
    standard,
    promotion: Object.freeze(detachedJson(promotion)),
    target,
    targetAuthority: Object.freeze(detachedJson(targetAuthority)),
  });
}

export function issueVerifiedDeepFallbackAuthority(inputs = {}) {
  const verified = verifyDeepFallbackAuthorityInputs(inputs);
  const capability = Object.freeze(Object.create(null));
  verifiedDeepFallbackAuthorities.set(capability, Object.freeze({
    standardAdmissionCapability: inputs.standardAdmissionCapability,
    promotions: Object.freeze(detachedJson(inputs.promotions)),
    promotionId: inputs.promotionId,
    target: inputs.target,
    targetAuthority: verified.targetAuthority,
  }));
  return capability;
}

function deepFallbackFromCapability(capability, standardAdmissionCapability) {
  const issued = verifiedDeepFallbackAuthorities.get(capability);
  if (issued === undefined || issued.standardAdmissionCapability !== standardAdmissionCapability) {
    fail('pilot verdict requires an in-process Deep fallback authority bound to this Standard admission');
  }
  const replayed = verifyDeepFallbackAuthorityInputs({
    standardAdmissionCapability,
    promotions: issued.promotions,
    promotionId: issued.promotionId,
    target: issued.target,
  });
  if (canonicalJson(replayed.targetAuthority) !== canonicalJson(issued.targetAuthority)) {
    fail('Deep fallback target authority changed after capability issuance');
  }
  return replayed;
}

function validateDeltaPath(value, name) {
  closed(value, ['path', 'change', 'disposition'], [], name);
  repositoryPath(value.path, `${name}.path`);
  oneOf(value.change, ['added', 'modified', 'deleted', 'renamed'], `${name}.change`);
  oneOf(value.disposition, ['standard-review', 'security-diff', 'non-impact', 'deleted-history', 'pure-move', 'open'], `${name}.disposition`);
  return value;
}

function validateOverlap(value, name) {
  closed(value, ['path', 'attemptIds'], [], name);
  repositoryPath(value.path, `${name}.path`);
  if (!Array.isArray(value.attemptIds) || value.attemptIds.length < 2) fail(`${name}.attemptIds must identify at least two attempts`);
  value.attemptIds.forEach((item, index) => token(item, `${name}.attemptIds[${index}]`));
  assertUnique(value.attemptIds, (item) => item, `${name}.attemptIds`);
  return value;
}

function validateClaimedSummary(value) {
  closed(value, ['state', 'completeClaimCount', 'partialClaimCount', 'noneClaimCount'], [], 'reconciliation claimed');
  oneOf(value.state, ['NONE', 'PARTIAL', 'COMPLETE'], 'claimed state');
  for (const field of ['completeClaimCount', 'partialClaimCount', 'noneClaimCount']) count(value[field], `claimed.${field}`);
  const total = value.completeClaimCount + value.partialClaimCount + value.noneClaimCount;
  const expected = total === 0 || value.completeClaimCount === 0 ? (total === 0 ? 'NONE' : 'PARTIAL')
    : (value.partialClaimCount === 0 && value.noneClaimCount === 0 ? 'COMPLETE' : 'PARTIAL');
  if (value.state !== expected) fail('claimed reconciliation state contradicts claim counts');
  return value;
}

function validateVerifiedSummary(value) {
  closed(value, ['fileCoverage', 'proofCompleteness', 'gateVerdict', 'blockerCodes'], [], 'reconciliation verified');
  oneOf(value.fileCoverage, ['none', 'partial', 'complete'], 'verified fileCoverage');
  oneOf(value.proofCompleteness, ['open', 'blocked', 'complete'], 'verified proofCompleteness');
  oneOf(value.gateVerdict, ['PASS', 'HOLD'], 'verified gateVerdict');
  if (!Array.isArray(value.blockerCodes)) fail('verified blockerCodes must be an array');
  value.blockerCodes.forEach((item, index) => token(item, `verified blockerCodes[${index}]`));
  assertUnique(value.blockerCodes, (item) => item, 'verified blockerCodes');
  if ((value.gateVerdict === 'PASS') !== (value.blockerCodes.length === 0)) fail('verified gate and blockers contradict');
  return value;
}

export function validateReconciliationRecord(record) {
  topLevel(record, RECONCILIATION_SCHEMA, RECORD_ROLES.DERIVED, [
    'generationId', 'generatedAt', 'epochRevision', 'inventorySha256', 'authorizedCount',
    'uniqueReviewedCount', 'reviewedPaths', 'missingPaths', 'overlaps', 'outsideEpochPaths',
    'crossSectionPaths', 'outOfShardPaths', 'unsealedBundleCount', 'hashMismatchCount', 'sourceMismatchCount',
    'missingReviewedSetCount', 'lostObservationCount', 'duplicateObservationCount',
    'observationCount', 'excludedCount', 'deltaPaths', 'claimed', 'verified',
  ], [], 'reconciliation record');
  token(record.generationId, 'reconciliation generationId');
  isoTime(record.generatedAt, 'reconciliation generatedAt');
  objectId(record.epochRevision, 'reconciliation epochRevision');
  hash(record.inventorySha256, 'reconciliation inventorySha256');
  for (const field of [
    'authorizedCount', 'uniqueReviewedCount', 'unsealedBundleCount', 'hashMismatchCount',
    'sourceMismatchCount', 'missingReviewedSetCount', 'lostObservationCount',
    'duplicateObservationCount', 'observationCount', 'excludedCount',
  ]) count(record[field], `reconciliation ${field}`);
  for (const field of ['reviewedPaths', 'missingPaths', 'outsideEpochPaths', 'crossSectionPaths', 'outOfShardPaths']) {
    if (!Array.isArray(record[field])) fail(`reconciliation ${field} must be an array`);
    record[field].forEach((item, index) => repositoryPath(item, `${field}[${index}]`));
    assertUnique(record[field], (item) => item, field);
    assertByteSorted(record[field], (item) => item, field);
  }
  if (!Array.isArray(record.overlaps)) fail('reconciliation overlaps must be an array');
  record.overlaps.forEach((item, index) => validateOverlap(item, `overlaps[${index}]`));
  assertUnique(record.overlaps, (item) => item.path, 'overlaps');
  if (!Array.isArray(record.deltaPaths)) fail('reconciliation deltaPaths must be an array');
  record.deltaPaths.forEach((item, index) => validateDeltaPath(item, `deltaPaths[${index}]`));
  assertUnique(record.deltaPaths, (item) => item.path, 'deltaPaths');
  validateClaimedSummary(record.claimed);
  validateVerifiedSummary(record.verified);
  if (record.uniqueReviewedCount !== record.reviewedPaths.length
      || record.authorizedCount !== record.reviewedPaths.length + record.missingPaths.length) {
    fail('reconciliation path counts do not match exact sets');
  }
  const pass = record.missingPaths.length === 0 && record.overlaps.length === 0
    && record.outsideEpochPaths.length === 0 && record.crossSectionPaths.length === 0
    && record.outOfShardPaths.length === 0 && record.unsealedBundleCount === 0
    && record.hashMismatchCount === 0 && record.sourceMismatchCount === 0
    && record.missingReviewedSetCount === 0 && record.lostObservationCount === 0
    && record.duplicateObservationCount === 0;
  if ((record.verified.gateVerdict === 'PASS') !== pass) fail('reconciliation verified verdict contradicts derived evidence');
  const expectedCoverage = record.reviewedPaths.length === 0 ? 'none' : (record.missingPaths.length === 0 ? 'complete' : 'partial');
  if (record.verified.fileCoverage !== expectedCoverage) fail('reconciliation verified file coverage contradicts exact sets');
  return record;
}

function claimSummary(claims) {
  const completeClaimCount = claims.filter((item) => item.claimedFileCoverage === 'complete').length;
  const partialClaimCount = claims.filter((item) => item.claimedFileCoverage === 'partial').length;
  const noneClaimCount = claims.filter((item) => item.claimedFileCoverage === 'none').length;
  const total = claims.length;
  const state = total === 0 ? 'NONE' : (completeClaimCount === total ? 'COMPLETE' : 'PARTIAL');
  return { state, completeClaimCount, partialClaimCount, noneClaimCount };
}

export function buildReconciliationRecord({
  generationId,
  generatedAt,
  epoch,
  sections,
  shards,
  resultClaims = [],
  reviewedSets = [],
  admissionCapabilities = [],
  observations = [],
  deltaPaths = [],
  liveAttemptIds = [],
}) {
  validateEpochRecord(epoch);
  validateSectionsRecord(sections, { epoch });
  validateShardGenerationRecord(shards, { epoch, sections });
  if (!Array.isArray(resultClaims)) fail('resultClaims must be an array');
  resultClaims.forEach(validateResultClaimRecord);
  assertUnique(resultClaims, (item) => item.claimId, 'resultClaims');
  assertUnique(resultClaims, (item) => item.attemptId, 'result attempt identities');
  if (!Array.isArray(reviewedSets)) fail('reviewedSets must be an array');
  reviewedSets.forEach(validateReviewedSetRecord);
  assertUnique(reviewedSets, (item) => item.evidenceId, 'reviewedSets');
  assertUnique(reviewedSets, (item) => item.attemptId, 'reviewed set attempt identities');
  if (!Array.isArray(admissionCapabilities)) fail('admissionCapabilities must be an array');
  const verifiedAdmissions = admissionCapabilities.map(admissionFromCapability);
  const admissions = verifiedAdmissions.map((item) => item.admission);
  admissions.forEach(validateAdmissionInputRecord);
  assertUnique(admissions, (item) => item.admissionId, 'admissions');
  assertUnique(admissions, (item) => item.attemptId, 'admission attempt identities');
  validateObservationRecords(observations, { liveAttemptIds });
  if (!Array.isArray(deltaPaths)) fail('deltaPaths must be an array');
  deltaPaths.forEach((item, index) => validateDeltaPath(item, `deltaPaths[${index}]`));
  assertUnique(deltaPaths, (item) => item.path, 'deltaPaths');

  const shardMap = new Map(shards.shards.map((shard) => [shard.id, shard]));
  const resultByAttempt = new Map(resultClaims.map((claim) => [claim.attemptId, claim]));
  const admissionByAttempt = new Map(admissions.map((admission) => [admission.attemptId, admission]));
  const verifiedByAttempt = new Map(verifiedAdmissions.map((item) => [item.admission.attemptId, item]));
  for (const claim of resultClaims) {
    const shard = shardMap.get(claim.shardId);
    if (!shard || shard.ownerSectionId !== claim.sectionId) fail('result claim names an unknown or mismatched shard');
  }
  for (const evidence of reviewedSets) {
    const shard = shardMap.get(evidence.shardId);
    if (!shard || shard.ownerSectionId !== evidence.sectionId) fail('reviewed set names an unknown or mismatched shard');
    const claim = resultByAttempt.get(evidence.attemptId);
    const admission = admissionByAttempt.get(evidence.attemptId);
    const verified = verifiedByAttempt.get(evidence.attemptId);
    if (!claim || !admission || !verified) fail('reviewed evidence requires exactly one matching result claim and verified admission');
    if (claim.claimId !== verified.resultClaimId || claim.claimHash !== verified.resultClaimHash) {
      fail('result claim does not match the claim used for live admission verification');
    }
    if (claim.scannerState !== 'SEALED' || claim.sectionId !== evidence.sectionId
        || claim.shardId !== evidence.shardId || claim.scanId !== evidence.scanId
        || claim.bundleRef !== evidence.bundleRef || claim.bundleHash !== evidence.bundleHash
        || claim.sourceRevision !== evidence.sourceRevision
        || claim.sourceFingerprint !== evidence.sourceFingerprint
        || claim.controlGenerationHash !== evidence.controlGenerationHash) {
      fail('reviewed evidence identity contradicts its result claim');
    }
    for (const field of [
      'attemptId', 'sectionId', 'shardId', 'scanId', 'bundleRef', 'bundleHash',
      'controlGenerationHash', 'inventorySha256', 'sourceRevision', 'sourceFingerprint',
    ]) {
      if (admission[field] !== evidence[field]) fail('reviewed evidence identity contradicts its admission input');
    }
    if (!evidence.reviewedPathsPresent
        || canonicalJson(evidence.reviewedPaths) !== canonicalJson(verified.reviewedFiles)) {
      fail('reviewed evidence paths do not exactly project the hash-verified canonical coverage reviewedFiles');
    }
  }
  for (const admission of admissions) {
    if (!reviewedSets.some((evidence) => evidence.attemptId === admission.attemptId)) {
      fail('admission input does not bind exactly one reviewed set');
    }
  }
  for (const observation of observations) {
    const claim = resultByAttempt.get(observation.attemptId);
    if (!claim) fail('observation does not bind a known result claim');
    if (claim.sectionId !== observation.sectionId || claim.scanId !== observation.scanId
        || claim.bundleRef === undefined || claim.bundleRef !== observation.bundleRef) {
      fail('observation identity does not match its result claim');
    }
  }
  const authorized = new Set(epoch.authorizedPaths.map((entry) => entry.path));
  const owner = new Map(sections.sections.flatMap((section) => section.paths.map((entry) => [entry.path, section.id])));
  const resultAttempts = new Set(resultClaims.filter((claim) => claim.scannerState === 'SEALED').map((claim) => claim.attemptId));
  const reviewedByAttempt = new Map(reviewedSets.map((evidence) => [evidence.attemptId, evidence]));
  const missingReviewedSetCount = [...resultAttempts].filter((attemptId) => (
    !reviewedByAttempt.has(attemptId) || !verifiedByAttempt.has(attemptId)
  )).length;
  const unsealedBundleCount = verifiedAdmissions.filter((item) => !item.verification.sealed).length;
  const hashMismatchCount = verifiedAdmissions.filter((item) => (
    !item.verification.hashesValid || !item.verification.canonicalFilesStable
  )).length;
  const sourceMismatchCount = admissions.filter((item) => item.sourceRevision !== epoch.revision
    || item.inventorySha256 !== epoch.inventorySha256).length;

  const creditedAttempts = verifiedAdmissions.filter((item) => {
    const admission = item.admission;
    const evidence = reviewedByAttempt.get(admission.attemptId);
    const claim = resultByAttempt.get(admission.attemptId);
    return evidence !== undefined && claim?.scannerState === 'SEALED'
      && admission.sourceRevision === epoch.revision && admission.inventorySha256 === epoch.inventorySha256;
  });
  const pathAttempts = new Map();
  const outside = new Set();
  const crossSection = new Set();
  const outOfShard = new Set();
  for (const verified of creditedAttempts) {
    const evidence = verified.admission;
    const shard = shardMap.get(evidence.shardId);
    const shardPaths = new Set(shard.paths.map((entry) => entry.path));
    for (const pathname of verified.reviewedFiles) {
      if (!authorized.has(pathname)) outside.add(pathname);
      else if (owner.get(pathname) !== evidence.sectionId) crossSection.add(pathname);
      else if (!shardPaths.has(pathname)) outOfShard.add(pathname);
      else {
        const attempts = pathAttempts.get(pathname) ?? new Set();
        attempts.add(evidence.attemptId);
        pathAttempts.set(pathname, attempts);
      }
    }
  }
  const reviewedPaths = [...pathAttempts.keys()].sort(compareBytes);
  const missingPaths = [...authorized].filter((item) => !pathAttempts.has(item)).sort(compareBytes);
  const overlaps = [...pathAttempts.entries()].filter(([, attempts]) => attempts.size > 1)
    .map(([pathname, attempts]) => ({ path: pathname, attemptIds: [...attempts].sort(compareBytes) }))
    .sort((left, right) => compareBytes(left.path, right.path));
  const observationCount = observations.length;
  const observationsByAttempt = new Map();
  for (const observation of observations) {
    observationsByAttempt.set(observation.attemptId, (observationsByAttempt.get(observation.attemptId) ?? 0) + 1);
  }
  const lostObservationCount = resultClaims.reduce((sum, claim) => (
    sum + Math.max(0, claim.claimedObservationCount - (observationsByAttempt.get(claim.attemptId) ?? 0))
  ), 0);
  const duplicateObservationCount = Math.max(0, observationCount - new Set(observations.map((item) => item.recordId)).size);
  const proofCompleteness = observations.some((item) => item.disposition === 'blocked' || item.disposition === 'external-proof-gap')
    ? 'blocked' : (observations.some((item) => item.disposition === 'open') ? 'open' : 'complete');
  const blockerCodes = [];
  if (missingPaths.length) blockerCodes.push('MISSING_AUTHORIZED_PATHS');
  if (overlaps.length) blockerCodes.push('DUPLICATE_REVIEW_CREDIT');
  if (outside.size) blockerCodes.push('REVIEWED_OUTSIDE_EPOCH');
  if (crossSection.size) blockerCodes.push('CROSS_SECTION_REVIEW_CREDIT');
  if (outOfShard.size) blockerCodes.push('REVIEWED_OUTSIDE_SHARD');
  if (unsealedBundleCount) blockerCodes.push('UNSEALED_BUNDLE');
  if (hashMismatchCount) blockerCodes.push('HASH_MISMATCH');
  if (sourceMismatchCount) blockerCodes.push('SOURCE_CHANGED');
  if (missingReviewedSetCount) blockerCodes.push('MISSING_REVIEWED_SET');
  if (lostObservationCount) blockerCodes.push('LOST_OBSERVATION');
  if (duplicateObservationCount) blockerCodes.push('DUPLICATE_OBSERVATION');
  blockerCodes.sort(compareBytes);
  const record = withFixed({
    generationId,
    generatedAt,
    epochRevision: epoch.revision,
    inventorySha256: epoch.inventorySha256,
    authorizedCount: epoch.authorizedCount,
    uniqueReviewedCount: reviewedPaths.length,
    reviewedPaths,
    missingPaths,
    overlaps,
    outsideEpochPaths: [...outside].sort(compareBytes),
    crossSectionPaths: [...crossSection].sort(compareBytes),
    outOfShardPaths: [...outOfShard].sort(compareBytes),
    unsealedBundleCount,
    hashMismatchCount,
    sourceMismatchCount,
    missingReviewedSetCount,
    lostObservationCount,
    duplicateObservationCount,
    observationCount,
    excludedCount: epoch.excludedCount,
    deltaPaths,
    claimed: claimSummary(resultClaims),
    verified: {
      fileCoverage: reviewedPaths.length === 0 ? 'none' : (missingPaths.length === 0 ? 'complete' : 'partial'),
      proofCompleteness,
      gateVerdict: blockerCodes.length === 0 ? 'PASS' : 'HOLD',
      blockerCodes,
    },
  }, RECONCILIATION_SCHEMA, RECORD_ROLES.DERIVED);
  return validateReconciliationRecord(record);
}

const MILESTONE_IDS = Object.freeze(['C0', 'C0.5', 'C1', 'D1', 'C2', 'C3']);

function validateMilestone(value, name) {
  closed(value, ['id', 'claimedState', 'verifiedState', 'blockerCodes'], [], name);
  oneOf(value.id, MILESTONE_IDS, `${name}.id`);
  oneOf(value.claimedState, ['NOT_STARTED', 'IN_PROGRESS', 'COMPLETE', 'HOLD', 'BLOCKED'], `${name}.claimedState`);
  oneOf(value.verifiedState, ['NOT_VERIFIED', 'VERIFIED', 'HOLD', 'BLOCKED'], `${name}.verifiedState`);
  if (!Array.isArray(value.blockerCodes)) fail(`${name}.blockerCodes must be an array`);
  value.blockerCodes.forEach((item, index) => token(item, `${name}.blockerCodes[${index}]`));
  assertUnique(value.blockerCodes, (item) => item, `${name}.blockerCodes`);
  if (value.verifiedState === 'VERIFIED' && value.blockerCodes.length > 0) fail(`${name} verified state contradicts blockers`);
  return value;
}

function statusSummary(milestones) {
  const programClaimedState = milestones.every((item) => item.claimedState === 'COMPLETE') ? 'COMPLETE'
    : (milestones.some((item) => item.claimedState === 'BLOCKED') ? 'BLOCKED'
      : (milestones.some((item) => item.claimedState === 'HOLD') ? 'HOLD' : 'INCOMPLETE'));
  const programVerifiedState = milestones.every((item) => item.verifiedState === 'VERIFIED') ? 'VERIFIED'
    : (milestones.some((item) => item.verifiedState === 'BLOCKED') ? 'BLOCKED'
      : (milestones.some((item) => item.verifiedState === 'HOLD') ? 'HOLD' : 'INCOMPLETE'));
  const next = milestones.find((item) => item.verifiedState !== 'VERIFIED');
  return { programClaimedState, programVerifiedState, nextMilestone: next?.id ?? null };
}

export function validateStatusRecord(record) {
  topLevel(record, STATUS_SCHEMA, RECORD_ROLES.DERIVED,
    ['generationId', 'generatedAt', 'milestones', 'programClaimedState', 'programVerifiedState', 'nextMilestone'], [], 'status record');
  token(record.generationId, 'status generationId');
  isoTime(record.generatedAt, 'status generatedAt');
  if (!Array.isArray(record.milestones) || record.milestones.length !== MILESTONE_IDS.length) fail('status must include every milestone exactly once');
  record.milestones.forEach((item, index) => validateMilestone(item, `milestones[${index}]`));
  if (canonicalJson(record.milestones.map((item) => item.id)) !== canonicalJson(MILESTONE_IDS)) fail('status milestones must use canonical order');
  const summary = statusSummary(record.milestones);
  if (record.programClaimedState !== summary.programClaimedState || record.programVerifiedState !== summary.programVerifiedState
      || record.nextMilestone !== summary.nextMilestone) fail('status summary contradicts milestone records');
  return record;
}

export function buildStatusRecord({ generationId, generatedAt, milestones }) {
  if (!Array.isArray(milestones)) fail('status milestones must be an array');
  milestones.forEach((item, index) => validateMilestone(item, `milestones[${index}]`));
  const summary = statusSummary(milestones);
  return validateStatusRecord(withFixed({ generationId, generatedAt, milestones, ...summary }, STATUS_SCHEMA, RECORD_ROLES.DERIVED));
}
