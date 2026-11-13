#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const rehearsalPath = path.join(root, 'docs/verification/architecture-r5-rehearsal-inventory.json');
const evidencePath = path.join(root, 'docs/verification/architecture-r5-evidence-boundary-inventory.json');
const shaPattern = /^[0-9a-f]{64}$/;
const rehearsalOperations = ['totp-uri-and-code', 'http-response-capture', 'status-retry-policy', 'cookie-and-session-policy', 'enrollment-reset-policy', 'readiness-wait', 'topology-and-checkpoint-orchestration'];
const evidencePrograms = ['architecture-r2', 'architecture-r3', 'architecture-r4', 'connectivity-aware-sync', 'office-foundation'];

function fail(message) { throw new Error(`E_ARCH_R5_BOUNDARY ${message}`); }
function object(value, location) { if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${location}: expected object`); }
function nonempty(value, location) { if (typeof value !== 'string' || value.trim() === '') fail(`${location}: expected non-empty string`); }
function exactKeys(value, location, keys) {
  object(value, location);
  for (const key of Object.keys(value)) if (!keys.includes(key)) fail(`${location}: unknown field ${key}`);
  for (const key of keys) if (!Object.hasOwn(value, key)) fail(`${location}: missing field ${key}`);
}
function safePath(value, location) {
  nonempty(value, location);
  if (path.isAbsolute(value) || value === '..' || value.startsWith('../') || value.includes('/../') || value.includes('\\')) fail(`${location}: unsafe path`);
}
function load(filename) { try { return JSON.parse(fs.readFileSync(filename, 'utf8')); } catch (error) { fail(`${filename}: ${error.message}`); } }
function digest(filename) { return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex'); }
function unique(values, location) { if (new Set(values).size !== values.length) fail(`${location}: duplicates`); }

function validateSources(sources, location) {
  if (!Array.isArray(sources) || sources.length < 2) fail(`${location}: incomplete source list`);
  const paths = [];
  for (const [index, source] of sources.entries()) {
    exactKeys(source, `${location}[${index}]`, ['path', 'sha256']);
    safePath(source.path, `${location}[${index}].path`);
    if (!shaPattern.test(source.sha256)) fail(`${location}[${index}].sha256: invalid digest`);
    const filename = path.resolve(root, source.path);
    if (!filename.startsWith(`${root}${path.sep}`) || !fs.existsSync(filename) || !fs.statSync(filename).isFile()) fail(`${location}[${index}]: source missing`);
    const actual = digest(filename);
    if (actual !== source.sha256) fail(`${location}[${index}]: stale source expected=${source.sha256} actual=${actual}`);
    paths.push(source.path);
  }
  unique(paths, location);
}

function validateBase(value, filename, caseId) {
  if (value.schemaVersion !== 1 || value.caseId !== caseId) fail(`${filename}: invalid identity`);
  safePath(value.authority, `${filename}.authority`);
  if (!fs.existsSync(path.join(root, value.authority))) fail(`${filename}.authority: missing`);
  validateSources(value.sources, `${filename}.sources`);
}

function validateRehearsal(value = load(rehearsalPath)) {
  exactKeys(value, rehearsalPath, ['schemaVersion', 'caseId', 'authority', 'decision', 'sources', 'operations']);
  validateBase(value, rehearsalPath, 'R5-REHEARSAL-BOOTSTRAP-BOUNDARY');
  if (value.decision !== 'implemented-pure-totp-only') fail(`${rehearsalPath}: decision drifted`);
  if (!Array.isArray(value.operations) || value.operations.length !== rehearsalOperations.length) fail(`${rehearsalPath}.operations: incomplete matrix`);
  const ids = value.operations.map((row) => row.id);
  if (JSON.stringify(ids) !== JSON.stringify(rehearsalOperations)) fail(`${rehearsalPath}.operations: exact operation IDs/order drifted`);
  for (const [index, row] of value.operations.entries()) {
    exactKeys(row, `${rehearsalPath}.operations[${index}]`, ['id', 'participants', 'matchingDimensions', 'differences', 'disposition', 'owner']);
    if (!Array.isArray(row.participants) || row.participants.length < 2) fail(`${row.id}: fewer than two participants`);
    unique(row.participants, `${row.id}.participants`);
    if (!Array.isArray(row.matchingDimensions) || !Array.isArray(row.differences)) fail(`${row.id}: matrix dimensions missing`);
    nonempty(row.owner, `${row.id}.owner`);
    const expectedDisposition = row.id === 'totp-uri-and-code' ? 'extracted-pure-leaf' : 'scenario-local';
    if (row.disposition !== expectedDisposition) fail(`${row.id}: forbidden extraction or missing TOTP leaf`);
    if (row.id === 'totp-uri-and-code' && (row.matchingDimensions.length < 6 || row.differences.length !== 0)) fail(`${row.id}: pure-leaf equality is incomplete`);
    if (row.id !== 'totp-uri-and-code' && row.differences.length === 0) fail(`${row.id}: scenario difference evidence missing`);
  }
  return value;
}

function validateEvidence(value = load(evidencePath)) {
  exactKeys(value, evidencePath, ['schemaVersion', 'caseId', 'authority', 'decision', 'stableCommonEnvelope', 'publicationLeaf', 'sources', 'programs', 'incompatibilities']);
  validateBase(value, evidencePath, 'R5-EVIDENCE-PUBLICATION-BOUNDARY');
  if (value.decision !== 'no-change' || value.stableCommonEnvelope !== false || value.publicationLeaf !== null) fail(`${evidencePath}: no-change boundary weakened`);
  if (!Array.isArray(value.programs) || value.programs.length !== evidencePrograms.length) fail(`${evidencePath}.programs: incomplete matrix`);
  if (JSON.stringify(value.programs.map((row) => row.id)) !== JSON.stringify(evidencePrograms)) fail(`${evidencePath}.programs: exact program IDs/order drifted`);
  for (const [index, row] of value.programs.entries()) {
    exactKeys(row, `${evidencePath}.programs[${index}]`, ['id', 'schemaIdentity', 'sourceBinding', 'verdictModel', 'artifactModel', 'publicationModel', 'pointerModel']);
    for (const field of ['schemaIdentity', 'sourceBinding', 'verdictModel', 'artifactModel', 'publicationModel', 'pointerModel']) nonempty(row[field], `${row.id}.${field}`);
  }
  if (!Array.isArray(value.incompatibilities) || value.incompatibilities.length < 6) fail(`${evidencePath}.incompatibilities: incomplete`);
  for (const [index, reason] of value.incompatibilities.entries()) nonempty(reason, `${evidencePath}.incompatibilities[${index}]`);
  unique(value.incompatibilities, `${evidencePath}.incompatibilities`);
  return value;
}

function clone(value) { return JSON.parse(JSON.stringify(value)); }
function expectFailure(fn, label) { try { fn(); } catch (error) { if (String(error.message).includes('E_ARCH_R5_BOUNDARY')) return; throw error; } fail(`self-test mutant passed: ${label}`); }

const command = process.argv[2] || 'all';
try {
  if (command === 'rehearsal') { validateRehearsal(); console.log('architecture-r5 rehearsal boundary: PASS (pure TOTP leaf only; six scenario-local operation families)'); }
  else if (command === 'evidence') { validateEvidence(); console.log('architecture-r5 evidence boundary: NO-CHANGE (five source-bound incompatible schemas; no common envelope/leaf)'); }
  else if (command === 'all') { validateRehearsal(); validateEvidence(); console.log('architecture-r5 boundaries: PASS'); }
  else if (command === 'self-test') {
    const rehearsal = validateRehearsal(); const evidence = validateEvidence();
    let mutant = clone(rehearsal); mutant.operations[1].disposition = 'extracted-pure-leaf'; expectFailure(() => validateRehearsal(mutant), 'scenario policy extraction');
    mutant = clone(rehearsal); mutant.sources[0].sha256 = '0'.repeat(64); expectFailure(() => validateRehearsal(mutant), 'stale rehearsal source');
    mutant = clone(evidence); mutant.stableCommonEnvelope = true; expectFailure(() => validateEvidence(mutant), 'common envelope promotion');
    mutant = clone(evidence); mutant.programs.pop(); expectFailure(() => validateEvidence(mutant), 'missing program row');
    mutant = clone(evidence); mutant.sources.push(mutant.sources[0]); expectFailure(() => validateEvidence(mutant), 'duplicate evidence source');
    console.log('architecture-r5 boundary self-test: PASS (forbidden extraction, stale source, homogenization, missing row, duplicate source mutants)');
  } else fail(`unknown command ${command}`);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
