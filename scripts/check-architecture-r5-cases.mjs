#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, '..');
const registryPath = process.env.ARCH_R5_REGISTRY || path.join(repositoryRoot, 'docs/verification/architecture-r5-cases.json');
const dispositions = new Set(['implemented', 'no-change', 'collision-held', 'folded', 'deferred']);
const gateClasses = new Set(['merge', 'extended', 'disposition']);
const predicateTypes = new Set(['focused-command', 'marker-selects-command-or-no-change', 'admin-collision', 'source-bound-constant']);
const topKeys = new Set(['schemaVersion', 'program', 'authority', 'collisionBaselines', 'cases']);
const caseKeys = new Set(['candidate', 'lane', 'caseId', 'owner', 'gateClass', 'warmEstimateSeconds', 'allowedDispositions', 'predicate', 'commands', 'alternateCommands']);
const predicateKeys = new Set(['type', 'passDisposition', 'absentDisposition', 'marker', 'alternateMarker', 'holdOn']);
const markerKeys = new Set(['path', 'selector']);
const collisionKeys = new Set(['baseCommit', 'releasedRef', 'candidatePaths']);
const expectedCases = [
  ['R5-1', 'smtp', 'R5-SMTP-INBOUND-PARITY'],
  ['R5-2', 'auth-json', 'R5-AUTH-JSON-INGRESS'],
  ['R5-3', 'artifacts', 'R5-PRIVATE-ARTIFACT-DURABILITY'],
  ['R5-4', 'rehearsal', 'R5-REHEARSAL-BOOTSTRAP-BOUNDARY'],
  ['R5-5', 'ca', 'R5-CA-ACTION-DISCRIMINATOR'],
  ['R5-6', 'admin', 'R5-ADMIN-CLIENT-OWNERSHIP'],
  ['R5-7', 'jmap-account', 'R5-JMAP-ACCOUNT-CONTEXT'],
  ['R5-8', 'evidence-boundary', 'R5-EVIDENCE-PUBLICATION-BOUNDARY'],
  ['R5-9', 'auth-cookie', 'R5-AUTH-COOKIE-TUPLE'],
  ['R5-10', 'chat', 'R5-CHAT-OWNER-RECONCILIATION'],
  ['R5-11', 'exchange-fold', 'R5-EXCHANGE-LIFECYCLE-FOLD'],
  ['R5-12', 'compose', 'R5-COMPOSE-OWNER-RECONCILIATION'],
  ['R5-13', 'calendar', 'R5-CALENDAR-OWNER-RECONCILIATION'],
  ['R5-14', 'offline-defer', 'R5-OFFLINE-CAPABILITY-DEFER'],
];

function fail(message) {
  console.error(`E_ARCH_R5_REGISTRY ${message}`);
  process.exit(1);
}

function object(value, location) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${location}: expected object`);
}

function exactKeys(value, location, expected) {
  object(value, location);
  for (const key of Object.keys(value)) if (!expected.has(key)) fail(`${location}: unknown field ${JSON.stringify(key)}`);
  for (const key of expected) if (!Object.hasOwn(value, key)) fail(`${location}: missing field ${JSON.stringify(key)}`);
}

function nonempty(value, location) {
  if (typeof value !== 'string' || value.trim() === '' || /[\0\r\n]/.test(value)) fail(`${location}: expected one non-empty line`);
}

function safeRelative(value, location) {
  nonempty(value, location);
  if (path.isAbsolute(value) || value === '..' || value.startsWith('../') || value.includes('/../') || value.includes('\\')) fail(`${location}: unsafe repository-relative path`);
}

// JSON.parse accepts duplicate keys. The verifier must not let an earlier policy field
// be visually shadowed by a later one, so scan object scopes before parsing.
function rejectDuplicateKeys(text) {
  let index = 0;
  const bad = (message) => fail(`${registryPath}: invalid JSON near character ${index + 1} (${message})`);
  const whitespace = () => { while (index < text.length && /\s/.test(text[index])) index += 1; };
  function string() {
    if (text[index] !== '"') bad('expected string');
    index += 1;
    let value = '';
    while (index < text.length) {
      const character = text[index++];
      if (character === '"') return value;
      if (character === '\\') {
        if (index >= text.length) bad('unterminated escape');
        const escaped = text[index++];
        if (escaped === 'u') {
          const hex = text.slice(index, index + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) bad('invalid unicode escape');
          value += String.fromCharCode(Number.parseInt(hex, 16));
          index += 4;
        } else {
          const simple = {'"':'"', '\\':'\\', '/':'/', b:'\b', f:'\f', n:'\n', r:'\r', t:'\t'};
          if (!Object.hasOwn(simple, escaped)) bad('invalid escape');
          value += simple[escaped];
        }
      } else {
        if (character < ' ') bad('control character in string');
        value += character;
      }
    }
    bad('unterminated string');
  }
  function value() {
    whitespace();
    if (text[index] === '{') return objectValue();
    if (text[index] === '[') return arrayValue();
    if (text[index] === '"') { string(); return; }
    for (const literal of ['true', 'false', 'null']) {
      if (text.slice(index, index + literal.length) === literal) { index += literal.length; return; }
    }
    const number = text.slice(index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (number) { index += number[0].length; return; }
    bad('expected value');
  }
  function objectValue() {
    index += 1;
    whitespace();
    const keys = new Set();
    if (text[index] === '}') { index += 1; return; }
    while (index < text.length) {
      whitespace();
      const key = string();
      if (keys.has(key)) fail(`${registryPath}: duplicate JSON field ${JSON.stringify(key)}`);
      keys.add(key);
      whitespace();
      if (text[index++] !== ':') bad('expected colon');
      value();
      whitespace();
      if (text[index] === '}') { index += 1; return; }
      if (text[index++] !== ',') bad('expected comma');
    }
    bad('unterminated object');
  }
  function arrayValue() {
    index += 1;
    whitespace();
    if (text[index] === ']') { index += 1; return; }
    while (index < text.length) {
      value();
      whitespace();
      if (text[index] === ']') { index += 1; return; }
      if (text[index++] !== ',') bad('expected comma');
    }
    bad('unterminated array');
  }
  whitespace();
  value();
  whitespace();
  if (index !== text.length) bad('trailing data');
}

function loadRegistry() {
  let text;
  try { text = fs.readFileSync(registryPath, 'utf8'); } catch (error) { fail(`${registryPath}: ${error.message}`); }
  rejectDuplicateKeys(text);
  let registry;
  try { registry = JSON.parse(text); } catch (error) { fail(`${registryPath}: ${error.message}`); }
  exactKeys(registry, 'registry', topKeys);
  if (registry.schemaVersion !== 1 || registry.program !== 'architecture-deepening-round-5') fail('registry: unsupported identity or schema');
  safeRelative(registry.authority, 'registry.authority');
  if (!fs.existsSync(path.join(repositoryRoot, registry.authority))) fail('registry.authority: path does not exist');
  exactKeys(registry.collisionBaselines, 'registry.collisionBaselines', new Set(['admin']));
  exactKeys(registry.collisionBaselines.admin, 'registry.collisionBaselines.admin', collisionKeys);
  if (!/^[0-9a-f]{40}$/.test(registry.collisionBaselines.admin.baseCommit)) fail('registry.collisionBaselines.admin.baseCommit: expected full commit');
  nonempty(registry.collisionBaselines.admin.releasedRef, 'registry.collisionBaselines.admin.releasedRef');
  if (!Array.isArray(registry.collisionBaselines.admin.candidatePaths) || registry.collisionBaselines.admin.candidatePaths.length === 0) fail('registry.collisionBaselines.admin.candidatePaths: expected non-empty array');
  for (const [index, candidatePath] of registry.collisionBaselines.admin.candidatePaths.entries()) safeRelative(candidatePath, `registry.collisionBaselines.admin.candidatePaths[${index}]`);
  if (new Set(registry.collisionBaselines.admin.candidatePaths).size !== registry.collisionBaselines.admin.candidatePaths.length) fail('registry.collisionBaselines.admin.candidatePaths: duplicates');
  if (!Array.isArray(registry.cases) || registry.cases.length !== expectedCases.length) fail(`registry.cases: expected exactly ${expectedCases.length}`);
  registry.cases.forEach((entry, index) => {
    const location = `registry.cases[${index}]`;
    exactKeys(entry, location, caseKeys);
    const expected = expectedCases[index];
    if (entry.candidate !== expected[0] || entry.lane !== expected[1] || entry.caseId !== expected[2]) fail(`${location}: exact candidate/lane/caseId mismatch`);
    nonempty(entry.owner, `${location}.owner`);
    if (!gateClasses.has(entry.gateClass)) fail(`${location}.gateClass: unsupported value`);
    if (!Number.isInteger(entry.warmEstimateSeconds) || entry.warmEstimateSeconds < 1) fail(`${location}.warmEstimateSeconds: expected positive integer`);
    if (!Array.isArray(entry.allowedDispositions) || entry.allowedDispositions.length === 0) fail(`${location}.allowedDispositions: expected non-empty array`);
    for (const disposition of entry.allowedDispositions) if (!dispositions.has(disposition)) fail(`${location}.allowedDispositions: unsupported ${JSON.stringify(disposition)}`);
    if (new Set(entry.allowedDispositions).size !== entry.allowedDispositions.length) fail(`${location}.allowedDispositions: duplicates`);
    exactKeys(entry.predicate, `${location}.predicate`, predicateKeys);
    if (!predicateTypes.has(entry.predicate.type)) fail(`${location}.predicate.type: unsupported value`);
    if (!entry.allowedDispositions.includes(entry.predicate.passDisposition)) fail(`${location}.predicate.passDisposition: not allowed`);
    if (entry.predicate.absentDisposition !== null && !entry.allowedDispositions.includes(entry.predicate.absentDisposition)) fail(`${location}.predicate.absentDisposition: not allowed`);
    exactKeys(entry.predicate.marker, `${location}.predicate.marker`, markerKeys);
    safeRelative(entry.predicate.marker.path, `${location}.predicate.marker.path`);
    nonempty(entry.predicate.marker.selector, `${location}.predicate.marker.selector`);
    if (entry.predicate.alternateMarker !== null) {
      exactKeys(entry.predicate.alternateMarker, `${location}.predicate.alternateMarker`, markerKeys);
      safeRelative(entry.predicate.alternateMarker.path, `${location}.predicate.alternateMarker.path`);
      nonempty(entry.predicate.alternateMarker.selector, `${location}.predicate.alternateMarker.selector`);
    }
    if ((entry.predicate.absentDisposition === null) !== (entry.predicate.alternateMarker === null)) fail(`${location}.predicate: absentDisposition and alternateMarker must both be null or both be present`);
    if (JSON.stringify(entry.predicate.holdOn) !== JSON.stringify(['malformed', 'stale', 'unknown'])) fail(`${location}.predicate.holdOn: must fail closed on malformed, stale, and unknown`);
    if (!Array.isArray(entry.commands)) fail(`${location}.commands: expected array`);
    if (!Array.isArray(entry.alternateCommands)) fail(`${location}.alternateCommands: expected array`);
    for (const [commandIndex, command] of entry.commands.entries()) nonempty(command, `${location}.commands[${commandIndex}]`);
    for (const [commandIndex, command] of entry.alternateCommands.entries()) nonempty(command, `${location}.alternateCommands[${commandIndex}]`);
    if (entry.gateClass !== 'disposition' && entry.commands.length === 0) fail(`${location}.commands: executable lane has no command`);
  });
  return registry;
}

function findCase(registry, lane) {
  const entry = registry.cases.find((candidate) => candidate.lane === lane);
  if (!entry) fail(`unknown lane ${JSON.stringify(lane)}`);
  return entry;
}

function markerPresent(marker, lane) {
  const filename = path.resolve(repositoryRoot, marker.path);
  if (!filename.startsWith(`${repositoryRoot}${path.sep}`)) fail(`${lane}: marker escaped repository`);
  if (!fs.existsSync(filename)) return false;
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink()) fail(`${lane}: marker is not a regular file`);
  return fs.readFileSync(filename, 'utf8').includes(marker.selector);
}

function evaluate(entry) {
  if (markerPresent(entry.predicate.marker, entry.lane)) return {state:'selected', disposition:entry.predicate.passDisposition, reason:'implementation-marker-present'};
  if (entry.predicate.alternateMarker !== null && markerPresent(entry.predicate.alternateMarker, entry.lane)) return {state:'selected', disposition:entry.predicate.absentDisposition, reason:'alternate-evidence-marker-present'};
  return {state:'hold', disposition:'hold', reason:'required-source-marker-absent'};
}

const command = process.argv[2] || 'validate';
const registry = loadRegistry();
switch (command) {
  case 'validate':
    console.log(`architecture-r5 registry: PASS (${registry.cases.length} exact cases)`);
    break;
  case 'list':
    for (const entry of registry.cases) console.log(`${entry.lane}\t${entry.caseId}\t${entry.allowedDispositions.join('/')}\t${entry.gateClass}\t${entry.warmEstimateSeconds}s\t${entry.owner}`);
    break;
  case 'case': {
    if (process.argv.length !== 4) fail('case: expected one lane');
    console.log(JSON.stringify(findCase(registry, process.argv[3])));
    break;
  }
  case 'evaluate': {
    if (process.argv.length !== 4) fail('evaluate: expected one lane');
    console.log(JSON.stringify(evaluate(findCase(registry, process.argv[3]))));
    break;
  }
  default:
    fail(`unknown command ${JSON.stringify(command)}`);
}
