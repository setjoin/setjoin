#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const inventoryPath = path.join(root, 'docs/verification/architecture-r5-disposition-inventory.json');
const caseIds = [
  'R5-CHAT-OWNER-RECONCILIATION',
  'R5-EXCHANGE-LIFECYCLE-FOLD',
  'R5-COMPOSE-OWNER-RECONCILIATION',
  'R5-CALENDAR-OWNER-RECONCILIATION',
  'R5-OFFLINE-CAPABILITY-DEFER'
];
const exchangeTransitionIds = [
  'bundle-object-write', 'bundle-authority-commit', 'publication-receipt-object-write',
  'publication-authority-commit', 'deletion-request', 'active-store-object-delete',
  'active-store-deletion-finalize', 'backup-expiry-attestation'
];
const calendarTransitionIds = ['create', 'update', 'delete', 'rsvp', 'drag-commit', 'apply-scope'];

function fail(code, message) { throw new Error(`${code} ${message}`); }
function boundary(message) { fail('E_ARCH_R5_DISPOSITION', message); }
function object(value, location) { if (value === null || typeof value !== 'object' || Array.isArray(value)) boundary(`${location}: expected object`); }
function nonempty(value, location) { if (typeof value !== 'string' || value.trim() === '') boundary(`${location}: expected non-empty string`); }
function unique(values, location) { if (new Set(values).size !== values.length) boundary(`${location}: duplicates`); }
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function load() { try { return JSON.parse(fs.readFileSync(inventoryPath, 'utf8')); } catch (error) { boundary(`${inventoryPath}: ${error.message}`); } }
function digest(filename) { return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex'); }
function repositoryFile(relative, location) {
  nonempty(relative, location);
  if (path.isAbsolute(relative) || relative.startsWith('../') || relative.includes('/../') || relative.includes('\\')) boundary(`${location}: unsafe path`);
  const filename = path.resolve(root, relative);
  if (!filename.startsWith(`${root}${path.sep}`) || !fs.existsSync(filename) || !fs.statSync(filename).isFile()) boundary(`${location}: source missing`);
  return filename;
}
function validateSources(sources, location) {
  if (!Array.isArray(sources) || sources.length < 2) boundary(`${location}: incomplete source fingerprint`);
  const paths = [];
  for (const [index, source] of sources.entries()) {
    object(source, `${location}[${index}]`);
    const filename = repositoryFile(source.path, `${location}[${index}].path`);
    if (!/^[0-9a-f]{64}$/.test(source.sha256)) boundary(`${location}[${index}].sha256: invalid digest`);
    const actual = digest(filename);
    if (actual !== source.sha256) fail('E_ARCH_R5_EVIDENCE_STALE', `problem=source_fingerprint_mismatch cause=reviewed_source_changed location=${source.path} artifact=${inventoryPath.slice(root.length + 1)} fix=re_inventory_round_5_disposition rerun=node_scripts/check-architecture-r5-dispositions.mjs_${location.split('.')[1]}`);
    paths.push(source.path);
  }
  unique(paths, location);
}
function findCase(value, caseId) {
  const found = value.cases.find((entry) => entry.caseId === caseId);
  if (!found) boundary(`missing case ${caseId}`);
  return found;
}
function validateRound3(entry, expectedCaseId, expectedLane) {
  if (entry.disposition !== 'no-change' || entry.round3CaseId !== expectedCaseId || entry.round3Lane !== expectedLane) boundary(`${entry.caseId}: Round-3 reconciliation drifted`);
  if (!Array.isArray(entry.reviewedContracts) || entry.reviewedContracts.length < 5) boundary(`${entry.caseId}: incomplete reviewed contract`);
  unique(entry.reviewedContracts, `${entry.caseId}.reviewedContracts`);
  if (!Array.isArray(entry.newPostR3RedCases) || entry.newPostR3RedCases.length !== 0) boundary(`${entry.caseId}: no-change cannot carry a new post-R3 red case`);
  const registry = fs.readFileSync(path.join(root, 'docs/verification/architecture-r3-cases.json'), 'utf8');
  const verifier = fs.readFileSync(path.join(root, 'scripts/verify-architecture-r3.sh'), 'utf8');
  if (!registry.includes(expectedCaseId) || !registry.includes(`verify-architecture-r3.sh ${expectedLane}`) || !verifier.includes(`${expectedLane}`)) boundary(`${entry.caseId}: exact Round-3 lane is not executable`);
}
function validateExchange(entry) {
  if (entry.disposition !== 'folded' || entry.ownershipOnly !== true || entry.claimsG4G6Completion !== false) boundary(`${entry.caseId}: fold must be ownership-only and completion-neutral`);
  if (entry.activeAuthority !== 'docs/superpowers/plans/2026-08-23-exchange-replacement-contract.md' || JSON.stringify(entry.ownerMilestones) !== JSON.stringify(['G4', 'G6'])) boundary(`${entry.caseId}: wrong active owner`);
  if (!Array.isArray(entry.transitions) || JSON.stringify(entry.transitions.map((row) => row.id)) !== JSON.stringify(exchangeTransitionIds)) boundary(`${entry.caseId}: incomplete artifact transition matrix`);
  for (const row of entry.transitions) {
    if (!['handler', 'reducer', 'worker'].includes(row.ownerKind)) boundary(`${row.id}: unsupported owner kind`);
    const contents = fs.readFileSync(repositoryFile(row.ownerPath, `${row.id}.ownerPath`), 'utf8');
    nonempty(row.ownerSymbol, `${row.id}.ownerSymbol`);
    if (!contents.includes(row.ownerSymbol)) boundary(`${row.id}: owner symbol absent`);
  }
}
function validateCalendar(entry) {
  if (entry.disposition !== 'no-change' || entry.ownerPath !== 'mailserver/webmail/src/lib/stores/calendarActionStore.svelte.ts') boundary(`${entry.caseId}: invalid Calendar disposition/owner`);
  if (entry.threshold.minimumDistinctTransitions !== 2 || entry.threshold.minimumOutsideOwnerProductionSitesPerTransition !== 2 || entry.threshold.redTestRequired !== true) boundary(`${entry.caseId}: threshold weakened`);
  if (!Array.isArray(entry.transitions) || JSON.stringify(entry.transitions.map((row) => row.id)) !== JSON.stringify(calendarTransitionIds)) boundary(`${entry.caseId}: incomplete transition inventory`);
  const qualifying = [];
  const testText = fs.readFileSync(path.join(root, 'mailserver/webmail/src/lib/stores/calendarActionStore.svelte.test.ts'), 'utf8');
  for (const row of entry.transitions) {
    if (row.stateChanging !== true || !Array.isArray(row.productionSites) || !Array.isArray(row.redTestIds)) boundary(`${row.id}: incomplete transition evidence`);
    unique(row.productionSites, `${row.id}.productionSites`);
    for (const site of row.productionSites) {
      const match = site.match(/^(.*):(\d+)$/);
      if (!match) boundary(`${row.id}: invalid production site ${site}`);
      if (match[1] === entry.ownerPath) boundary(`${row.id}: owner-internal site cannot qualify`);
      const lines = fs.readFileSync(repositoryFile(match[1], `${row.id}.productionSite`), 'utf8').split('\n');
      if (Number(match[2]) < 1 || Number(match[2]) > lines.length) boundary(`${row.id}: production line absent`);
    }
    for (const redTestId of row.redTestIds) {
      nonempty(redTestId, `${row.id}.redTestId`);
      const selector = redTestId.slice(redTestId.indexOf(':') + 1);
      if (!testText.includes(selector)) boundary(`${row.id}: red test selector absent`);
    }
    const qualifies = row.productionSites.length >= 2 && row.redTestIds.length > 0;
    if (row.qualifies !== qualifies) boundary(`${row.id}: qualification result drifted`);
    if (qualifies) qualifying.push(row.id);
  }
  if (JSON.stringify(entry.qualifyingTransitionIds) !== JSON.stringify(qualifying)) boundary(`${entry.caseId}: qualifying transition receipt drifted`);
  if (qualifying.length >= 2 || entry.disposition !== 'no-change') boundary(`${entry.caseId}: threshold met but no-change retained`);
}
function validateOffline(entry) {
  if (entry.disposition !== 'deferred' || entry.activeAuthority !== 'docs/superpowers/plans/2026-08-11-connectivity-aware-sync-resource-qos.md') boundary(`${entry.caseId}: wrong deferral`);
  if (JSON.stringify(entry.ownerMilestones) !== JSON.stringify(['E4', 'E5']) || entry.decision !== 'optional-storage-metrics-and-facade-absorption') boundary(`${entry.caseId}: capability owner drifted`);
  if (entry.deleteFacadeNow !== false || entry.claimsCapabilityImplemented !== false) boundary(`${entry.caseId}: deferral cannot delete facade or claim capability`);
}
function validate(value = load(), selected = null) {
  object(value, 'inventory');
  if (value.schemaVersion !== 1 || value.authority !== 'docs/superpowers/plans/archive/2026-08-24-architecture-deepening-round-5.md') boundary('inventory identity drifted');
  if (!Array.isArray(value.cases) || JSON.stringify(value.cases.map((entry) => entry.caseId)) !== JSON.stringify(caseIds)) boundary('exact case IDs/order drifted');
  const targets = selected ? [findCase(value, selected)] : value.cases;
  for (const entry of targets) {
    validateSources(entry.sources, `${entry.caseId}.sources`);
    if (entry.caseId === caseIds[0]) validateRound3(entry, 'ARCH-R3-R6-CHAT-RECONCILE', 'chat-reconcile');
    else if (entry.caseId === caseIds[1]) validateExchange(entry);
    else if (entry.caseId === caseIds[2]) validateRound3(entry, 'ARCH-R3-R7-COMPOSE-STATE', 'compose-state');
    else if (entry.caseId === caseIds[3]) validateCalendar(entry);
    else validateOffline(entry);
  }
  return value;
}
function expectFailure(fn, code, label) {
  try { fn(); } catch (error) { if (String(error.message).startsWith(code)) return; throw error; }
  boundary(`self-test mutant passed: ${label}`);
}

const aliases = {chat: caseIds[0], exchange: caseIds[1], compose: caseIds[2], calendar: caseIds[3], offline: caseIds[4]};
const command = process.argv[2] || 'all';
try {
  if (command === 'all') {
    validate();
    console.log('architecture-r5 dispositions: PASS (chat/compose no-change; exchange folded; calendar no-change; offline deferred)');
  } else if (Object.hasOwn(aliases, command)) {
    const value = validate(load(), aliases[command]);
    const entry = findCase(value, aliases[command]);
    console.log(`architecture-r5 disposition: ${entry.caseId} ${entry.disposition.toUpperCase()}`);
  } else if (command === 'self-test') {
    const original = validate();
    let mutant = clone(original);
    findCase(mutant, caseIds[0]).newPostR3RedCases.push('planted-red-case');
    expectFailure(() => validate(mutant, caseIds[0]), 'E_ARCH_R5_DISPOSITION', 'Chat no-change with new red case');
    mutant = clone(original);
    findCase(mutant, caseIds[1]).claimsG4G6Completion = true;
    expectFailure(() => validate(mutant, caseIds[1]), 'E_ARCH_R5_DISPOSITION', 'Exchange completion overclaim');
    mutant = clone(original);
    const calendar = findCase(mutant, caseIds[3]);
    calendar.transitions[0].productionSites.push('mailserver/webmail/src/lib/components/CalendarApp.svelte:827');
    calendar.transitions[0].qualifies = true;
    calendar.transitions[1].productionSites.push('mailserver/webmail/src/lib/components/CalendarApp.svelte:827');
    calendar.transitions[1].qualifies = true;
    calendar.qualifyingTransitionIds.push('create', 'update');
    expectFailure(() => validate(mutant, caseIds[3]), 'E_ARCH_R5_DISPOSITION', 'Calendar threshold reached under no-change');
    mutant = clone(original);
    findCase(mutant, caseIds[3]).sources[0].sha256 = '0'.repeat(64);
    expectFailure(() => validate(mutant, caseIds[3]), 'E_ARCH_R5_EVIDENCE_STALE', 'Calendar stale source HOLD');
    mutant = clone(original);
    findCase(mutant, caseIds[4]).deleteFacadeNow = true;
    expectFailure(() => validate(mutant, caseIds[4]), 'E_ARCH_R5_DISPOSITION', 'offline premature deletion');
    console.log('architecture-r5 disposition self-test: PASS (no-change, fold, threshold, stale-HOLD, defer mutants)');
  } else boundary(`unknown command ${command}`);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
