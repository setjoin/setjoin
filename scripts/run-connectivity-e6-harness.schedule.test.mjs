import assert from 'node:assert/strict';
import fs from 'node:fs';
import { buildPlan, assertProfileHost } from './run-connectivity-e6-harness.mjs';
import { validateE6ProfileDocument } from './check-connectivity-aware-sync-cases.mjs';

const document = JSON.parse(fs.readFileSync(new URL('../docs/verification/connectivity-e6-profile.json', import.meta.url)));
const v1 = document.profiles[0];
const seeds = { run: v1.clockAndSeeds.runSeed, order: v1.clockAndSeeds.orderSeed, bootstrap: v1.clockAndSeeds.bootstrapSeed };
const planFor = selected => buildPlan({ selected, seeds, pairs: 20, smoke: false });
const historical = planFor(v1);
assert.equal(historical.scheduleDigest, '261a4c0af9f604e312a06febde73247b34b6674ff6f14840f47ac2a81b97ac09', 'the retained v1 workload must not be reinterpreted');
assert.equal(historical.schedule.classSequence.length, 5_000);

const next = structuredClone(document);
Object.assign(next.profiles[0], { profileId: 'e6-electron-macos-arm64-v2', profileVersion: 2, attemptsPerCriticalClassPerRun: 2_000 });
validateE6ProfileDocument(next);
const prospective = planFor(next.profiles[0]);
assert.equal(prospective.schedule.observationFloorPerClassPerRun, 1_000);
assert.equal(prospective.schedule.measurementMs, 300_000);
assert.equal(prospective.schedule.attemptIntervalMs, 30);
assert.equal(prospective.schedule.classSequence.length, 10_000);
for (const className of prospective.classes) {
  assert.equal(prospective.schedule.classSequence.filter(item => item === className).length, 2_000);
}
assert.deepEqual(planFor(next.profiles[0]), prospective, 'fixed inputs must yield the identical paired workload; no outcome-dependent stopping');
assert.notEqual(prospective.scheduleDigest, historical.scheduleDigest);
for (const budget of [undefined, 1_000, -1, 1_001, 20_000]) {
  const invalid = structuredClone(next);
  if (budget === undefined) delete invalid.profiles[0].attemptsPerCriticalClassPerRun;
  else invalid.profiles[0].attemptsPerCriticalClassPerRun = budget;
  assert.throws(() => validateE6ProfileDocument(invalid));
  assert.throws(() => planFor(invalid.profiles[0]));
}
assert.throws(() => planFor({ ...v1, attemptsPerCriticalClassPerRun: 2_000 }), /new profileVersion/);
const current = { arch: 'arm64', profileOS: 'macOS 27.0 (26A428)' };
assert.throws(() => assertProfileHost(v1.host, current, 'darwin'), /freeze a new profile version/);
assert.doesNotThrow(() => assertProfileHost({ os: current.profileOS, arch: 'arm64' }, current, 'darwin'));
assert.throws(() => assertProfileHost({ os: current.profileOS, arch: 'arm64' }, { ...current, arch: 'x64' }, 'darwin'));
assert.throws(() => assertProfileHost({ os: current.profileOS, arch: 'arm64' }, current, 'linux'));
console.log('E6 schedule/host: PASS (immutable v1, fixed v2 attempt budget, unchanged floor, exact host qualification)');
