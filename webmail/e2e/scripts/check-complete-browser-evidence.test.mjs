import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { verifyCompleteBrowserEvidence } from './check-complete-browser-evidence.mjs';

function reportFor(cases, listed = false) {
  return {
    suites: cases.map((item) => ({
      specs: [{
        file: item.file,
        line: item.line,
        column: item.column,
        title: item.title,
        tests: [{
          projectName: item.project,
          results: listed ? [] : [{ status: item.status }],
        }],
      }],
    })),
  };
}

function writeJSON(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'setjoin-browser-evidence-'));
  const cases = {
    main: [
      { file: 'mail.spec.ts', line: 10, column: 1, title: 'same title', project: 'chromium', status: 'skipped' },
      { file: 'mail.spec.ts', line: 10, column: 1, title: 'same title', project: 'admin-chromium', status: 'skipped' },
      { file: 'plain.spec.ts', line: 20, column: 1, title: 'plain pass', project: 'chromium', status: 'passed' },
      { file: 'plain.spec.ts', line: 20, column: 1, title: 'plain pass', project: 'admin-chromium', status: 'passed' },
    ],
    ca: [{ file: 'mail.spec.ts', line: 10, column: 1, title: 'same title', project: 'chromium', status: 'passed' }],
    meet: [{ file: 'meet.spec.ts', line: 30, column: 1, title: 'meet pass', project: 'chromium', status: 'passed' }],
    onboarding: [{ file: 'onboarding.spec.ts', line: 40, column: 1, title: 'boot pass', project: 'onboarding-chromium', status: 'passed' }],
    csp: [{ file: 'csp.spec.ts', line: 50, column: 1, title: 'csp pass', project: 'chromium', status: 'passed' }],
  };
  const manifest = {
    schemaVersion: 1,
    phases: Object.fromEntries(Object.entries(cases).map(([phase, phaseCases]) => [phase, {
      inventory: `${phase}.expected.json`,
      projects: [...new Set(phaseCases.map((item) => item.project))],
    }])),
    mainSkipRules: [
      { file: 'mail.spec.ts', project: 'chromium', type: 'gate', gate: 'ca', reason: 'fixture gate' },
      { file: 'mail.spec.ts', project: 'admin-chromium', type: 'not-applicable', reason: 'fixture project boundary' },
    ],
    externalGates: [],
  };
  const reports = {};
  for (const [phase, phaseCases] of Object.entries(cases)) {
    reports[phase] = path.join(root, `${phase}.json`);
    writeJSON(reports[phase], reportFor(phaseCases));
    writeJSON(path.join(root, `${phase}.expected.json`), reportFor(phaseCases, true));
  }
  const manifestPath = path.join(root, 'manifest.json');
  writeJSON(manifestPath, manifest);
  return { root, cases, reports, manifestPath };
}

function run(fixtureData, overrides = {}) {
  const reportPaths = { ...fixtureData.reports };
  for (const [phase, cases] of Object.entries(overrides)) {
    writeJSON(reportPaths[phase], reportFor(cases));
  }
  return verifyCompleteBrowserEvidence({
    reportPaths,
    manifestPath: fixtureData.manifestPath,
    quiet: true,
  });
}

test('complete-browser evidence accepts the exact source/project inventory', () => {
  const data = fixture();
  assert.equal(run(data).status, 'pass');
});

test('mutant: removing one listed case is rejected instead of producing a narrowed green', () => {
  const data = fixture();
  const narrowed = data.cases.main.slice(1);
  assert.throws(
    () => run(data, { main: narrowed }),
    /does not match the source\/project inventory.*missing/s,
  );
});

test('mutant: a same-title pass in another project cannot discharge a skipped case', () => {
  const data = fixture();
  const manifest = JSON.parse(fs.readFileSync(data.manifestPath, 'utf8'));
  manifest.mainSkipRules = manifest.mainSkipRules.filter((rule) => rule.project !== 'admin-chromium');
  writeJSON(data.manifestPath, manifest);
  assert.throws(
    () => run(data),
    /main skip has no exact manifest rule: admin-chromium mail\.spec\.ts:10:1/,
  );
});

test('mutant: a skipped dedicated-phase case is rejected even when its report is non-empty', () => {
  const data = fixture();
  const skipped = data.cases.ca.map((item) => ({ ...item, status: 'skipped' }));
  assert.throws(
    () => run(data, { ca: skipped }),
    /ca phase unexpectedly skipped tests/,
  );
});
