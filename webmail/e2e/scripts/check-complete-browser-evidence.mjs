#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_MANIFEST = path.resolve(SCRIPT_DIR, '..', 'browser-complete-coverage.json');
const PHASES = ['main', 'ca', 'meet', 'onboarding', 'csp'];

function fail(message) {
  throw new Error(message);
}

function readJSON(file, label) {
  if (!file || !fs.statSync(file, { throwIfNoEntry: false })?.isFile()) {
    fail(`${label} missing: ${file ?? '<unset>'}`);
  }
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    fail(`${label} is not valid JSON (${file}): ${error.message}`);
  }
}

function normalizeFile(file) {
  return String(file).replaceAll('\\', '/').replace(/^\.\//, '');
}

function flattenReport(report, { listed = false } = {}) {
  const tests = [];
  const visit = (suites = []) => {
    for (const suite of suites) {
      for (const spec of suite.specs ?? []) {
        for (const test of spec.tests ?? []) {
          const attempts = (test.results ?? []).map((result) => result.status);
          const status = listed
            ? 'listed'
            : attempts.includes('passed')
              ? 'passed'
              : attempts.length > 0 && attempts.every((attempt) => attempt === 'skipped')
                ? 'skipped'
                : 'failed';
          tests.push({
            file: normalizeFile(spec.file),
            line: Number(spec.line ?? 0),
            column: Number(spec.column ?? 0),
            title: spec.title,
            project: test.projectName ?? test.projectId,
            status,
            attempts,
            id: test.id ?? spec.id,
          });
        }
      }
      visit(suite.suites);
    }
  };
  visit(report.suites);
  if (tests.length === 0) fail('Playwright report contains no tests');
  return tests;
}

export function readTests(file) {
  return flattenReport(readJSON(file, 'Playwright report'));
}

function testKey(test) {
  return [test.project, test.file, `${test.line}:${test.column}`, test.title].join('\u0000');
}

function caseWithoutProject(test) {
  return [test.file, `${test.line}:${test.column}`, test.title].join('\u0000');
}

function describeTest(test) {
  return `${test.project} ${test.file}:${test.line}:${test.column} ${JSON.stringify(test.title)}`;
}

function assertUnique(tests, label) {
  const seen = new Set();
  const duplicates = [];
  for (const test of tests) {
    const key = testKey(test);
    if (seen.has(key)) duplicates.push(describeTest(test));
    seen.add(key);
  }
  if (duplicates.length > 0) {
    fail(`${label} contains duplicate source/project cases: ${duplicates.join(', ')}`);
  }
}

function parsePlaywrightJSON(output, phase) {
  const start = output.indexOf('{');
  const end = output.lastIndexOf('}');
  if (start < 0 || end <= start) fail(`${phase} Playwright --list did not return JSON`);
  try {
    return JSON.parse(output.slice(start, end + 1));
  } catch (error) {
    fail(`${phase} Playwright --list returned malformed JSON: ${error.message}`);
  }
}

function expectedInventoryPath(manifestPath, configuredPath) {
  if (!configuredPath) return null;
  return path.resolve(path.dirname(manifestPath), configuredPath);
}

function readExpectedInventory(phase, config, manifestPath) {
  const inventoryPath = expectedInventoryPath(manifestPath, config.inventory);
  if (inventoryPath) return flattenReport(readJSON(inventoryPath, `${phase} expected inventory`), { listed: true });

  if (!Array.isArray(config.listArgs) || config.listArgs.length === 0) {
    fail(`${phase} manifest entry must provide listArgs or inventory`);
  }
  const webmailRoot = path.resolve(path.dirname(manifestPath), '..');
  const playwright = path.join(webmailRoot, 'node_modules', '.bin', 'playwright');
  if (!fs.statSync(playwright, { throwIfNoEntry: false })?.isFile()) {
    fail(`${phase} expected inventory requires ${playwright}; install Webmail dependencies or provide a test inventory`);
  }
  const env = { ...process.env, ...(config.env ?? {}) };
  // The list command is deliberately source/config-only. Never let a prior
  // run's JSON reporter redirect this inventory into a mutable result file.
  delete env.PLAYWRIGHT_JSON_OUTPUT_FILE;
  env.E2E_SERVER ??= 'http://127.0.0.1:8080';
  env.E2E_BASE_URL ??= env.E2E_SERVER;
  const result = spawnSync(
    playwright,
    [...config.listArgs, '--list', '--reporter=json'],
    { cwd: webmailRoot, env, encoding: 'utf8' },
  );
  if (result.status !== 0) {
    fail(`${phase} Playwright --list failed (exit ${result.status}): ${(result.stderr || result.stdout).trim()}`);
  }
  return flattenReport(parsePlaywrightJSON(result.stdout, phase), { listed: true });
}

function validateManifest(manifest, manifestPath) {
  if (manifest?.schemaVersion !== 1) fail(`unsupported browser coverage manifest schema: ${manifestPath}`);
  for (const phase of PHASES) {
    const config = manifest.phases?.[phase];
    if (!config) fail(`browser coverage manifest missing phase ${phase}`);
    if (!Array.isArray(config.projects) || config.projects.length === 0) {
      fail(`${phase} manifest entry must declare projects`);
    }
  }
  for (const rule of manifest.mainSkipRules ?? []) {
    if (!rule.file || !rule.project || !rule.type || !rule.reason) {
      fail(`mainSkipRules require file, project, type, and reason: ${JSON.stringify(rule)}`);
    }
    if (rule.type === 'gate' && (!rule.gate || !PHASES.includes(rule.gate))) {
      fail(`mainSkipRules gate is not a browser-complete phase: ${JSON.stringify(rule)}`);
    }
    if (!['gate', 'native', 'not-applicable'].includes(rule.type)) {
      fail(`mainSkipRules has unknown type ${rule.type}: ${JSON.stringify(rule)}`);
    }
  }
}

function matchesRule(test, rule) {
  if (normalizeFile(rule.file) !== test.file) return false;
  if (rule.project !== '*' && rule.project !== test.project) return false;
  if (rule.title && rule.title !== '*' && rule.title !== test.title) return false;
  return true;
}

function sameCase(left, right) {
  return caseWithoutProject(left) === caseWithoutProject(right);
}

function compareInventory(phase, actual, expected, config) {
  assertUnique(actual, `${phase} report`);
  assertUnique(expected, `${phase} expected inventory`);
  const actualByKey = new Map(actual.map((test) => [testKey(test), test]));
  const expectedByKey = new Map(expected.map((test) => [testKey(test), test]));
  const missing = expected.filter((test) => !actualByKey.has(testKey(test)));
  const unexpected = actual.filter((test) => !expectedByKey.has(testKey(test)));
  if (missing.length > 0 || unexpected.length > 0) {
    fail(
      `${phase} report does not match the source/project inventory: ` +
        JSON.stringify({
          missing: missing.map(describeTest),
          unexpected: unexpected.map(describeTest),
        }, null, 2),
    );
  }
  const expectedProjects = [...new Set(expected.map((test) => test.project))].sort();
  const declaredProjects = [...new Set(config.projects)].sort();
  if (JSON.stringify(expectedProjects) !== JSON.stringify(declaredProjects)) {
    fail(`${phase} Playwright --list projects ${expectedProjects.join(', ')} do not match manifest ${declaredProjects.join(', ')}`);
  }
  const actualProjects = [...new Set(actual.map((test) => test.project))].sort();
  if (JSON.stringify(actualProjects) !== JSON.stringify(declaredProjects)) {
    fail(`${phase} report projects ${actualProjects.join(', ')} do not match manifest ${declaredProjects.join(', ')}`);
  }
}

function assertStatuses(phase, tests) {
  const bad = tests.filter((test) => !['passed', 'skipped'].includes(test.status));
  if (bad.length > 0) {
    fail(`${phase} contains non-passing tests: ${JSON.stringify(bad, null, 2)}`);
  }
  const flaky = tests.filter((test) => test.attempts.some((status) => status !== 'passed' && status !== 'skipped'));
  if (flaky.length > 0) {
    fail(`${phase} contains retry/flaky attempts: ${JSON.stringify(flaky, null, 2)}`);
  }
}

function verifyMainSkips(mainTests, reports, manifest) {
  const rules = manifest.mainSkipRules ?? [];
  const skipped = mainTests.filter((test) => test.status === 'skipped');
  for (const test of skipped) {
    const rule = rules.find((candidate) => matchesRule(test, candidate));
    if (!rule) fail(`main skip has no exact manifest rule: ${describeTest(test)}`);
    if (rule.type === 'native' || rule.type === 'not-applicable') continue;
    const gateTests = reports[rule.gate];
    const gateProject = rule.gateProject ?? test.project;
    const passed = gateTests?.some(
      (candidate) => candidate.project === gateProject && sameCase(candidate, test) && candidate.status === 'passed',
    );
    if (!passed) {
      fail(`main skip was not discharged by its exact gate (${rule.gate}/${gateProject}): ${describeTest(test)}`);
    }
  }
}

export function verifyCompleteBrowserEvidence({ reportPaths, manifestPath = DEFAULT_MANIFEST, verdictPath, quiet = false }) {
  const manifest = readJSON(manifestPath, 'browser coverage manifest');
  validateManifest(manifest, manifestPath);
  const reports = {};
  const expected = {};
  for (const phase of PHASES) {
    reports[phase] = readTests(reportPaths[phase]);
    expected[phase] = readExpectedInventory(phase, manifest.phases[phase], manifestPath);
    compareInventory(phase, reports[phase], expected[phase], manifest.phases[phase]);
    assertStatuses(phase, reports[phase]);
  }
  for (const phase of ['ca', 'meet', 'onboarding', 'csp']) {
    const skipped = reports[phase].filter((test) => test.status === 'skipped');
    if (skipped.length > 0) {
      fail(`${phase} phase unexpectedly skipped tests: ${JSON.stringify(skipped, null, 2)}`);
    }
  }
  verifyMainSkips(reports.main, reports, manifest);

  const summary = Object.fromEntries(
    PHASES.map((phase) => [phase, {
      expected: expected[phase].length,
      passed: reports[phase].filter((test) => test.status === 'passed').length,
      skipped: reports[phase].filter((test) => test.status === 'skipped').length,
    }]),
  );
  const verdict = {
    status: 'pass',
    manifest: path.relative(path.resolve(manifestPath, '..', '..', '..'), manifestPath),
    phases: summary,
    nativeBrowserExclusions: (manifest.mainSkipRules ?? [])
      .filter((rule) => rule.type === 'native')
      .map((rule) => ({ file: rule.file, project: rule.project, title: rule.title, reason: rule.reason })),
    externalGates: manifest.externalGates ?? [],
  };
  const output = `${JSON.stringify(verdict, null, 2)}\n`;
  if (verdictPath) fs.writeFileSync(verdictPath, output);
  if (!quiet) process.stdout.write(output);
  return verdict;
}

function cli() {
  const [mainPath, caPath, meetPath, onboardingPath, cspPath, verdictPath, manifestPath = DEFAULT_MANIFEST] = process.argv.slice(2);
  if (![mainPath, caPath, meetPath, onboardingPath, cspPath].every(Boolean)) {
    process.stderr.write(
      'usage: check-complete-browser-evidence.mjs MAIN.json CA.json MEET.json ONBOARDING.json CSP.json [VERDICT.json] [MANIFEST.json]\n',
    );
    process.exitCode = 2;
    return;
  }
  try {
    verifyCompleteBrowserEvidence({
      reportPaths: { main: mainPath, ca: caPath, meet: meetPath, onboarding: onboardingPath, csp: cspPath },
      manifestPath,
      verdictPath,
    });
  } catch (error) {
    process.stderr.write(`complete-browser-evidence: FAIL — ${error.message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) cli();
