#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const defaultRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function usage(message) {
	if (message) console.error(`test-evidence: ${message}`);
	console.error('usage: node scripts/test-evidence-report.mjs [--root DIR] [--manifest FILE] [--format FORMAT] [--validate-bindings|--verify] [--output FILE]');
	process.exit(2);
}

function parseArgs(argv) {
	const options = { root: defaultRoot, manifest: 'docs/verification/feature-test-contracts.json', mode: '', format: '', output: '' };
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === '--validate-bindings') options.mode = 'validate';
		else if (arg === '--verify') options.mode = 'verify';
		else if (arg === '--root' || arg === '--manifest' || arg === '--format' || arg === '--output') {
			const value = argv[++i];
			if (!value) usage(`${arg} requires a value`);
			options[arg.slice(2)] = value;
		} else usage(`unknown argument ${arg}`);
	}
	if (!options.mode) usage('choose --validate-bindings or --verify');
	options.root = path.resolve(options.root);
	options.manifest = path.resolve(options.root, options.manifest);
	if (options.output) {
		options.output = path.resolve(options.root, options.output);
		const relativeOutput = path.relative(options.root, options.output);
		if (relativeOutput === '..' || relativeOutput.startsWith(`..${path.sep}`)) usage('--output must stay inside the repository');
	}
	return options;
}

function repoRelative(root, value) {
	const absolute = path.isAbsolute(value) ? value : path.resolve(root, value);
	const relative = path.relative(root, absolute).split(path.sep).join('/');
	return relative.startsWith('../') ? value.split(path.sep).join('/') : relative;
}

function loadBindings(manifest, requestedFormat) {
	const supported = new Set(['go-json', 'vitest-json', 'tap', 'playwright-json']);
	const bindings = [];
	for (const contract of manifest.contracts ?? []) {
		for (const requirement of contract.requirements ?? []) {
			for (const evidence of requirement.evidence ?? []) {
				if (!evidence.result) continue;
				const binding = evidence.result;
				if (!supported.has(binding.format)) throw new Error(`unsupported result format ${binding.format}`);
				if (requestedFormat && binding.format !== requestedFormat) continue;
				for (const field of ['report', 'suite', 'testId']) {
					if (typeof binding[field] !== 'string' || binding[field].trim() === '') {
						throw new Error(`${contract.id}/${requirement.id}/${evidence.id} result.${field} is required`);
					}
				}
				const normalizedReport = path.posix.normalize(binding.report);
				if (path.isAbsolute(binding.report) || binding.report.includes('\\') || normalizedReport !== binding.report || normalizedReport === '..' || normalizedReport.startsWith('../')) {
					throw new Error(`${contract.id}/${requirement.id}/${evidence.id} result.report must stay inside the repository`);
				}
				bindings.push({
					contract: contract.id,
					requirement: requirement.id,
					evidence: evidence.id,
					skipPolicy: evidence.skipPolicy,
					...binding,
				});
			}
		}
	}
	return bindings;
}

function parseVitest(root, contents) {
	const document = JSON.parse(contents);
	const cases = [];
	for (const file of document.testResults ?? []) {
		const suite = repoRelative(root, file.name ?? '');
		for (const assertion of file.assertionResults ?? []) {
			cases.push({ suite, testId: assertion.fullName ?? assertion.title ?? '', status: assertion.status ?? 'unknown' });
		}
	}
	return cases;
}

function parseGoJSON(contents) {
	const terminal = new Map();
	for (const [index, line] of contents.split(/\r?\n/).entries()) {
		if (!line.trim()) continue;
		let event;
		try { event = JSON.parse(line); } catch (error) { throw new Error(`invalid go-json line ${index + 1}: ${error.message}`); }
		if (!event.Test || !['pass', 'fail', 'skip'].includes(event.Action)) continue;
		terminal.set(`${event.Package}\u0000${event.Test}`, { suite: event.Package, testId: event.Test, status: event.Action === 'skip' ? 'skipped' : `${event.Action}ed` });
	}
	return [...terminal.values()];
}

function parseTAP(root, contents) {
	const cases = [];
	let suite = '';
	for (const rawLine of contents.split(/\r?\n/)) {
		const line = rawLine.trim();
		const suiteMatch = line.match(/^(.+?)\s+\.{2,}\s*$/);
		if (suiteMatch) {
			suite = repoRelative(root, suiteMatch[1]);
			continue;
		}
		const assertion = line.match(/^(not ok|ok)\s+\d+(?:\s+-\s+)?(.*)$/i);
		if (!assertion || !suite) continue;
		const tail = assertion[2].trim();
		const skipAt = tail.search(/\s+#\s*SKIP\b/i);
		const testId = (skipAt >= 0 ? tail.slice(0, skipAt) : tail).trim();
		if (!testId) continue;
		const status = skipAt >= 0 ? 'skipped' : assertion[1].toLowerCase() === 'ok' ? 'passed' : 'failed';
		cases.push({ suite, testId, status });
	}
	return cases;
}

function parsePlaywright(root, contents) {
	const document = JSON.parse(contents);
	const cases = [];
	const rootDir = document.config?.rootDir ?? root;
	function walk(suites, ancestors = []) {
		for (const suiteNode of suites ?? []) {
			const fileWrapper = suiteNode.file && suiteNode.title === path.basename(suiteNode.file);
			const nextAncestors = suiteNode.title && !fileWrapper ? [...ancestors, suiteNode.title] : ancestors;
			for (const spec of suiteNode.specs ?? []) {
				for (const test of spec.tests ?? []) {
					const project = test.projectName ? `#${test.projectName}` : '';
					const sourceFile = spec.file ?? suiteNode.file ?? '';
					const absoluteSource = path.isAbsolute(sourceFile) ? sourceFile : path.resolve(rootDir, sourceFile);
					const suite = `${repoRelative(root, absoluteSource)}${project}`;
					const last = test.results?.at(-1);
					let status = last?.status ?? test.status ?? 'unknown';
					if (test.expectedStatus === 'skipped' || status === 'skipped') status = 'skipped';
					else if (test.status === 'flaky' || (test.results ?? []).some((result) => ['failed', 'timedOut', 'interrupted'].includes(result.status))) status = 'failed';
					else if (status === 'passed' || test.status === 'expected') status = 'passed';
					else if (['failed', 'timedOut', 'interrupted'].includes(status)) status = 'failed';
					cases.push({ suite, testId: [...nextAncestors, spec.title].filter(Boolean).join(' '), status });
				}
			}
			walk(suiteNode.suites, nextAncestors);
		}
	}
	walk(document.suites);
	return cases;
}

function parseReport(format, root, contents) {
	switch (format) {
		case 'vitest-json': return parseVitest(root, contents);
		case 'go-json': return parseGoJSON(contents);
		case 'tap': return parseTAP(root, contents);
		case 'playwright-json': return parsePlaywright(root, contents);
		default: throw new Error(`unsupported format ${format}`);
	}
}

function writeOutput(filename, report) {
	if (!filename) return;
	fs.mkdirSync(path.dirname(filename), { recursive: true });
	fs.writeFileSync(filename, `${JSON.stringify(report, null, 2)}\n`);
}

const options = parseArgs(process.argv.slice(2));
let manifest;
try {
	manifest = JSON.parse(fs.readFileSync(options.manifest, 'utf8'));
} catch (error) {
	console.error(`test-evidence: cannot read manifest: ${error.message}`);
	process.exit(1);
}

let bindings;
try {
	bindings = loadBindings(manifest, options.format);
} catch (error) {
	console.error(`test-evidence: ${error.message}`);
	process.exit(1);
}
if (bindings.length === 0) {
	console.error(`test-evidence: no result bindings${options.format ? ` for ${options.format}` : ''}`);
	process.exit(1);
}
if (options.mode === 'validate') {
	console.log(`test-evidence: PASS (${bindings.length} result binding(s) validated)`);
	process.exit(0);
}

const parsedByReport = new Map();
const results = [];
for (const binding of bindings) {
	const reportPath = path.resolve(options.root, binding.report);
	const cacheKey = `${binding.format}\u0000${reportPath}`;
	let cases = parsedByReport.get(cacheKey);
	if (!cases) {
		try {
			cases = parseReport(binding.format, options.root, fs.readFileSync(reportPath, 'utf8'));
		} catch (error) {
			results.push({ ...binding, status: 'not-run', detail: error.message });
			continue;
		}
		parsedByReport.set(cacheKey, cases);
	}
	const matches = cases.filter((entry) => entry.suite === binding.suite && entry.testId === binding.testId);
	if (matches.length === 0) results.push({ ...binding, status: 'missing', detail: 'exact suite/testId not present in report' });
	else if (matches.length > 1) results.push({ ...binding, status: 'ambiguous', detail: `${matches.length} exact matches` });
	else results.push({ ...binding, status: matches[0].status });
}

const failures = results.filter((result) => result.status !== 'passed');
const report = {
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	mode: 'verify',
	...(process.env.TEST_EVIDENCE_ORIGIN || process.env.TEST_EVIDENCE_CSP_ORIGIN ? {
		environment: {
			...(process.env.TEST_EVIDENCE_ORIGIN ? { origin: process.env.TEST_EVIDENCE_ORIGIN } : {}),
			...(process.env.TEST_EVIDENCE_CSP_ORIGIN ? { cspOrigin: process.env.TEST_EVIDENCE_CSP_ORIGIN } : {}),
		},
	} : {}),
	results,
	passed: failures.length === 0,
};
writeOutput(options.output, report);
for (const result of results) {
	console.log(`test-evidence: ${result.status.toUpperCase()} ${result.evidence} (${result.suite} :: ${result.testId})${result.detail ? ` — ${result.detail}` : ''}`);
}
if (failures.length > 0) {
	console.error(`test-evidence: FAIL (${failures.length}/${results.length} required result(s) not passed)`);
	process.exit(1);
}
console.log(`test-evidence: PASS (${results.length} required result(s) executed and passed)`);
