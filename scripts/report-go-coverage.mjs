#!/usr/bin/env node

import childProcess from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const defaultRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function usage(message) {
	if (message) console.error(`go-coverage: ${message}`);
	console.error('usage: node scripts/report-go-coverage.mjs [--root DIR] [--config FILE] [--modules CSV] [--base REF|--diff-file FILE] [--mode report|enforce] [--output FILE]');
	process.exit(2);
}

function parseArgs(argv) {
	const options = {
		root: defaultRoot,
		config: 'docs/verification/go-coverage-thresholds.json',
		modules: process.env.GO_COVERAGE_MODULES ?? 'authserver,mailserver,shared,mailctl,setjoin-release,asrbot',
		base: process.env.COVERAGE_BASE ?? '',
		diffFile: '',
		mode: 'report',
		output: 'test-results/coverage/go-summary.json',
	};
	const names = new Set(['root', 'config', 'modules', 'base', 'diff-file', 'mode', 'output']);
	for (let index = 0; index < argv.length; index += 1) {
		const arg = argv[index];
		if (!arg.startsWith('--') || !names.has(arg.slice(2))) usage(`unknown argument ${arg}`);
		const value = argv[++index];
		if (value === undefined) usage(`${arg} requires a value`);
		options[arg.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
	}
	options.root = path.resolve(options.root);
	options.config = path.resolve(options.root, options.config);
	options.output = path.resolve(options.root, options.output);
	if (options.diffFile) options.diffFile = path.resolve(options.root, options.diffFile);
	const relativeOutput = path.relative(options.root, options.output);
	if (relativeOutput === '..' || relativeOutput.startsWith(`..${path.sep}`)) usage('--output must stay inside the root');
	options.modules = options.modules.split(',').map((value) => value.trim()).filter(Boolean);
	if (options.modules.length === 0 || new Set(options.modules).size !== options.modules.length) usage('--modules must contain unique names');
	if (!['report', 'enforce'].includes(options.mode)) usage('--mode must be report or enforce');
	return options;
}

function moduleDirectory(root, module) {
	const catalog = JSON.parse(fs.readFileSync(path.join(root, 'config', 'go-modules.json'), 'utf8'));
	const definition = catalog.modules.find((item) => item.id === module);
	if (!definition) throw new Error(`module ${module} is absent from config/go-modules.json`);
	return definition.path;
}

function modulePath(root, directory) {
	const goMod = fs.readFileSync(path.join(root, directory, 'go.mod'), 'utf8');
	const match = goMod.match(/^module\s+(\S+)\s*$/m);
	if (!match) throw new Error(`${directory}/go.mod has no module directive`);
	return match[1];
}

function parseProfile(filename, module, importPath) {
	const lines = fs.readFileSync(filename, 'utf8').split(/\r?\n/);
	if (!lines[0]?.startsWith('mode: ')) throw new Error('missing Go coverage mode header');
	// With -coverpkg=./..., Go emits the same instrumented source block once
	// per package test binary. Merge those duplicate coordinates and treat a
	// block as covered when any test binary hit it, matching go tool cover.
	const blocks = new Map();
	for (const [index, line] of lines.slice(1).entries()) {
		if (!line.trim()) continue;
		const match = line.match(/^(.+):(\d+)\.(\d+),(\d+)\.(\d+)\s+(\d+)\s+(\d+)$/);
		if (!match) throw new Error(`invalid profile line ${index + 2}`);
		const [, source, startLineRaw, startColumnRaw, endLineRaw, endColumnRaw, countRaw, hitsRaw] = match;
		if (!source.startsWith(`${importPath}/`)) throw new Error(`profile source ${source} is outside module ${importPath}`);
		const count = Number(countRaw);
		const hits = Number(hitsRaw);
		const coordinates = `${startLineRaw}.${startColumnRaw},${endLineRaw}.${endColumnRaw}`;
		const key = `${source}:${coordinates}`;
		const prior = blocks.get(key);
		if (prior && prior.count !== count) throw new Error(`inconsistent statement count for ${key}`);
		blocks.set(key, {
			source,
			repoFile: path.posix.join(module, source.slice(importPath.length + 1)),
			startLine: Number(startLineRaw),
			endLine: Number(endLineRaw),
			count,
			hits: Math.max(prior?.hits ?? 0, hits),
		});
	}
	const packages = new Map();
	let covered = 0;
	let statements = 0;
	for (const { source, count, hits } of blocks.values()) {
		const packageName = source.includes('/') ? source.slice(0, source.lastIndexOf('/')) : source;
		const current = packages.get(packageName) ?? { covered: 0, statements: 0 };
		current.statements += count;
		statements += count;
		if (hits > 0) {
			current.covered += count;
			covered += count;
		}
		packages.set(packageName, current);
	}
	if (statements === 0) throw new Error('profile contains no executable statements');
	return { covered, statements, packages, blocks };
}

function resolveBase(root, requested) {
	if (requested && !/^0+$/.test(requested)) {
		try {
			return childProcess.execFileSync('git', ['merge-base', requested, 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
		} catch {
			throw new Error(`cannot determine merge-base for requested coverage base ${requested}`);
		}
	}
	for (const args of [['merge-base', 'main', 'HEAD'], ['rev-parse', 'HEAD^']]) {
		try {
			return childProcess.execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
		} catch { /* try the next deterministic fallback */ }
	}
	throw new Error('cannot determine coverage base; pass --base REF');
}

function loadDiff(options) {
	if (options.diffFile) return fs.readFileSync(options.diffFile, 'utf8');
	const base = resolveBase(options.root, options.base);
	options.base = base;
	const moduleDirectories = options.modules.map((module) => moduleDirectory(options.root, module));
	const tracked = childProcess.execFileSync(
		'git',
		['diff', '--find-renames', '--unified=0', '--no-color', base, '--', ...moduleDirectories],
		{ cwd: options.root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
	);
	const untrackedRaw = childProcess.execFileSync(
		'git',
		['ls-files', '--others', '--exclude-standard', '-z', '--', ...moduleDirectories],
		{ cwd: options.root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
	);
	// git reports untracked symlinks as leaf paths. Worktrees may use a
	// node_modules directory symlink to reuse an installed dependency tree;
	// reading every untracked path before checking the source extension turns
	// that harmless directory link into EISDIR and prevents Go attribution.
	// Only regular Go source files can affect this reporter's result.
	const untracked = untrackedRaw.split('\0').filter(Boolean).filter((filename) => {
		if (!filename.endsWith('.go')) return false;
		try {
			return fs.lstatSync(path.join(options.root, filename)).isFile();
		} catch {
			return false;
		}
	}).map((filename) => {
		const contents = fs.readFileSync(path.join(options.root, filename), 'utf8');
		const lineCount = contents.length === 0
			? 0
			: contents.split(/\r?\n/).length - (contents.endsWith('\n') ? 1 : 0);
		if (lineCount === 0) return '';
		// parseChangedLines needs only the new-file header and hunk coordinates.
		// Avoid staging or shelling through `git diff --no-index`: the reporter
		// must audit the working tree exactly as it exists.
		return [
			`diff --git a/${filename} b/${filename}`,
			'--- /dev/null',
			`+++ b/${filename}`,
			`@@ -0,0 +1,${lineCount} @@`,
			'',
		].join('\n');
	}).join('\n');
	return `${tracked}\n${untracked}`;
}

function parseChangedLines(diff) {
	const files = new Map();
	let current = '';
	for (const line of diff.split(/\r?\n/)) {
		if (line.startsWith('+++ ')) {
			const value = line.slice(4).trim();
			current = value === '/dev/null' ? '' : value.replace(/^b\//, '');
			if (current && !files.has(current)) files.set(current, new Set());
			continue;
		}
		if (!current || !line.startsWith('@@ ')) continue;
		const match = line.match(/\+(\d+)(?:,(\d+))?/);
		if (!match) continue;
		const start = Number(match[1]);
		const count = match[2] === undefined ? 1 : Number(match[2]);
		for (let number = start; number < start + count; number += 1) files.get(current).add(number);
	}
	return files;
}

function globRegex(pattern) {
	let output = '^';
	for (let index = 0; index < pattern.length; index += 1) {
		const char = pattern[index];
		if (char === '*' && pattern[index + 1] === '*') {
			output += '.*';
			index += 1;
		} else if (char === '*') output += '[^/]*';
		else if (char === '?') output += '[^/]';
		else output += char.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
	}
	return new RegExp(`${output}$`);
}

function percent(covered, statements) {
	return Number(((covered / statements) * 100).toFixed(2));
}

const options = parseArgs(process.argv.slice(2));
let config;
try {
	config = JSON.parse(fs.readFileSync(options.config, 'utf8'));
	if (config.schemaVersion !== 1 || typeof config.modules !== 'object' || typeof config.criticalPackages !== 'object' ||
		typeof config.changedLines !== 'object' || !Number.isFinite(config.changedLines.minimum) ||
		!Number.isFinite(config.changedLines.criticalMinimum) || !Array.isArray(config.changedLines.exclude)) throw new Error('invalid config schema');
} catch (error) {
	console.error(`go-coverage: cannot read config: ${error.message}`);
	process.exit(1);
}

const moduleResults = [];
const packageTotals = new Map();
const changedHits = new Map();
const sourcePackages = new Map();
for (const module of options.modules) {
	const minimum = config.modules[module];
	if (!Number.isFinite(minimum) || minimum < 0 || minimum > 100) {
		moduleResults.push({ module, status: 'invalid-config', detail: 'module threshold is missing or invalid' });
		continue;
	}
	const profile = path.join(options.root, 'test-results', 'coverage', 'go', `${module}.out`);
	try {
		const directory = moduleDirectory(options.root, module);
		const importPath = modulePath(options.root, directory);
		const parsed = parseProfile(profile, directory, importPath);
		for (const [packageName, totals] of parsed.packages) {
			const current = packageTotals.get(packageName) ?? { covered: 0, statements: 0 };
			current.covered += totals.covered;
			current.statements += totals.statements;
			packageTotals.set(packageName, current);
		}
		for (const block of parsed.blocks.values()) {
			const hits = changedHits.get(block.repoFile) ?? new Map();
			for (let line = block.startLine; line <= block.endLine; line += 1) {
				hits.set(line, Math.max(hits.get(line) ?? 0, block.hits));
			}
			changedHits.set(block.repoFile, hits);
			sourcePackages.set(block.repoFile, block.source.slice(0, block.source.lastIndexOf('/')));
		}
		const actual = percent(parsed.covered, parsed.statements);
		moduleResults.push({ module, profile: path.relative(options.root, profile), covered: parsed.covered, statements: parsed.statements, percent: actual, minimum, status: actual >= minimum ? 'pass' : 'below-threshold' });
	} catch (error) {
		moduleResults.push({ module, profile: path.relative(options.root, profile), status: 'not-ready', detail: error.message, minimum });
	}
}

const criticalResults = [];
for (const [packageName, minimum] of Object.entries(config.criticalPackages)) {
	const totals = packageTotals.get(packageName);
	if (!Number.isFinite(minimum) || minimum < 0 || minimum > 100) criticalResults.push({ package: packageName, minimum, status: 'invalid-config' });
	else if (!totals) criticalResults.push({ package: packageName, minimum, status: 'not-ready', detail: 'package absent from selected profiles' });
	else {
		const actual = percent(totals.covered, totals.statements);
		criticalResults.push({ package: packageName, covered: totals.covered, statements: totals.statements, percent: actual, minimum, status: actual >= minimum ? 'pass' : 'below-threshold' });
	}
}

let changedResult;
try {
	const minimum = config.changedLines.minimum;
	const criticalMinimum = config.changedLines.criticalMinimum;
	if (minimum < 0 || minimum > 100 || criticalMinimum < 0 || criticalMinimum > 100) throw new Error('changed-line thresholds must be between 0 and 100');
	const changed = parseChangedLines(loadDiff(options));
	const exclusions = config.changedLines.exclude.map(globRegex);
	const criticalPackages = new Set(Object.keys(config.criticalPackages));
	const selectedPrefixes = options.modules.map((module) => `${moduleDirectory(options.root, module)}/`);
	const files = [];
	const excludedFiles = [];
	const unattributedFiles = [];
	let executableLines = 0;
	let coveredLines = 0;
	let criticalExecutableLines = 0;
	let criticalCoveredLines = 0;
	for (const [filename, lines] of changed) {
		if (!filename.endsWith('.go') || !selectedPrefixes.some((prefix) => filename.startsWith(prefix))) continue;
		if (exclusions.some((regex) => regex.test(filename))) {
			excludedFiles.push(filename);
			continue;
		}
		const hits = changedHits.get(filename);
		if (!hits) {
			unattributedFiles.push(filename);
			continue;
		}
		const executable = [...lines].filter((line) => hits.has(line));
		const covered = executable.filter((line) => hits.get(line) > 0);
		const uncoveredLines = executable.filter((line) => hits.get(line) === 0);
		const critical = criticalPackages.has(sourcePackages.get(filename));
		executableLines += executable.length;
		coveredLines += covered.length;
		if (critical) {
			criticalExecutableLines += executable.length;
			criticalCoveredLines += covered.length;
		}
		files.push({ file: filename, critical, changedLines: lines.size, executableLines: executable.length, coveredLines: covered.length, uncoveredLines });
	}
	const changedPercent = executableLines === 0 ? null : percent(coveredLines, executableLines);
	const criticalPercent = criticalExecutableLines === 0 ? null : percent(criticalCoveredLines, criticalExecutableLines);
	let status = 'pass';
	if (unattributedFiles.length > 0) status = 'not-ready';
	else if (changedPercent === null) status = 'no-executable-changes';
	else if (changedPercent < minimum) status = 'below-threshold';
	else if (criticalPercent !== null && criticalPercent < criticalMinimum) status = 'critical-below-threshold';
	changedResult = {
		status,
		base: options.base || null,
		minimum,
		criticalMinimum,
		percent: changedPercent,
		executableLines,
		coveredLines,
		criticalPercent,
		criticalExecutableLines,
		criticalCoveredLines,
		files,
		excludedFiles: excludedFiles.sort(),
		unattributedFiles: unattributedFiles.sort(),
	};
} catch (error) {
	changedResult = { status: 'not-ready', detail: error.message, minimum: config.changedLines.minimum, criticalMinimum: config.changedLines.criticalMinimum };
}

const failures = [...moduleResults, ...criticalResults].filter((result) => result.status !== 'pass');
if (!['pass', 'no-executable-changes'].includes(changedResult.status)) failures.push(changedResult);
const aggregate = moduleResults.filter((result) => Number.isFinite(result.statements)).reduce((sum, result) => ({ covered: sum.covered + result.covered, statements: sum.statements + result.statements }), { covered: 0, statements: 0 });
const report = {
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	mode: options.mode,
	passed: failures.length === 0,
	aggregate: aggregate.statements ? { ...aggregate, percent: percent(aggregate.covered, aggregate.statements) } : null,
	modules: moduleResults,
	criticalPackages: criticalResults,
	changedLines: changedResult,
};
fs.mkdirSync(path.dirname(options.output), { recursive: true });
fs.writeFileSync(options.output, `${JSON.stringify(report, null, 2)}\n`);
for (const result of moduleResults) console.log(`go-coverage: ${result.status.toUpperCase()} ${result.module}${Number.isFinite(result.percent) ? ` ${result.percent}% (minimum ${result.minimum}%)` : ` — ${result.detail}`}`);
for (const result of criticalResults) console.log(`go-coverage: ${result.status.toUpperCase()} ${result.package}${Number.isFinite(result.percent) ? ` ${result.percent}% (minimum ${result.minimum}%)` : ` — ${result.detail}`}`);
console.log(`go-coverage: changed lines ${changedResult.status.toUpperCase()}${Number.isFinite(changedResult.percent) ? ` ${changedResult.coveredLines}/${changedResult.executableLines} (${changedResult.percent}%, minimum ${changedResult.minimum}%)` : changedResult.detail ? ` — ${changedResult.detail}` : ''}`);
if (Number.isFinite(changedResult.criticalPercent)) console.log(`go-coverage: critical changed lines ${changedResult.criticalCoveredLines}/${changedResult.criticalExecutableLines} (${changedResult.criticalPercent}%, minimum ${changedResult.criticalMinimum}%)`);
if (changedResult.status === 'below-threshold' || changedResult.status === 'critical-below-threshold') {
	// Diagnose BEFORE the report file pointer: name the files carrying the
	// uncovered changed lines so test writing can target them.
	const worst = [...(changedResult.files ?? [])]
		.filter((f) => f.uncoveredLines.length > 0)
		.sort((a, b) => b.uncoveredLines.length - a.uncoveredLines.length)
		.slice(0, 20);
	for (const f of worst) {
		console.error(`go-coverage: uncovered ${f.uncoveredLines.length}/${f.executableLines} ${f.critical ? '[critical] ' : ''}${f.file}: lines ${f.uncoveredLines.slice(0, 40).join(',')}${f.uncoveredLines.length > 40 ? ' …' : ''}`);
	}
}
if (changedResult.unattributedFiles?.length) console.log(`go-coverage: unattributed changed Go files: ${changedResult.unattributedFiles.join(', ')}`);
if (failures.length && options.mode === 'enforce') process.exit(1);
console.log(`go-coverage: ${failures.length ? 'NOT-READY' : 'PASS'} (${moduleResults.length} module(s), ${criticalResults.length} critical package ratchet(s))`);
