#!/usr/bin/env node

import childProcess from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const defaultRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function usage(message) {
	if (message) console.error(`changed-coverage: ${message}`);
	console.error('usage: node scripts/report-changed-coverage.mjs [--root DIR] [--base REF|--diff-file FILE] [--coverage FILE] [--config FILE] [--threshold N] [--critical-threshold N] [--mode report|enforce] [--output FILE]');
	process.exit(2);
}

function parseArgs(argv) {
	const options = {
		root: defaultRoot,
		base: process.env.COVERAGE_BASE ?? '',
		diffFile: '',
		coverage: 'mailserver/webmail/coverage/coverage-final.json',
		config: 'docs/verification/changed-coverage-exclusions.json',
		threshold: 90,
		criticalThreshold: 95,
		mode: 'report',
		output: 'mailserver/webmail/test-results/changed-coverage.json',
	};
	const names = new Set(['root', 'base', 'diff-file', 'coverage', 'config', 'threshold', 'critical-threshold', 'mode', 'output']);
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (!arg.startsWith('--') || !names.has(arg.slice(2))) usage(`unknown argument ${arg}`);
		const value = argv[++i];
		if (value === undefined) usage(`${arg} requires a value`);
		options[arg.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
	}
	options.root = path.resolve(options.root);
	for (const key of ['diffFile', 'coverage', 'config', 'output']) {
		if (options[key]) options[key] = path.resolve(options.root, options[key]);
	}
	options.threshold = Number(options.threshold);
	if (!Number.isFinite(options.threshold) || options.threshold < 0 || options.threshold > 100) usage('--threshold must be between 0 and 100');
	options.criticalThreshold = Number(options.criticalThreshold);
	if (!Number.isFinite(options.criticalThreshold) || options.criticalThreshold < 0 || options.criticalThreshold > 100) usage('--critical-threshold must be between 0 and 100');
	if (!['report', 'enforce'].includes(options.mode)) usage('--mode must be report or enforce');
	return options;
}

function normalizeRepoPath(root, filename) {
	const absolute = path.isAbsolute(filename) ? filename : path.resolve(root, filename);
	return path.relative(root, absolute).split(path.sep).join('/');
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
	return childProcess.execFileSync(
		'git',
		['diff', '--find-renames', '--unified=0', '--no-color', base, '--', 'mailserver/webmail/src'],
		{ cwd: options.root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
	);
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
	for (let i = 0; i < pattern.length; i += 1) {
		const char = pattern[i];
		if (char === '*' && pattern[i + 1] === '*') {
			output += '.*';
			i += 1;
		} else if (char === '*') output += '[^/]*';
		else if (char === '?') output += '[^/]';
		else output += char.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
	}
	return new RegExp(`${output}$`);
}

function isInScope(filename, config) {
	return config.scope.some((prefix) => filename.startsWith(prefix)) && config.extensions.some((extension) => filename.endsWith(extension));
}

function lineHits(record) {
	const hits = new Map();
	for (const [id, location] of Object.entries(record.statementMap ?? {})) {
		const start = location?.start?.line;
		const end = location?.end?.line;
		if (!Number.isInteger(start) || !Number.isInteger(end) || end < start) continue;
		const count = Number(record.s?.[id] ?? 0);
		for (let line = start; line <= end; line += 1) {
			hits.set(line, Math.max(hits.get(line) ?? 0, count));
		}
	}
	return hits;
}

function writeReport(filename, report) {
	if (!filename) return;
	fs.mkdirSync(path.dirname(filename), { recursive: true });
	fs.writeFileSync(filename, `${JSON.stringify(report, null, 2)}\n`);
}

const options = parseArgs(process.argv.slice(2));
let config;
let coverage;
let diff;
try {
	config = JSON.parse(fs.readFileSync(options.config, 'utf8'));
	if (config.schemaVersion !== 1 || !Array.isArray(config.scope) || !Array.isArray(config.extensions) || !Array.isArray(config.exclude) || !Array.isArray(config.critical)) {
		throw new Error('invalid changed-coverage config schema');
	}
	coverage = JSON.parse(fs.readFileSync(options.coverage, 'utf8'));
	diff = loadDiff(options);
} catch (error) {
	const report = { schemaVersion: 1, mode: options.mode, status: 'not-ready', detail: error.message, threshold: options.threshold, criticalThreshold: options.criticalThreshold };
	writeReport(options.output, report);
	console.log(`changed-coverage: NOT-READY — ${error.message}`);
	process.exit(options.mode === 'enforce' ? 1 : 0);
}

const exclusions = config.exclude.map(globRegex);
const criticalPatterns = config.critical.map(globRegex);
const changed = parseChangedLines(diff);
const coverageByFile = new Map();
for (const [filename, record] of Object.entries(coverage)) coverageByFile.set(normalizeRepoPath(options.root, filename), record);

const excludedFiles = [];
const unattributedFiles = [];
const fileResults = [];
let executableLines = 0;
let coveredLines = 0;
let criticalExecutableLines = 0;
let criticalCoveredLines = 0;
for (const [filename, lines] of changed) {
	if (!isInScope(filename, config)) continue;
	if (exclusions.some((regex) => regex.test(filename))) {
		excludedFiles.push(filename);
		continue;
	}
	if (lines.size === 0) continue;
	const record = coverageByFile.get(filename);
	if (!record) {
		unattributedFiles.push(filename);
		continue;
	}
	const hits = lineHits(record);
	const executable = [...lines].filter((line) => hits.has(line));
	const covered = executable.filter((line) => hits.get(line) > 0);
	executableLines += executable.length;
	coveredLines += covered.length;
	const critical = criticalPatterns.some((regex) => regex.test(filename));
	if (critical) {
		criticalExecutableLines += executable.length;
		criticalCoveredLines += covered.length;
	}
	fileResults.push({ file: filename, critical, changedLines: lines.size, executableLines: executable.length, coveredLines: covered.length });
}

const percent = executableLines === 0 ? null : Number(((coveredLines / executableLines) * 100).toFixed(2));
const criticalPercent = criticalExecutableLines === 0 ? null : Number(((criticalCoveredLines / criticalExecutableLines) * 100).toFixed(2));
let status = 'pass';
if (unattributedFiles.length > 0) status = 'not-ready';
else if (percent === null) status = 'no-executable-changes';
else if (percent < options.threshold) status = 'below-threshold';
else if (criticalPercent !== null && criticalPercent < options.criticalThreshold) status = 'critical-below-threshold';
const report = {
	schemaVersion: 1,
	generatedAt: new Date().toISOString(),
	mode: options.mode,
	base: options.base || null,
	threshold: options.threshold,
	criticalThreshold: options.criticalThreshold,
	status,
	percent,
	executableLines,
	coveredLines,
	criticalPercent,
	criticalExecutableLines,
	criticalCoveredLines,
	files: fileResults,
	excludedFiles: excludedFiles.sort(),
	unattributedFiles: unattributedFiles.sort(),
};
writeReport(options.output, report);
console.log(`changed-coverage: ${status.toUpperCase()} — ${coveredLines}/${executableLines} executable changed line(s) covered${percent === null ? '' : ` (${percent}%, target ${options.threshold}%)`}`);
if (criticalPercent !== null) console.log(`changed-coverage: critical paths ${criticalCoveredLines}/${criticalExecutableLines} covered (${criticalPercent}%, target ${options.criticalThreshold}%)`);
if (excludedFiles.length) console.log(`changed-coverage: excluded ${excludedFiles.length} mechanically classified file(s)`);
if (unattributedFiles.length) console.log(`changed-coverage: unattributed source-map/file coverage: ${unattributedFiles.join(', ')}`);
if (options.mode === 'enforce' && !['pass', 'no-executable-changes'].includes(status)) process.exit(1);
