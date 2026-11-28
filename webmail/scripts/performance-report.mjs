import { createHash } from 'node:crypto';
import {
	constants as zlibConstants,
	brotliCompressSync,
	gzipSync,
} from 'node:zlib';
import {
	 existsSync,
	 lstatSync,
	 mkdirSync,
	 readdirSync,
	 readFileSync,
	 writeFileSync,
} from 'node:fs';
import { dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const WEBMAIL_DIR = resolve(SCRIPT_DIR, '..');
const DEFAULTS = Object.freeze({
	buildDir: join(WEBMAIL_DIR, 'build'),
	manifestPath: join(WEBMAIL_DIR, '.svelte-kit/output/client/.vite/manifest.json'),
	budgetsPath: join(WEBMAIL_DIR, 'performance-budgets.json'),
	outputDir: join(WEBMAIL_DIR, 'test-results/performance'),
});

export const REPORT_VERSION = 'webmail-performance-asset-ledger-v1';
export const SCHEMA_VERSION = 1;

const METRICS = Object.freeze([
	['loginJs', 'publicLoginInitialJsBrotliBytes'],
	['loginCss', 'publicLoginInitialCssBrotliBytes'],
	['sharedChunk', 'largestSynchronousSharedJsBrotliBytes'],
	['serviceWorker', 'serviceWorkerBrotliBytes'],
	['candidateShell', 'candidateShellBrotliBytes'],
	['inboxJs', 'inboxInitialJsBrotliBytes'],
	['inboxCss', 'inboxInitialCssBrotliBytes'],
]);

const MIME_TYPES = Object.freeze({
	'.avif': 'image/avif',
	'.css': 'text/css',
	'.gif': 'image/gif',
	'.html': 'text/html',
	'.ico': 'image/x-icon',
	'.jpeg': 'image/jpeg',
	'.jpg': 'image/jpeg',
	'.js': 'text/javascript',
	'.json': 'application/json',
	'.map': 'application/json',
	'.mjs': 'text/javascript',
	'.otf': 'font/otf',
	'.png': 'image/png',
	'.svg': 'image/svg+xml',
	'.tflite': 'application/octet-stream',
	'.txt': 'text/plain',
	'.ttf': 'font/ttf',
	'.wasm': 'application/wasm',
	'.webmanifest': 'application/manifest+json',
	'.woff': 'font/woff',
	'.woff2': 'font/woff2',
});

const FONT_EXTENSIONS = new Set(['.otf', '.ttf', '.woff', '.woff2']);

export class PerformanceError extends Error {
	constructor({ kind, problem, cause, value = '-', artifact = 'reporter', fix, rerun }) {
		super(`${kind}:${problem}`);
		this.name = 'PerformanceError';
		this.kind = kind;
		this.problem = problem;
		this.cause = cause;
		this.value = value;
		this.artifact = artifact;
		this.fix = fix;
		this.rerun = rerun ?? 'npm run test:performance:report';
	}
}

function fail(kind, problem, cause, details = {}) {
	throw new PerformanceError({ kind, problem, cause, ...details });
}

function compareStrings(left, right) {
	return left < right ? -1 : left > right ? 1 : 0;
}

function sorted(values) {
	return [...values].sort(compareStrings);
}

function safeField(value) {
	const text = String(value ?? '-').replace(/[\r\n\t'"`]/g, '_').replace(/\s+/g, '_');
	return text.slice(0, 240) || '-';
}

function safeQuoted(value) {
	const text = String(value ?? '-').replace(/[\r\n'"`]/g, '_');
	return text.slice(0, 240) || '-';
}

export function formatPerformanceError(error) {
	const source = error instanceof PerformanceError
		? error
		: new PerformanceError({
			kind: 'runtime_failure',
			problem: 'reporter crashed',
			cause: error?.message ?? String(error),
			fix: 'inspect the reporter failure',
		});
	const code = `E_WEBMAIL_PERF_${source.kind.toUpperCase()}`;
	return `${code} problem=${safeField(source.problem)} cause=${safeField(source.cause)} value=${safeField(source.value)} artifact=${safeField(source.artifact)} fix='${safeQuoted(source.fix)}' rerun='${safeQuoted(source.rerun)}'`;
}

function assertPlainObject(value, artifact, problem = 'record is not an object') {
	if (value === null || typeof value !== 'object' || Array.isArray(value)) {
		fail('invalid_evidence', problem, 'expected a JSON object', { artifact });
	}
}

function readRequired(path, artifact) {
	if (!existsSync(path)) {
		fail('inputs_absent', 'required input missing', 'file or directory does not exist', { value: artifact, artifact });
	}
	try {
		return readFileSync(path);
	} catch (error) {
		fail('runtime_failure', 'required input unreadable', error.code ?? 'read failed', { value: artifact, artifact });
	}
}

function readJson(path, artifact) {
	let value;
	try {
		value = JSON.parse(readRequired(path, artifact).toString('utf8'));
	} catch (error) {
		if (error instanceof PerformanceError) throw error;
		fail('invalid_evidence', 'JSON is malformed', 'JSON parsing failed', { artifact });
	}
	return value;
}

function normalizeRelativePath(input, artifact, { url = false } = {}) {
	if (typeof input !== 'string' || input.length === 0 || input.includes('\0')) {
		fail('invalid_evidence', 'path is malformed', 'expected a non-empty relative path', { value: input, artifact });
	}
	let value = input.replaceAll('\\', '/');
	if (url) {
		if (/^(?:[A-Za-z][A-Za-z0-9+.-]*:|\/\/)/.test(value)) {
			fail('invalid_evidence', 'path is external', 'only same-origin build paths may enter the ledger', { value, artifact });
		}
		value = value.split(/[?#]/, 1)[0];
		if (value === '/') return 'index.html';
		if (value.startsWith('/')) value = value.slice(1);
	} else if (value.startsWith('/') || /^[A-Za-z]:\//.test(value)) {
		fail('invalid_evidence', 'path is absolute', 'artifact paths must be build-relative', { value, artifact });
	}
	const parts = value.split('/');
	if (parts.includes('..')) {
		fail('invalid_evidence', 'path escapes build root', 'parent traversal is not allowed', { value, artifact });
	}
	value = parts.filter((part) => part !== '.').join('/');
	if (!value || value === '.') {
		fail('invalid_evidence', 'path is empty', 'expected a build artifact path', { value: input, artifact });
	}
	return value;
}

function listBuildFiles(root, { includeSidecars = false } = {}) {
	if (!existsSync(root) || !lstatSync(root).isDirectory()) {
		fail('inputs_absent', 'build input missing', 'production build directory is absent', { value: 'build/', artifact: 'build/' });
	}
	const files = [];
	const visit = (directory) => {
		for (const name of sorted(readdirSync(directory))) {
			const path = join(directory, name);
			const stat = lstatSync(path);
			if (stat.isSymbolicLink()) {
				fail('invalid_evidence', 'build contains a symlink', 'asset identity would depend on an outside path', { value: relative(root, path), artifact: 'build/' });
			}
			if (stat.isDirectory()) visit(path);
			else if (stat.isFile()) {
				const relativePath = normalizeRelativePath(relative(root, path), 'build/');
				if (includeSidecars || (!relativePath.endsWith('.br') && !relativePath.endsWith('.gz'))) files.push(relativePath);
			}
			else fail('invalid_evidence', 'build contains a non-file artifact', 'only regular files are ledger inputs', { value: relative(root, path), artifact: 'build/' });
		}
	};
	visit(root);
	return sorted(files);
}

function validateRepresentationManifest(buildDir, buildFiles) {
	const artifact = 'static-representations.v1.json';
	const value = readJson(join(buildDir, artifact), artifact);
	assertPlainObject(value, artifact, 'representation manifest is malformed');
	const versionRecord = readJson(join(buildDir, '_app/version.json'), '_app/version.json');
	if (value.schemaVersion !== 1 || value.buildId !== versionRecord.version || !Array.isArray(value.assets)) {
		fail('invalid_evidence', 'representation manifest is stale or malformed', 'schema, buildId, and assets must match the current build', { artifact });
	}
	const allFiles = new Set(listBuildFiles(buildDir, { includeSidecars: true }));
	const expectedIdentity = sorted([...buildFiles].filter((path) => path !== artifact));
	const records = new Map();
	for (const raw of value.assets) {
		assertPlainObject(raw, artifact, 'representation asset is malformed');
		const path = normalizeRelativePath(raw.path, artifact, { url: true });
		if (records.has(path)) fail('invalid_evidence', 'duplicate representation asset', 'each identity path may appear once', { value: path, artifact });
		if (!buildFiles.has(path) || path === artifact) fail('invalid_evidence', 'representation asset is unknown', 'identity path is absent or self-referential', { value: path, artifact });
		const identity = readRequired(join(buildDir, path), `build/${path}`);
		if (raw.identityBytes !== identity.byteLength || raw.identitySha256 !== hash(identity)) {
			fail('invalid_evidence', 'representation identity is stale', 'identity size or hash does not match the current build', { value: path, artifact });
		}
		assertPlainObject(raw.representations, artifact, 'representation map is malformed');
		const representations = {};
		for (const [encoding, record] of Object.entries(raw.representations)) {
			if (encoding !== 'br' && encoding !== 'gzip') fail('invalid_evidence', 'representation encoding is unknown', 'only br and gzip are supported', { value: encoding, artifact });
			assertPlainObject(record, artifact, 'representation record is malformed');
			const sidecar = normalizeRelativePath(record.path, artifact, { url: true });
			const expectedSuffix = encoding === 'br' ? '.br' : '.gz';
			if (sidecar !== `${path}${expectedSuffix}` || !allFiles.has(sidecar)) {
				fail('invalid_evidence', 'representation sidecar is missing or misbound', 'sidecar path must be identity path plus the encoding suffix', { value: sidecar, artifact });
			}
			const bytes = readRequired(join(buildDir, sidecar), `build/${sidecar}`);
			if (record.bytes !== bytes.byteLength || record.sha256 !== hash(bytes) || bytes.byteLength >= identity.byteLength) {
				fail('invalid_evidence', 'representation sidecar is stale', 'sidecar size/hash must match and reduce transfer bytes', { value: sidecar, artifact });
			}
			representations[encoding] = { path: sidecar, bytes: bytes.byteLength, sha256: record.sha256 };
		}
		records.set(path, representations);
	}
	if (stableJson(sorted(records.keys())) !== stableJson(expectedIdentity)) {
		fail('invalid_evidence', 'representation asset membership drifted', 'manifest must bind every identity artifact exactly once', { artifact });
	}
	for (const path of allFiles) {
		if ((path.endsWith('.br') || path.endsWith('.gz')) && ![...records.values()].some((representations) => Object.values(representations).some((record) => record.path === path))) {
			fail('invalid_evidence', 'undeclared representation sidecar exists', 'every encoded file must be bound by the current manifest', { value: path, artifact });
		}
	}
	return records;
}

function validateArray(value, field, artifact) {
	if (value === undefined) return [];
	if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
		fail('invalid_evidence', 'manifest field is malformed', `${field} must be an array of strings`, { value: field, artifact });
	}
	return value;
}

function manifestOutputForRef(ref, keyToOutput, outputPaths, buildFiles, artifact) {
	if (keyToOutput.has(ref)) return keyToOutput.get(ref);
	const normalized = normalizeRelativePath(ref, artifact);
	if (outputPaths.has(normalized)) return normalized;
	if (buildFiles.has(normalized)) return normalized;
	fail('invalid_evidence', 'manifest reference is missing', 'reference does not resolve to a declared output', { value: ref, artifact });
}

function validateManifest(manifest, buildFiles) {
	assertPlainObject(manifest, 'manifest.json', 'manifest is malformed');
	const entries = Object.entries(manifest).filter(([key]) => !['routes', 'routeNodes'].includes(key));
	if (entries.length === 0) fail('invalid_evidence', 'manifest is empty', 'at least one output entry is required', { artifact: 'manifest.json' });
	const keyToOutput = new Map();
	const outputOwners = new Map();
	for (const [key, entry] of entries) {
		assertPlainObject(entry, 'manifest.json', 'manifest entry is malformed');
		if (typeof entry.file !== 'string') {
			fail('invalid_evidence', 'manifest entry is malformed', 'every entry needs a file path', { value: key, artifact: 'manifest.json' });
		}
		const output = normalizeRelativePath(entry.file, 'manifest.json');
		if (outputOwners.has(output)) {
			fail('invalid_evidence', 'duplicate output path', 'two manifest entries claim the same output', { value: output, artifact: 'manifest.json' });
		}
		outputOwners.set(output, key);
		keyToOutput.set(key, output);
	}
	const outputPaths = new Set(outputOwners.keys());
	const references = new Map([...buildFiles].map((path) => [path, { sources: new Set(), importers: new Set() }]));
	const graph = new Map();
	for (const [key, entry] of entries) {
		const output = keyToOutput.get(key);
		const imports = validateArray(entry.imports, 'imports', 'manifest.json');
		const dynamicImports = validateArray(entry.dynamicImports, 'dynamicImports', 'manifest.json');
		const css = validateArray(entry.css, 'css', 'manifest.json');
		const resolvedImports = imports.map((ref) => manifestOutputForRef(ref, keyToOutput, outputPaths, buildFiles, 'manifest.json'));
		const resolvedDynamicImports = dynamicImports.map((ref) => manifestOutputForRef(ref, keyToOutput, outputPaths, buildFiles, 'manifest.json'));
		const resolvedCss = css.map((ref) => manifestOutputForRef(ref, keyToOutput, outputPaths, buildFiles, 'manifest.json'));
		graph.set(key, { output, imports: resolvedImports, dynamicImports: resolvedDynamicImports, css: resolvedCss });
		references.get(output).sources.add(key);
		for (const path of [...resolvedImports, ...resolvedDynamicImports, ...resolvedCss]) {
			references.get(path).sources.add(key);
		}
		for (const path of resolvedImports) references.get(path).importers.add(key);
	}
	for (const [output, owner] of outputOwners) {
		if (!buildFiles.has(output)) {
			fail('invalid_evidence', 'manifest output is missing', 'declared output is absent from build/', { value: output, artifact: 'manifest.json' });
		}
		if (output === 'index.html' || output === 'service-worker.js') {
			fail('invalid_evidence', 'manifest claims a control artifact', 'index.html and service-worker.js are not client outputs', { value: output, artifact: 'manifest.json' });
		}
		if (!owner) fail('invalid_evidence', 'manifest owner is missing', 'output ownership is ambiguous', { value: output, artifact: 'manifest.json' });
	}
	return { entries, keyToOutput, outputPaths, references, graph };
}

function findBalanced(source, start, open, close) {
	let depth = 0;
	let quote = null;
	let escaped = false;
	let lineComment = false;
	let blockComment = false;
	for (let index = start; index < source.length; index += 1) {
		const char = source[index];
		const next = source[index + 1];
		if (lineComment) {
			if (char === '\n') lineComment = false;
			continue;
		}
		if (blockComment) {
			if (char === '*' && next === '/') {
				blockComment = false;
				index += 1;
			}
			continue;
		}
		if (quote) {
			if (escaped) escaped = false;
			else if (char === '\\') escaped = true;
			else if (char === quote) quote = null;
			continue;
		}
		if ((char === '\'' || char === '"' || char === '`')) {
			quote = char;
			continue;
		}
		if (char === '/' && next === '/') {
			lineComment = true;
			index += 1;
			continue;
		}
		if (char === '/' && next === '*') {
			blockComment = true;
			index += 1;
			continue;
		}
		if (char === open) depth += 1;
		if (char === close) {
			depth -= 1;
			if (depth === 0) return index;
		}
	}
	return -1;
}

function splitTopLevel(expression) {
	const parts = [];
	let start = 0;
	let square = 0;
	let curly = 0;
	let paren = 0;
	let quote = null;
	let escaped = false;
	for (let index = 0; index < expression.length; index += 1) {
		const char = expression[index];
		if (quote) {
			if (escaped) escaped = false;
			else if (char === '\\') escaped = true;
			else if (char === quote) quote = null;
			continue;
		}
		if (char === '\'' || char === '"' || char === '`') {
			quote = char;
			continue;
		}
		if (char === '[') square += 1;
		else if (char === ']') square -= 1;
		else if (char === '{') curly += 1;
		else if (char === '}') curly -= 1;
		else if (char === '(') paren += 1;
		else if (char === ')') paren -= 1;
		else if (char === ',' && square === 0 && curly === 0 && paren === 0) {
			parts.push(expression.slice(start, index).trim());
			start = index + 1;
		}
	}
	parts.push(expression.slice(start).trim());
	return parts.filter(Boolean);
}

function decodeStaticLiteral(source, start, artifact) {
	const quote = source[start];
	let escaped = false;
	for (let index = start + 1; index < source.length; index += 1) {
		const char = source[index];
		if (escaped) {
			escaped = false;
			continue;
		}
		if (char === '\\') {
			escaped = true;
			continue;
		}
		if (char === quote) {
			const raw = source.slice(start + 1, index);
			if (raw.includes('${')) {
				fail('invalid_evidence', 'precache membership is ambiguous', 'template interpolation is not a static asset list', { artifact });
			}
			if (quote === '"') {
				try {
					return { value: JSON.parse(source.slice(start, index + 1)), end: index + 1 };
				} catch {
					fail('invalid_evidence', 'precache literal is malformed', 'quoted path could not be decoded', { artifact });
				}
			}
			const value = raw.replace(/\\([\\'"`nrt])/g, (_, escapedChar) => ({ n: '\n', r: '\r', t: '\t' }[escapedChar] ?? escapedChar));
			return { value, end: index + 1 };
		}
	}
	fail('invalid_evidence', 'precache literal is malformed', 'quoted path has no closing quote', { artifact });
}

function findVariableAssignment(source, name, before, artifact) {
	const pattern = new RegExp(`(?:\\b(?:const|let|var)\\s+)?\\b${name.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&')}\\s*=`, 'g');
	const matches = [];
	let match;
	while ((match = pattern.exec(source)) !== null) {
		if (match.index >= before) break;
		matches.push(match);
	}
	for (const candidate of matches.reverse()) {
		let expressionStart = candidate.index + candidate[0].length;
		while (/\s/.test(source[expressionStart] ?? '')) expressionStart += 1;
		if (source[expressionStart] === '[') return { expressionStart, before: candidate.index };
	}
	fail('invalid_evidence', 'precache membership is ambiguous', `array variable ${name} has no static array assignment`, { value: name, artifact });
}

function parseArrayExpression(source, expression, assignmentBefore, artifact, seen = new Set()) {
	let value = expression.trim();
	if (/^\(?[A-Za-z_$][A-Za-z0-9_$]*\)?$/.test(value)) {
		const name = value.replace(/[()]/g, '');
		if (seen.has(name)) fail('invalid_evidence', 'precache membership is ambiguous', 'array variables contain a cycle', { value: name, artifact });
		const assignment = findVariableAssignment(source, name, assignmentBefore, artifact);
		const expressionEnd = findExpressionEnd(source, assignment.expressionStart);
		return parseArrayExpression(source, source.slice(assignment.expressionStart, expressionEnd), assignment.before, artifact, new Set([...seen, name]));
	}
	if (!value.startsWith('[')) {
		fail('invalid_evidence', 'precache membership is ambiguous', 'only static arrays and array spreads are supported', { value: value.slice(0, 80), artifact });
	}
	const closing = findBalanced(value, 0, '[', ']');
	if (closing < 0 || value.slice(closing + 1).trim()) {
		fail('invalid_evidence', 'precache array is malformed', 'array does not have one static closing bracket', { artifact });
	}
	const members = [];
	for (const part of splitTopLevel(value.slice(1, closing))) {
		if (part.startsWith('...')) {
			const spreadName = part.slice(3).trim();
			if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(spreadName)) {
				fail('invalid_evidence', 'precache membership is ambiguous', 'spread target is not a named static array', { value: part, artifact });
			}
			members.push(...parseArrayExpression(source, spreadName, assignmentBefore, artifact, seen));
			continue;
		}
		let literalStart = 0;
		if (!['\'', '"', '`'].includes(part[0])) {
			const prefix = /^[A-Za-z_$][A-Za-z0-9_$]*\s*\+\s*/.exec(part);
			if (!prefix) fail('invalid_evidence', 'precache membership is ambiguous', 'array member is not a static string', { value: part.slice(0, 80), artifact });
			literalStart = prefix[0].length;
		}
		const literal = decodeStaticLiteral(part, literalStart, artifact);
		if (part.slice(literal.end).trim()) fail('invalid_evidence', 'precache membership is ambiguous', 'array member has a dynamic suffix', { value: part.slice(0, 80), artifact });
		members.push(literal.value);
	}
	return members;
}

function findExpressionEnd(source, start) {
	let index = start;
	while (index < source.length && /\s/.test(source[index])) index += 1;
	if (source[index] === '[') {
		const end = findBalanced(source, index, '[', ']');
		if (end < 0) return source.length;
		return end + 1;
	}
	const identifier = /^[A-Za-z_$][A-Za-z0-9_$]*/.exec(source.slice(index));
	if (identifier) return index + identifier[0].length;
	return source.length;
}

export function parsePrecacheMembers(source, buildFiles = new Set()) {
	if (typeof source !== 'string' || source.trim() === '') {
		fail('invalid_evidence', 'service worker is malformed', 'worker source is empty', { artifact: 'service-worker.js' });
	}
	const addAllMatches = [...source.matchAll(/\baddAll\s*\(/g)];
	if (addAllMatches.length !== 1) {
		fail('invalid_evidence', 'precache declaration is ambiguous', 'expected exactly one static cache.addAll declaration', { value: addAllMatches.length, artifact: 'service-worker.js' });
	}
	const match = addAllMatches[0];
	const open = source.indexOf('(', match.index);
	const close = findBalanced(source, open, '(', ')');
	if (close < 0) fail('invalid_evidence', 'service worker is malformed', 'addAll call has no closing parenthesis', { artifact: 'service-worker.js' });
	const expression = source.slice(open + 1, close).trim();
	if (!expression) fail('invalid_evidence', 'precache declaration is malformed', 'addAll has no membership expression', { artifact: 'service-worker.js' });
	const rawMembers = parseArrayExpression(source, expression, match.index, 'service-worker.js');
	const members = rawMembers.map((member) => normalizeRelativePath(member, 'service-worker.js', { url: true }));
	if (members.length === 0) fail('invalid_evidence', 'precache declaration is empty', 'at least one shell member is required', { artifact: 'service-worker.js' });
	const duplicate = members.find((member, index) => members.indexOf(member) !== index);
	if (duplicate) fail('invalid_evidence', 'duplicate precache member', 'the service worker would install one asset twice', { value: duplicate, artifact: 'service-worker.js' });
	for (const member of members) {
		if (buildFiles.size > 0 && !buildFiles.has(member)) {
			fail('invalid_evidence', 'precache member is missing', 'declared shell asset is absent from build/', { value: member, artifact: 'service-worker.js' });
		}
	}
	return sorted(members);
}

function extractIndexReferences(html, buildFiles) {
	if (!/<(?:html|head|body|script|link)\b/i.test(html)) {
		fail('invalid_evidence', 'index.html is malformed', 'expected an HTML document with asset tags', { artifact: 'index.html' });
	}
	const references = new Set();
	const attributes = /\b(?:src|href)\s*=\s*(["'])(.*?)\1/gi;
	let match;
	while ((match = attributes.exec(html)) !== null) {
		const value = match[2].trim();
		if (!value || /^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(value)) continue;
		references.add(normalizeRelativePath(value, 'index.html', { url: true }));
	}
	if (/(?:["'`])\/?service-worker\.js(?:[?#"'`])/.test(html)) references.add('service-worker.js');
	if (references.size === 0) fail('invalid_evidence', 'index.html has no asset references', 'initial document closure cannot be measured', { artifact: 'index.html' });
	for (const path of references) {
		if (!buildFiles.has(path)) fail('invalid_evidence', 'index asset is missing', 'index.html points outside the production build', { value: path, artifact: 'index.html' });
	}
	return sorted(references);
}

function assetClass(path) {
	if (path === 'service-worker.js') return 'service-worker';
	const extension = extname(path).toLowerCase();
	if (extension === '.html') return 'html';
	if (extension === '.css') return 'css';
	if (['.js', '.mjs'].includes(extension)) return 'javascript';
	if (FONT_EXTENSIONS.has(extension)) return 'font';
	if (['.avif', '.gif', '.ico', '.jpeg', '.jpg', '.png', '.svg'].includes(extension)) return 'image';
	if (extension === '.wasm') return 'wasm';
	if (extension === '.json' || extension === '.map' || extension === '.webmanifest') return 'data';
	return 'other';
}

function cacheClass(path, refs) {
	if (path === 'index.html') return 'mutable-html';
	if (path === 'service-worker.js') return 'mutable-service-worker';
	if (refs.serviceWorker) return 'public-shell';
	if (refs.clientManifest && (/\/_app\/immutable\//.test(`/${path}`) || /[.-][A-Za-z0-9_-]{8,}\./.test(path))) return 'immutable-public';
	if (refs.clientManifest || refs.initialIndex) return 'public-static';
	return 'unreferenced-static';
}

function compress(bytes) {
	return {
		gzipBytes: gzipSync(bytes, { level: 9, mtime: 0 }).byteLength,
		brotliBytes: brotliCompressSync(bytes, {
			params: { [zlibConstants.BROTLI_PARAM_QUALITY]: 5 },
		}).byteLength,
	};
}

function hash(bytes) {
	return createHash('sha256').update(bytes).digest('hex');
}

function stableJson(value) {
	if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
	if (value && typeof value === 'object') {
		return `{${Object.keys(value).sort(compareStrings).map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
	}
	return JSON.stringify(value);
}

function metricBytes(records, paths) {
	const selected = sorted(new Set(paths)).map((path) => records.get(path)).filter(Boolean);
	if (selected.length === 0) return { status: 'diagnostic', reason: 'no assets in closure', paths: [] };
	return {
		status: 'measured',
		paths: selected.map((record) => record.path),
		identityBytes: selected.reduce((sum, record) => sum + record.identityBytes, 0),
		gzipBytes: selected.reduce((sum, record) => sum + record.gzipBytes, 0),
		brotliBytes: selected.reduce((sum, record) => sum + record.brotliBytes, 0),
	};
}

function routeSourceKey(manifest, route) {
	const expected = route === '/' ? 'src/routes/+page.svelte' : `src/routes${route}/+page.svelte`;
	const found = Object.entries(manifest).find(([key, entry]) => key === expected || entry?.src === expected);
	return found?.[0] ?? null;
}

function optionalServerRouteNodes(manifestPath) {
	const serverManifest = resolve(dirname(manifestPath), '../../server/manifest.js');
	if (!existsSync(serverManifest)) return new Map();
	let source;
	try {
		source = readFileSync(serverManifest, 'utf8');
	} catch {
		return new Map();
	}
	const routes = new Map();
	const pattern = /\{\s*id:\s*(["'`])([^"'`]+)\1[\s\S]*?page:\s*\{[\s\S]*?leaf:\s*(\d+)/g;
	let match;
	while ((match = pattern.exec(source)) !== null) routes.set(match[2], Number(match[3]));
	return routes;
}

function findRouteKey(manifest, route, manifestPath) {
	const direct = routeSourceKey(manifest, route);
	if (direct) return direct;
	const routeNode = optionalServerRouteNodes(manifestPath).get(route);
	if (routeNode === undefined) return null;
	const nodeKey = `.svelte-kit/generated/client-optimized/nodes/${routeNode}.js`;
	return manifest[nodeKey] ? nodeKey : null;
}

function synchronousClosure(graph, key, seen = new Set(), outputs = new Set()) {
	if (!key || seen.has(key) || !graph.has(key)) return outputs;
	seen.add(key);
	const entry = graph.get(key);
	outputs.add(entry.output);
	for (const output of [...entry.imports, ...entry.css]) {
		outputs.add(output);
		const child = [...graph.entries()].find(([, value]) => value.output === output)?.[0];
		if (child) synchronousClosure(graph, child, seen, outputs);
	}
	return outputs;
}

function routeClosurePaths(manifestInfo, route, manifestPath) {
	const key = findRouteKey(manifestInfo.manifest, route, manifestPath);
	if (!key) return { status: 'diagnostic', reason: `route closure unavailable for ${route}`, paths: [] };
	const outputs = synchronousClosure(manifestInfo.graph, key);
	return {
		status: 'measured',
		paths: sorted(outputs),
	};
}

/**
 * Derive the exact public shell needed to mount the root route. This is shared
 * by the post-build manifest generator and the release reporter so the worker
 * allowlist cannot silently drift from the measured route closure.
 */
export function deriveCriticalShellMembers({ buildDir = DEFAULTS.buildDir, manifestPath = DEFAULTS.manifestPath } = {}) {
	const buildFiles = new Set(listBuildFiles(buildDir));
	if (!buildFiles.has('index.html')) fail('inputs_absent', 'index.html missing', 'production build has no initial document', { value: 'index.html', artifact: 'build/' });
	const manifest = readJson(manifestPath, 'manifest.json');
	const manifestInfo = validateManifest(manifest, buildFiles);
	manifestInfo.manifest = manifest;
	const indexHtml = readRequired(join(buildDir, 'index.html'), 'index.html').toString('utf8');
	const indexPaths = extractIndexReferences(indexHtml, buildFiles).filter((path) => path !== 'service-worker.js');
	const publicRoute = routeClosurePaths(manifestInfo, '/', manifestPath);
	if (publicRoute.status !== 'measured') {
		fail('invalid_evidence', 'public route closure is unavailable', 'the critical shell must be derived from an exact root-route node', { artifact: 'manifest.json' });
	}
	const members = sorted(new Set([
		'index.html',
		...indexPaths,
		...publicRoute.paths,
		...['manifest.webmanifest', '_app/version.json'].filter((path) => buildFiles.has(path)),
	]));
	for (const member of members) {
		if (!buildFiles.has(member)) fail('invalid_evidence', 'critical shell member is missing', 'derived member is absent from build/', { value: member, artifact: 'critical-shell.v1.json' });
		if (member === 'service-worker.js' || member === 'critical-shell.v1.json') {
			fail('invalid_evidence', 'critical shell contains a control artifact', 'the worker and self-describing manifest must never enter their own cache', { value: member, artifact: 'critical-shell.v1.json' });
		}
	}
	return members;
}

function validateCriticalShellManifest({ buildDir, manifestPath, buildFiles }) {
	const artifact = 'critical-shell.v1.json';
	const path = join(buildDir, artifact);
	const value = readJson(path, artifact);
	assertPlainObject(value, artifact, 'critical shell manifest is malformed');
	if (value.schemaVersion !== 1 || value.protocolVersion !== 1) {
		fail('invalid_evidence', 'critical shell schema is unsupported', 'schemaVersion and protocolVersion must both equal 1', { artifact });
	}
	const versionRecord = readJson(join(buildDir, '_app/version.json'), '_app/version.json');
	if (typeof versionRecord.version !== 'string' || !versionRecord.version || value.buildId !== versionRecord.version) {
		fail('invalid_evidence', 'critical shell build id is stale', 'manifest buildId must equal the SvelteKit build version', { value: value.buildId, artifact });
	}
	if (!Array.isArray(value.members) || value.members.length === 0) {
		fail('invalid_evidence', 'critical shell membership is malformed', 'members must be a non-empty array', { artifact });
	}
	const expected = deriveCriticalShellMembers({ buildDir, manifestPath });
	const seen = new Set();
	const members = [];
	for (const member of value.members) {
		assertPlainObject(member, artifact, 'critical shell member is malformed');
		const normalized = normalizeRelativePath(member.path, artifact, { url: true });
		if (seen.has(normalized)) fail('invalid_evidence', 'duplicate critical shell member', 'each public asset may appear once', { value: normalized, artifact });
		seen.add(normalized);
		if (!buildFiles.has(normalized)) fail('invalid_evidence', 'critical shell member is missing', 'declared member is absent from build/', { value: normalized, artifact });
		const bytes = readRequired(join(buildDir, normalized), `build/${normalized}`);
		if (!Number.isSafeInteger(member.identityBytes) || member.identityBytes !== bytes.byteLength) {
			fail('invalid_evidence', 'critical shell size is stale', 'declared identityBytes does not match the artifact', { value: normalized, artifact });
		}
		if (typeof member.sha256 !== 'string' || member.sha256 !== hash(bytes)) {
			fail('invalid_evidence', 'critical shell hash is stale', 'declared SHA-256 does not match the artifact', { value: normalized, artifact });
		}
		members.push(normalized);
	}
	const actual = sorted(members);
	if (stableJson(actual) !== stableJson(expected)) {
		fail('invalid_evidence', 'critical shell membership drifted', 'manifest members must exactly match the generated public root closure', { artifact });
	}
	return { buildId: value.buildId, members: actual, records: value.members, manifest: value };
}

function compareBudgets(report, budgetConfig) {
	assertPlainObject(budgetConfig, 'performance-budgets.json', 'budget file is malformed');
	if (budgetConfig.schemaVersion !== SCHEMA_VERSION) {
		fail('invalid_evidence', 'budget schema is unsupported', `expected schema version ${SCHEMA_VERSION}`, { value: budgetConfig.schemaVersion, artifact: 'performance-budgets.json' });
	}
	const source = budgetConfig.budgets ?? budgetConfig.metrics;
	if (budgetConfig.budgets !== undefined && budgetConfig.metrics !== undefined) {
		fail('invalid_evidence', 'budget records are ambiguous', 'use one budgets or metrics object', { artifact: 'performance-budgets.json' });
	}
	assertPlainObject(source, 'performance-budgets.json', 'budgets must be an object');
	const known = new Set(METRICS.map(([id]) => id));
	for (const id of Object.keys(source)) {
		if (!known.has(id)) fail('invalid_evidence', 'budget record is unknown', 'every budget must name a known deterministic metric', { value: id, artifact: 'performance-budgets.json' });
	}
	const results = [];
	const failures = [];
	for (const [id, metricName] of METRICS) {
		if (!(id in source)) fail('invalid_evidence', 'budget record is missing', 'every deterministic metric needs one budget', { value: id, artifact: 'performance-budgets.json' });
		const record = source[id];
		const limit = typeof record === 'number' ? record : record?.limitBytes ?? record?.limit;
		if (!Number.isSafeInteger(limit) || limit < 0) {
			fail('invalid_evidence', 'budget record is malformed', 'limitBytes must be a non-negative integer', { value: id, artifact: 'performance-budgets.json' });
		}
		if (record && typeof record === 'object' && record.metric !== undefined && record.metric !== metricName) {
			fail('invalid_evidence', 'budget record is ambiguous', 'budget metric does not match its known record', { value: id, artifact: 'performance-budgets.json' });
		}
		if (record && typeof record === 'object' && record.limit !== undefined && record.limitBytes !== undefined && record.limit !== record.limitBytes) {
			fail('invalid_evidence', 'budget record is ambiguous', 'limit and limitBytes disagree', { value: id, artifact: 'performance-budgets.json' });
		}
		const metric = report.metricValues[metricName];
		const actual = metric?.status === 'measured' ? metric.brotliBytes : null;
		const required = typeof record === 'object' ? record.required !== false : true;
		const diagnosticAllowed = typeof record === 'object' && record.diagnostic === true;
		const result = {
			id,
			metric: metricName,
			actualBrotliBytes: actual,
			limitBrotliBytes: limit,
			required,
			status: actual === null ? (diagnosticAllowed ? 'diagnostic' : 'missing') : actual > limit ? 'fail' : 'pass',
		};
		results.push(result);
		if (result.status === 'fail' || (result.status === 'missing' && required && !diagnosticAllowed)) failures.push(result);
	}
	return { results, failures, verdict: failures.length === 0 ? 'pass' : 'fail' };
}

export function assertBudgetPasses(report) {
	const failure = report.budgets?.failures?.[0];
	if (!failure) return;
	const isMissing = failure.status === 'missing';
	fail('policy_violation', isMissing ? 'required metric is missing' : 'deterministic budget is exceeded', isMissing ? 'metric closure was not measured' : `${failure.metric} is over its declared Brotli limit`, {
		value: `${failure.id}: actual=${failure.actualBrotliBytes ?? 'unmeasured'} limit=${failure.limitBrotliBytes}`,
		artifact: 'performance-budgets.json',
		fix: isMissing ? 'provide an unambiguous route closure or mark the metric diagnostic' : 'reduce the selected asset closure or review the committed budget',
	});
}

function makeHumanTable(report) {
	const lines = [
		`WEBMAIL PERFORMANCE LEDGER v${SCHEMA_VERSION}`,
		`build=${report.buildId} assets=${report.assets.length} totalBytes=${report.aggregates.totalBuildBytes} fonts=${report.aggregates.totalFontBytes}`,
		'',
		' METRIC                         ACTUAL BR  LIMIT BR  STATUS',
		' ----------------------------------------------------------',
	];
	for (const result of report.budgets.results) {
		const actual = result.actualBrotliBytes === null ? 'unmeasured' : String(result.actualBrotliBytes);
		lines.push(` ${result.id.padEnd(30)} ${actual.padStart(10)} ${String(result.limitBrotliBytes).padStart(9)}  ${result.status}`);
	}
	lines.push('', ` precache members=${report.serviceWorker.precache.memberCount} bytes=${report.serviceWorker.precache.identityBytes} brotli=${report.serviceWorker.precache.brotliBytes}`);
	return `${lines.join('\n')}\n`;
}

export function writeReport(report, outputDir) {
	mkdirSync(outputDir, { recursive: true });
	const machinePath = join(outputDir, 'asset-ledger.v1.json');
	const tablePath = join(outputDir, 'asset-ledger.v1.txt');
	writeFileSync(machinePath, `${JSON.stringify(report, null, 2)}\n`);
	writeFileSync(tablePath, makeHumanTable(report));
	return { machinePath, tablePath };
}

export function createReport({ buildDir = DEFAULTS.buildDir, manifestPath = DEFAULTS.manifestPath, budgetsPath = DEFAULTS.budgetsPath } = {}) {
	const buildFilePaths = listBuildFiles(buildDir);
	const buildFiles = new Set(buildFilePaths);
	if (!buildFiles.has('index.html')) fail('inputs_absent', 'index.html missing', 'production build has no initial document', { value: 'index.html', artifact: 'build/' });
	if (!buildFiles.has('service-worker.js')) fail('inputs_absent', 'service-worker.js missing', 'production build has no service worker', { value: 'service-worker.js', artifact: 'build/' });
	const manifest = readJson(manifestPath, 'manifest.json');
	const manifestInfo = validateManifest(manifest, buildFiles);
	manifestInfo.manifest = manifest;
	const indexHtml = readRequired(join(buildDir, 'index.html'), 'index.html').toString('utf8');
	const indexPaths = extractIndexReferences(indexHtml, buildFiles);
	const workerSource = readRequired(join(buildDir, 'service-worker.js'), 'service-worker.js').toString('utf8');
	if (!workerSource.includes('critical-shell.v1.json')) {
		fail('invalid_evidence', 'service worker ignores the critical shell manifest', 'candidate install membership is not bound to the generated manifest', { artifact: 'service-worker.js' });
	}
	const criticalShell = validateCriticalShellManifest({ buildDir, manifestPath, buildFiles });
	const representationRecords = validateRepresentationManifest(buildDir, buildFiles);
	const precacheMembers = criticalShell.members;
	const memberSet = new Set(precacheMembers);
	const indexSet = new Set(indexPaths);
	const manifestSet = new Set([...manifestInfo.references.entries()].filter(([, reference]) => reference.sources.size > 0).map(([path]) => path));
	const routeClasses = new Map();
	const publicRoute = routeClosurePaths(manifestInfo, '/', manifestPath);
	const inboxRoute = routeClosurePaths(manifestInfo, '/inbox', manifestPath);
	for (const path of publicRoute.paths) routeClasses.set(path, [...(routeClasses.get(path) ?? []), 'public-login']);
	for (const path of inboxRoute.paths) routeClasses.set(path, [...(routeClasses.get(path) ?? []), 'authenticated-inbox']);
	const records = new Map();
	for (const path of buildFilePaths) {
		const bytes = readRequired(join(buildDir, path), `build/${path}`);
		const refs = {
			clientManifest: manifestSet.has(path),
			initialIndex: indexSet.has(path),
			serviceWorker: memberSet.has(path),
			unreferencedStaticArtifact: !manifestSet.has(path) && !indexSet.has(path) && !memberSet.has(path) && !['index.html', 'service-worker.js'].includes(path),
		};
		const encoded = compress(bytes);
		const representations = representationRecords.get(path) ?? {};
		const mime = MIME_TYPES[extname(path).toLowerCase()] ?? 'application/octet-stream';
		records.set(path, {
			path,
			mime,
			mimeType: mime,
			assetClass: assetClass(path),
			identityBytes: bytes.byteLength,
			identitySha256: hash(bytes),
			gzipBytes: representations.gzip?.bytes ?? encoded.gzipBytes,
			brotliBytes: representations.br?.bytes ?? encoded.brotliBytes,
			representations,
			cacheClass: cacheClass(path, refs),
			referencedBy: refs,
			manifestSources: sorted(manifestInfo.references.get(path)?.sources ?? []),
			routeClasses: sorted(routeClasses.get(path) ?? []),
		});
	}
	const initialPaths = sorted(new Set([...indexPaths, ...publicRoute.paths]));
	const inboxPaths = sorted(new Set([...indexPaths, ...inboxRoute.paths]));
	const publicLoginJs = metricBytes(records, initialPaths.filter((path) => records.get(path)?.assetClass === 'javascript'));
	const publicLoginCss = metricBytes(records, initialPaths.filter((path) => records.get(path)?.assetClass === 'css'));
	const inboxJs = metricBytes(records, inboxPaths.filter((path) => records.get(path)?.assetClass === 'javascript'));
	const inboxCss = metricBytes(records, inboxPaths.filter((path) => records.get(path)?.assetClass === 'css'));
	if (publicRoute.status !== 'measured') publicLoginJs.status = publicLoginCss.status = 'diagnostic';
	if (inboxRoute.status !== 'measured') inboxJs.status = inboxCss.status = 'diagnostic';
	const importers = new Map();
	for (const entry of manifestInfo.graph.values()) {
		for (const output of entry.imports) {
			const list = importers.get(output) ?? [];
			list.push(entry.output);
			importers.set(output, list);
		}
	}
	const allSharedCandidates = [...importers.entries()]
		.map(([path, paths]) => ({ path, importers: sorted(new Set(paths)) }))
		.filter(({ path, importers: owners }) => records.get(path)?.assetClass === 'javascript' && owners.length > 1)
		.sort((left, right) => records.get(right.path).brotliBytes - records.get(left.path).brotliBytes || compareStrings(left.path, right.path));
	const initialClosure = new Set([...initialPaths, ...inboxPaths]);
	const sharedCandidates = allSharedCandidates.filter(({ path }) => initialClosure.has(path));
	const largestShared = sharedCandidates[0]
		? { status: 'measured', path: sharedCandidates[0].path, brotliBytes: records.get(sharedCandidates[0].path).brotliBytes, identityBytes: records.get(sharedCandidates[0].path).identityBytes, importerCount: sharedCandidates[0].importers.length, importers: sharedCandidates[0].importers }
		: { status: 'diagnostic', reason: 'no synchronously shared JavaScript output', path: null, brotliBytes: null, identityBytes: null, importerCount: 0, importers: [] };
	const globalLargestShared = allSharedCandidates[0]
		? {
			status: 'diagnostic',
			path: allSharedCandidates[0].path,
			brotliBytes: records.get(allSharedCandidates[0].path).brotliBytes,
			identityBytes: records.get(allSharedCandidates[0].path).identityBytes,
			importerCount: allSharedCandidates[0].importers.length,
			importers: allSharedCandidates[0].importers,
			reason: 'largest global shared chunk; route/action loaded and not part of the public or Inbox initial closure',
		}
		: { status: 'diagnostic', reason: 'no globally shared JavaScript output', path: null, brotliBytes: null };
	const precacheRecords = precacheMembers.map((path) => records.get(path));
	const criticalManifestRecord = records.get('critical-shell.v1.json');
	const precache = {
		members: precacheMembers,
		declaredMembers: precacheMembers,
		memberCount: precacheMembers.length,
		manifestPath: 'critical-shell.v1.json',
		identityBytes: precacheRecords.reduce((sum, record) => sum + record.identityBytes, 0) + criticalManifestRecord.identityBytes,
		gzipBytes: precacheRecords.reduce((sum, record) => sum + record.gzipBytes, 0) + criticalManifestRecord.gzipBytes,
		brotliBytes: precacheRecords.reduce((sum, record) => sum + record.brotliBytes, 0) + criticalManifestRecord.brotliBytes,
	};
	const assetList = buildFilePaths.map((path) => records.get(path));
	const workerRecord = records.get('service-worker.js');
	const metricValues = {
		publicLoginInitialJsBrotliBytes: publicLoginJs,
		publicLoginInitialCssBrotliBytes: publicLoginCss,
		largestSynchronousSharedJsBrotliBytes: largestShared.status === 'measured'
			? { status: 'measured', brotliBytes: largestShared.brotliBytes }
			: largestShared,
		serviceWorkerBrotliBytes: { status: 'measured', brotliBytes: workerRecord.brotliBytes },
		candidateShellBrotliBytes: { status: 'measured', brotliBytes: precache.brotliBytes },
		inboxInitialJsBrotliBytes: inboxJs,
		inboxInitialCssBrotliBytes: inboxCss,
	};
	const reportIdentity = {
		assets: assetList.map(({ path, identityBytes, identitySha256 }) => ({ path, identityBytes, identitySha256 })),
		precacheMembers,
	};
	const report = {
		reportVersion: REPORT_VERSION,
		schemaVersion: SCHEMA_VERSION,
		encoding: { gzip: { level: 9, mtime: 0 }, brotli: { quality: 5 } },
		buildId: criticalShell.buildId,
		artifactSetSha256: hash(Buffer.from(stableJson(reportIdentity))),
		manifest: { entryCount: manifestInfo.entries.length, outputCount: manifestInfo.outputPaths.size },
		index: { path: 'index.html', referencedAssets: indexPaths, publicLoginClosure: initialPaths },
		serviceWorker: {
			path: 'service-worker.js',
			script: { identityBytes: workerRecord.identityBytes, brotliBytes: workerRecord.brotliBytes, identitySha256: workerRecord.identitySha256 },
			precache,
		},
		aggregates: {
			publicLogin: { initialJs: publicLoginJs, initialCss: publicLoginCss },
			inbox: { initialJs: inboxJs, initialCss: inboxCss },
			largestSynchronousSharedJs: largestShared,
			largestGlobalSharedJs: globalLargestShared,
			serviceWorkerBrotliBytes: workerRecord.brotliBytes,
			candidateShellBrotliBytes: precache.brotliBytes,
			totalBuildBytes: assetList.reduce((sum, record) => sum + record.identityBytes, 0),
			totalFontBytes: assetList.filter((record) => record.assetClass === 'font').reduce((sum, record) => sum + record.identityBytes, 0),
			serviceWorkerPrecache: precache,
			publicLoginInitialJsBrotliBytes: publicLoginJs.brotliBytes ?? null,
			publicLoginInitialCssBrotliBytes: publicLoginCss.brotliBytes ?? null,
			inboxInitialJsBrotliBytes: inboxJs.brotliBytes ?? null,
			inboxInitialCssBrotliBytes: inboxCss.brotliBytes ?? null,
		},
		metricValues,
		assets: assetList,
	};
	const budgetConfig = readJson(budgetsPath, 'performance-budgets.json');
	report.budgets = compareBudgets(report, budgetConfig);
	return report;
}

function parseArgs(args) {
	const options = { ...DEFAULTS };
	for (let index = 0; index < args.length; index += 1) {
		const arg = args[index];
		if (arg === '--help' || arg === '-h') return { help: true };
		const names = { '--build': 'buildDir', '--manifest': 'manifestPath', '--budgets': 'budgetsPath', '--output': 'outputDir' };
		if (!names[arg] || index + 1 >= args.length) {
			fail('runtime_failure', 'CLI arguments are malformed', 'expected --build, --manifest, --budgets, or --output followed by a path', { value: arg, artifact: 'reporter' });
		}
		options[names[arg]] = resolve(args[++index]);
	}
	return options;
}

export function renderHumanTable(report) {
	return makeHumanTable(report);
}

export function runCli(args = process.argv.slice(2)) {
	const options = parseArgs(args);
	if (options.help) {
		process.stdout.write('Usage: node scripts/performance-report.mjs [--build DIR] [--manifest FILE] [--budgets FILE] [--output DIR]\n');
		return 0;
	}
	let report;
	try {
		report = createReport(options);
		const paths = writeReport(report, options.outputDir);
		process.stdout.write(renderHumanTable(report));
		process.stdout.write(`machine=${relative(WEBMAIL_DIR, paths.machinePath).replaceAll('\\', '/')} table=${relative(WEBMAIL_DIR, paths.tablePath).replaceAll('\\', '/')}\n`);
		assertBudgetPasses(report);
		return 0;
	} catch (error) {
		process.stderr.write(`${formatPerformanceError(error)}\n`);
		return 1;
	}
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	process.exitCode = runCli();
}
