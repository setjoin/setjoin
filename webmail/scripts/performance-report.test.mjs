import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
	assertBudgetPasses,
	createReport,
	formatPerformanceError,
	PerformanceError,
} from './performance-report.mjs';

const LIMITS = {
	loginJs: 1_000_000,
	loginCss: 1_000_000,
	sharedChunk: 1_000_000,
	serviceWorker: 1_000_000,
	candidateShell: 1_000_000,
	inboxJs: 1_000_000,
	inboxCss: 1_000_000,
};

const METRIC_BY_ID = {
	loginJs: 'publicLoginInitialJsBrotliBytes',
	loginCss: 'publicLoginInitialCssBrotliBytes',
	sharedChunk: 'largestSynchronousSharedJsBrotliBytes',
	serviceWorker: 'serviceWorkerBrotliBytes',
	candidateShell: 'candidateShellBrotliBytes',
	inboxJs: 'inboxInitialJsBrotliBytes',
	inboxCss: 'inboxInitialCssBrotliBytes',
};

function makeFixture({ manifest = null, worker = null, limits = LIMITS, fileOrder = 'forward' } = {}) {
	const root = mkdtempSync(join(tmpdir(), 'setjoin-webmail-perf-'));
	const buildDir = join(root, 'build');
	const manifestPath = join(root, '.svelte-kit/output/client/.vite/manifest.json');
	const budgetsPath = join(root, 'performance-budgets.json');
	mkdirSync(buildDir, { recursive: true });
	mkdirSync(join(root, '.svelte-kit/output/client/.vite'), { recursive: true });
	const files = {
		'index.html': `<!doctype html><html><head><link rel="stylesheet" href="/page.css"></head><body><script src="/page.js"></script><script>navigator.serviceWorker.register('/service-worker.js')</script></body></html>`,
		'page.js': 'export const page = true;\n',
		'page.css': 'body { color: black; }\n',
		'inbox.js': 'export const inbox = true;\n',
		'inbox.css': '.inbox { display: block; }\n',
		'shared.js': 'export const shared = true;\n',
		'font.woff2': 'fixture-font',
		'_app/version.json': JSON.stringify({ version: 'fixture-build' }),
		'service-worker.js': worker ?? `const manifest = '/critical-shell.v1.json'; self.addEventListener('install', (event) => event.waitUntil(fetch(manifest)));`,
	};
	const entries = fileOrder === 'reverse' ? [...Object.entries(files)].reverse() : Object.entries(files);
	for (const [path, contents] of entries) {
		mkdirSync(join(buildDir, path, '..'), { recursive: true });
		writeFileSync(join(buildDir, path), contents);
	}
	const defaultManifest = {
		'src/routes/+page.svelte': { file: 'page.js', imports: ['shared.js'], css: ['page.css'], isEntry: true },
		'src/routes/inbox/+page.svelte': { file: 'inbox.js', imports: ['shared.js'], css: ['inbox.css'], isEntry: true },
		'shared.js': { file: 'shared.js' },
	};
	writeFileSync(manifestPath, JSON.stringify(manifest ?? defaultManifest, null, 2));
	const shellMembers = ['_app/version.json', 'index.html', 'page.css', 'page.js', 'shared.js'];
	writeFileSync(join(buildDir, 'critical-shell.v1.json'), JSON.stringify({
		schemaVersion: 1,
		protocolVersion: 1,
		buildId: 'fixture-build',
		members: shellMembers.map((path) => {
			const bytes = readFileSync(join(buildDir, path));
			return { path: `/${path}`, identityBytes: bytes.byteLength, sha256: createHash('sha256').update(bytes).digest('hex') };
		}),
	}, null, 2));
	const identityFiles = Object.keys(files).concat('critical-shell.v1.json').sort();
	writeFileSync(join(buildDir, 'static-representations.v1.json'), JSON.stringify({
		schemaVersion: 1,
		buildId: 'fixture-build',
		parameters: { gzip: { level: 9, mtime: 0 }, brotli: { quality: 5 } },
		assets: identityFiles.map((path) => {
			const bytes = readFileSync(join(buildDir, path));
			return { path: `/${path}`, identityBytes: bytes.byteLength, identitySha256: createHash('sha256').update(bytes).digest('hex'), representations: {} };
		}),
	}, null, 2));
	writeFileSync(budgetsPath, JSON.stringify({
		schemaVersion: 1,
		budgets: Object.fromEntries(Object.entries(limits).map(([id, limitBytes]) => [id, {
			metric: METRIC_BY_ID[id],
			limitBytes,
			required: true,
		} ])),
	}, null, 2));
	return { root, buildDir, manifestPath, budgetsPath };
}

function cleanup(fixture) {
	rmSync(fixture.root, { recursive: true, force: true });
}

function create(fixture) {
	return createReport({
		buildDir: fixture.buildDir,
		manifestPath: fixture.manifestPath,
		budgetsPath: fixture.budgetsPath,
	});
}

test('valid minimal fixture emits a measured, sorted ledger', () => {
	const fixture = makeFixture();
	try {
		const report = create(fixture);
		assert.equal(report.reportVersion, 'webmail-performance-asset-ledger-v1');
		assert.equal(report.schemaVersion, 1);
		assert.equal(report.budgets.verdict, 'pass');
		assert.doesNotThrow(() => assertBudgetPasses(report));
		assert.deepEqual(report.assets.map((asset) => asset.path), [...report.assets].map((asset) => asset.path).sort());
		assert.ok(report.assets.every((asset) => asset.identitySha256.length === 64));
		assert.equal(report.serviceWorker.precache.members.length, 5);
		assert.equal(report.aggregates.totalFontBytes, 'fixture-font'.length);
		assert.equal(report.aggregates.publicLogin.initialJs.status, 'measured');
		assert.equal(report.aggregates.inbox.initialCss.status, 'measured');
		assert.equal(report.aggregates.largestSynchronousSharedJs.path, 'shared.js');
		assert.equal(report.aggregates.largestGlobalSharedJs.path, 'shared.js');
		const app = report.assets.find((asset) => asset.path === 'page.js');
		assert.deepEqual(app.referencedBy, {
			clientManifest: true,
			initialIndex: true,
			serviceWorker: true,
			unreferencedStaticArtifact: false,
		});
		const font = report.assets.find((asset) => asset.path === 'font.woff2');
		assert.equal(font.referencedBy.unreferencedStaticArtifact, true);
	} finally {
		cleanup(fixture);
	}
});

test('identical inputs have identical output regardless of filesystem write order', () => {
	const first = makeFixture({ fileOrder: 'forward' });
	const second = makeFixture({ fileOrder: 'reverse' });
	try {
		const firstReport = create(first);
		const secondReport = create(second);
		assert.deepEqual(firstReport, secondReport);
	} finally {
		cleanup(first);
		cleanup(second);
	}
});

test('missing build input fails closed', () => {
	const fixture = makeFixture();
	try {
		rmSync(fixture.buildDir, { recursive: true, force: true });
		assert.throws(() => create(fixture), (error) => error instanceof PerformanceError && error.kind === 'inputs_absent');
	} finally {
		cleanup(fixture);
	}
});

test('malformed manifest fails closed', () => {
	const fixture = makeFixture();
	try {
		writeFileSync(fixture.manifestPath, '{"broken":');
		assert.throws(() => create(fixture), (error) => error instanceof PerformanceError && error.kind === 'invalid_evidence');
	} finally {
		cleanup(fixture);
	}
});

test('duplicate manifest output paths fail closed', () => {
	const fixture = makeFixture({
		manifest: {
			'a.js': { file: 'page.js' },
			'b.js': { file: 'page.js' },
		},
	});
	try {
		assert.throws(() => create(fixture), (error) => error instanceof PerformanceError && error.problem === 'duplicate output path');
	} finally {
		cleanup(fixture);
	}
});

test('oversize deterministic budget fails the release assertion', () => {
	const fixture = makeFixture({ limits: { ...LIMITS, loginJs: 1 } });
	try {
		const report = create(fixture);
		assert.equal(report.budgets.results.find((result) => result.id === 'loginJs').status, 'fail');
		assert.throws(() => assertBudgetPasses(report), (error) => error instanceof PerformanceError && error.kind === 'policy_violation');
	} finally {
		cleanup(fixture);
	}
});

test('a worker that ignores the generated critical shell fails closed', () => {
	const fixture = makeFixture({ worker: `self.addEventListener('install', () => {});` });
	try {
		assert.throws(() => create(fixture), (error) => error instanceof PerformanceError && error.problem === 'service worker ignores the critical shell manifest');
	} finally {
		cleanup(fixture);
	}
});

test('a tampered critical-shell member fails closed', () => {
	const fixture = makeFixture();
	try {
		writeFileSync(join(fixture.buildDir, 'page.js'), 'tampered');
		assert.throws(() => create(fixture), (error) => error instanceof PerformanceError && error.problem === 'critical shell size is stale');
	} finally {
		cleanup(fixture);
	}
});

test('stable errors use the required machine-readable grammar without absolute paths', () => {
	const error = new PerformanceError({
		kind: 'inputs_absent',
		problem: 'required input missing',
		cause: 'not found',
		value: 'build/',
		artifact: 'build/',
		fix: 'run npm run build',
	});
	const line = formatPerformanceError(error);
	assert.match(line, /^E_WEBMAIL_PERF_INPUTS_ABSENT problem=\S+ cause=\S+ value=\S+ artifact=\S+ fix='[^']+' rerun='[^']+'$/);
	assert.equal(line.includes('/Users/'), false);
});

test('committed budget file retains the normative thresholds', () => {
	const budgets = JSON.parse(readFileSync(new URL('../performance-budgets.json', import.meta.url), 'utf8')).budgets;
	assert.deepEqual(Object.fromEntries(Object.entries(budgets).map(([id, record]) => [id, record.limitBytes])), {
		loginJs: 204800,
		loginCss: 40960,
		sharedChunk: 153600,
		serviceWorker: 102400,
		candidateShell: 1048576,
		inboxJs: 358400,
		inboxCss: 61440,
	});
});
