import { readFile, writeFile } from 'node:fs/promises';

export const REQUIRED_SCENARIOS = Object.freeze({
	'public-login-cold-en': ['public-visible', 'public-interactive'],
	'public-login-warm-en': ['public-visible', 'public-interactive'],
	'inbox-cold': ['shell-visible', 'inbox-list-visible', 'inbox-interactive'],
	'inbox-warm': ['shell-visible', 'inbox-list-visible', 'inbox-interactive'],
});

function visit(value, callback) {
	if (!value || typeof value !== 'object') return;
	callback(value);
	for (const child of Array.isArray(value) ? value : Object.values(value)) visit(child, callback);
}

function decodeAttachment(attachment) {
	if (typeof attachment?.body !== 'string') {
		throw new Error(`attachment ${attachment?.name ?? '<unknown>'} has no embedded body`);
	}
	return JSON.parse(Buffer.from(attachment.body, 'base64').toString('utf8'));
}

function percentile(values, fraction) {
	if (values.length === 0) throw new Error('cannot summarize an empty sample set');
	const sorted = [...values].sort((left, right) => left - right);
	return sorted[Math.ceil(fraction * sorted.length) - 1];
}

function summarizeMetric(values) {
	return {
		median: percentile(values, 0.5),
		p95: percentile(values, 0.95),
		min: Math.min(...values),
		max: Math.max(...values),
	};
}

export function buildPerformanceSummary(report, expectedSamples) {
	if (!Number.isInteger(expectedSamples) || expectedSamples < 1) {
		throw new Error('expectedSamples must be a positive integer');
	}
	if (report?.stats?.unexpected !== 0 || report?.stats?.flaky !== 0) {
		throw new Error(`Playwright verdict is not clean (unexpected=${report?.stats?.unexpected}, flaky=${report?.stats?.flaky})`);
	}

	const attachments = new Map();
	visit(report, (value) => {
		for (const attachment of value.attachments ?? []) {
			if (attachment?.name) attachments.set(attachment.name, attachment);
		}
	});

	const samples = [
		...decodeAttachment(attachments.get('public-login-performance.json')),
		...decodeAttachment(attachments.get('inbox-performance.json')),
	];
	const scenarios = {};
	for (const [scenario, requiredMarks] of Object.entries(REQUIRED_SCENARIOS)) {
		const observed = samples.filter((sample) => sample.scenario === scenario);
		if (observed.length !== expectedSamples) {
			throw new Error(`scenario ${scenario} has ${observed.length} samples, expected ${expectedSamples}`);
		}
		const ordinals = observed.map((sample) => sample.ordinal).sort((left, right) => left - right);
		if (ordinals.some((ordinal, index) => ordinal !== index)) {
			throw new Error(`scenario ${scenario} has missing or duplicate sample ordinals`);
		}
		const marks = {};
		for (const mark of requiredMarks) {
			const values = observed.map((sample) => sample.marks?.[mark]);
			if (values.some((value) => typeof value !== 'number' || !Number.isFinite(value))) {
				throw new Error(`scenario ${scenario} has an invalid ${mark} mark`);
			}
			marks[mark] = summarizeMetric(values);
		}
		const navigation = {};
		for (const metric of ['ttfb', 'domInteractive', 'domComplete', 'load']) {
			const values = observed.map((sample) => sample.navigation?.[metric]);
			if (values.some((value) => typeof value !== 'number' || !Number.isFinite(value))) {
				throw new Error(`scenario ${scenario} has an invalid ${metric} navigation metric`);
			}
			navigation[metric] = summarizeMetric(values);
		}
		scenarios[scenario] = { samples: observed.length, marks, navigation };
	}

	const cacheAudit = decodeAttachment(attachments.get('cache-audit.json'));
	const cjkAudit = decodeAttachment(attachments.get('cjk-network.json'));
	return {
		schemaVersion: 1,
		verdict: 'pass',
		expectedSamples,
		scenarios,
		cacheAudit: {
			cacheNames: cacheAudit.names,
			cachedUrlCount: cacheAudit.urls.length,
		},
		cjkAudit: {
			fallbackRequestCount: cjkAudit.fallbackRequests.length,
		},
	};
}

async function main() {
	const [reportPath, outputPath, rawExpectedSamples] = process.argv.slice(2);
	if (!reportPath || !outputPath || !rawExpectedSamples) {
		throw new Error('usage: node scripts/performance-evidence.mjs <playwright.json> <output.json> <expected-samples>');
	}
	const report = JSON.parse(await readFile(reportPath, 'utf8'));
	const summary = buildPerformanceSummary(report, Number.parseInt(rawExpectedSamples, 10));
	await writeFile(outputPath, `${JSON.stringify(summary, null, 2)}\n`);
}

if (process.argv[1]?.endsWith('performance-evidence.mjs')) {
	main().catch((error) => {
		console.error(`E_WEBMAIL_PERF_INVALID_EVIDENCE problem=browser_summary_invalid cause=${JSON.stringify(error.message)} value=playwright.json artifact=performance-summary.v1.json fix='inspect the retained Playwright report and rerun the failed scenario' rerun='bash scripts/verify-webmail-performance.sh diagnostic'`);
		process.exitCode = 1;
	});
}
