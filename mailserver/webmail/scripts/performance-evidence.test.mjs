import assert from 'node:assert/strict';
import test from 'node:test';

import { buildPerformanceSummary, REQUIRED_SCENARIOS } from './performance-evidence.mjs';

function attachment(name, value) {
	return { name, body: Buffer.from(JSON.stringify(value)).toString('base64') };
}

function sample(scenario, ordinal = 0) {
	const marks = Object.fromEntries(REQUIRED_SCENARIOS[scenario].map((mark, index) => [mark, 10 + index]));
	return { scenario, ordinal, marks, navigation: { ttfb: 1, domInteractive: 2, domComplete: 3, load: 4 } };
}

function report(overrides = {}) {
	return {
		stats: { unexpected: 0, flaky: 0 },
		suites: [{ specs: [{ tests: [{ results: [{ attachments: [
			attachment('public-login-performance.json', [sample('public-login-cold-en'), sample('public-login-warm-en')]),
			attachment('inbox-performance.json', [sample('inbox-cold'), sample('inbox-warm')]),
			attachment('cache-audit.json', { names: ['shell'], urls: ['https://example.test/index.html'] }),
			attachment('cjk-network.json', { fallbackRequests: [] }),
		] }] }] }] }],
		...overrides,
	};
}

test('summarizes the exact required browser scenarios', () => {
	const summary = buildPerformanceSummary(report(), 1);
	assert.equal(summary.verdict, 'pass');
	assert.equal(summary.scenarios['inbox-cold'].marks['inbox-interactive'].p95, 12);
	assert.equal(summary.cjkAudit.fallbackRequestCount, 0);
});

test('fails closed when a named scenario is absent', () => {
	const value = report();
	value.suites[0].specs[0].tests[0].results[0].attachments[1] = attachment('inbox-performance.json', [sample('inbox-cold')]);
	assert.throws(() => buildPerformanceSummary(value, 1), /inbox-warm has 0 samples/);
});

test('fails closed when sample ordinals are duplicated', () => {
	const value = report();
	value.suites[0].specs[0].tests[0].results[0].attachments[0] = attachment('public-login-performance.json', [
		sample('public-login-cold-en', 0),
		sample('public-login-cold-en', 0),
		sample('public-login-warm-en', 0),
		sample('public-login-warm-en', 1),
	]);
	value.suites[0].specs[0].tests[0].results[0].attachments[1] = attachment('inbox-performance.json', [
		sample('inbox-cold', 0), sample('inbox-cold', 1), sample('inbox-warm', 0), sample('inbox-warm', 1),
	]);
	assert.throws(() => buildPerformanceSummary(value, 2), /missing or duplicate sample ordinals/);
});

test('fails closed on a flaky Playwright verdict', () => {
	assert.throws(() => buildPerformanceSummary(report({ stats: { unexpected: 0, flaky: 1 } }), 1), /not clean/);
});

test('fails closed when a required mark is malformed', () => {
	const value = report();
	const samples = [sample('inbox-cold'), sample('inbox-warm')];
	delete samples[0].marks['inbox-interactive'];
	value.suites[0].specs[0].tests[0].results[0].attachments[1] = attachment('inbox-performance.json', samples);
	assert.throws(() => buildPerformanceSummary(value, 1), /invalid inbox-interactive/);
});
