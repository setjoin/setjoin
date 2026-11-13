// Selftests for the route-only raw-fetch ratchet (WP5, decision 5A) defined in
// eslint.config.mjs. The rule is exercised with the stock ESLint RuleTester;
// the frozen baseline is asserted against the real census it must freeze.
//
// The ratchet binds grandfathered exceptions to EXACT call fingerprints
// (`callee + METHOD + first-argument source`, whitespace collapsed) — not
// per-file counts — so replacing an old call with a new one FAILS even though
// the per-file count stays equal.

import { describe, expect, it } from 'vitest';
import { RuleTester } from 'eslint';
import {
	routeRawFetchRule,
	routeRawFetchBaseline,
	assertRouteRawFetchBaselineWellFormed,
	// eslint.config.mjs is a plain .mjs config module (allowJs:false — no types).
	// @ts-expect-error — untyped .mjs import
} from '../../eslint.config.mjs';

const ROUTE_FILE = '/proj/src/routes/settings/+page.svelte';
const LIB_FILE = '/proj/src/lib/http.ts';
const TEST_FILE = '/proj/src/routes/inbox.test.ts';

const tester = new RuleTester();

tester.run('route-raw-fetch/no-new-raw-fetch (rule mechanics)', routeRawFetchRule, {
	valid: [
		{
			// Only src/routes/** is ratcheted — lib seams keep their own fetch.
			code: 'await fetch("/x");',
			filename: LIB_FILE,
		},
		{
			// Route test files are exempt: fetch mocks stay allowed.
			code: 'vi.stubGlobal("fetch", vi.fn()); fetch("/x");',
			filename: TEST_FILE,
		},
		{
			// The exact frozen fingerprint passes.
			code: 'await fetch("/a");',
			filename: ROUTE_FILE,
			options: [{ baseline: { 'settings/+page.svelte': { calls: ['fetch GET "/a"'], reason: 'grandfathered legacy call' } } }],
		},
		{
			// Formatting and an explicit method are fingerprint-invariant:
			// the collapsed text + uppercased method match the same entry.
			code: 'await fetch(\n\t"/a",\n\t{ method: "get", credentials: "include" }\n);',
			filename: ROUTE_FILE,
			options: [{ baseline: { 'settings/+page.svelte': { calls: ['fetch GET "/a"'], reason: 'grandfathered legacy call' } } }],
		},
		{
			// Duplicated grandfathered calls pass when the baseline lists the
			// fingerprint twice (multiset semantics).
			code: 'await fetch("/a"); await fetch("/a");',
			filename: ROUTE_FILE,
			options: [{ baseline: { 'settings/+page.svelte': { calls: ['fetch GET "/a"', 'fetch GET "/a"'], reason: 'grandfathered duplicate calls' } } }],
		},
		{
			// No fetches at all — with or without a baseline entry.
			code: 'const x = 1;',
			filename: ROUTE_FILE,
			options: [{ baseline: {} }],
		},
		{
			// The typed seams are not raw fetches.
			code: 'const x = await typedFetch("/a"); api.fetch("/b");',
			filename: ROUTE_FILE,
			options: [{ baseline: {} }],
		},
	],
	invalid: [
		{
			// A raw fetch in a route with no baseline entry fails outright.
			code: 'await fetch("/a");',
			filename: ROUTE_FILE,
			options: [{ baseline: {} }],
			errors: [{ messageId: 'noBaseline' }],
		},
		{
			// globalThis.fetch is counted (and fingerprinted) exactly like fetch.
			code: 'globalThis.fetch("/a");',
			filename: ROUTE_FILE,
			options: [{ baseline: {} }],
			errors: [{ messageId: 'noBaseline' }],
		},
		{
			// THE ratchet demo (finding 8): REPLACING an old grandfathered call
			// with a new one at the SAME per-file count FAILS — the new call's
			// fingerprint is unknown and the removed one is stale. (RuleTester
			// compares position-sorted messages: the stale report anchors on the
			// first call, which sorts before the unknown one.)
			code: 'await fetch("/a"); await fetch("/new-bypass");',
			filename: '/proj/src/routes/inbox/+page.svelte',
			options: [{ baseline: { 'inbox/+page.svelte': { calls: ['fetch GET "/a"', 'fetch GET "/old"'], reason: 'legacy inbox actions, awaiting migration' } } }],
			errors: [{ messageId: 'staleBaseline' }, { messageId: 'unknownCall' }],
		},
		{
			// A newly planted call in an already grandfathered file fails — the
			// baseline is a per-fingerprint allowlist, not a license.
			code: 'await fetch("/a"); await fetch("/b"); await fetch("/c");',
			filename: '/proj/src/routes/inbox/+page.svelte',
			options: [{ baseline: { 'inbox/+page.svelte': { calls: ['fetch GET "/a"', 'fetch GET "/b"'], reason: 'legacy inbox actions, awaiting migration' } } }],
			errors: [{ messageId: 'unknownCall' }],
		},
		{
			// Duplicating a grandfathered call beyond its frozen count is new.
			code: 'await fetch("/a"); await fetch("/a");',
			filename: ROUTE_FILE,
			options: [{ baseline: { 'settings/+page.svelte': { calls: ['fetch GET "/a"'], reason: 'grandfathered legacy call' } } }],
			errors: [{ messageId: 'unknownCall' }],
		},
		{
			// The callee participates in the fingerprint: window.fetch is not
			// the grandfathered bare fetch.
			code: 'window.fetch("/a");',
			filename: ROUTE_FILE,
			options: [{ baseline: { 'settings/+page.svelte': { calls: ['fetch GET "/a"'], reason: 'grandfathered legacy call' } } }],
			errors: [{ messageId: 'unknownCall' }, { messageId: 'staleBaseline' }],
		},
		{
			// The method participates in the fingerprint: the same URL on a
			// different method is a different (unknown) call.
			code: 'await fetch("/a", { method: "POST" });',
			filename: ROUTE_FILE,
			options: [{ baseline: { 'settings/+page.svelte': { calls: ['fetch GET "/a"'], reason: 'grandfathered legacy call' } } }],
			errors: [{ messageId: 'unknownCall' }, { messageId: 'staleBaseline' }],
		},
		{
			// A file that DROPPED a call fails as stale — the census must shrink
			// in the same change that removes calls.
			code: 'await fetch("/a");',
			filename: ROUTE_FILE,
			options: [{ baseline: { 'settings/+page.svelte': { calls: ['fetch GET "/a"', 'fetch GET "/b"'], reason: 'grandfathered legacy calls' } } }],
			errors: [{ messageId: 'staleBaseline' }],
		},
		{
			// A file with an entry but zero calls is stale — remove the entry
			// when a file goes clean.
			code: 'const x = 1;',
			filename: ROUTE_FILE,
			options: [{ baseline: { 'settings/+page.svelte': { calls: ['fetch GET "/a"'], reason: 'grandfathered legacy call' } } }],
			errors: [{ messageId: 'staleBaseline' }],
		},
	],
});

describe('route raw-fetch baseline (frozen census)', () => {
	it('rejects stale or unreasoned baseline entries', () => {
		expect(() =>
			assertRouteRawFetchBaselineWellFormed({ 'a/+page.svelte': { calls: ['fetch GET "/a"'], reason: '' } })
		).toThrow();
		expect(() =>
			assertRouteRawFetchBaselineWellFormed({ 'a/+page.svelte': { calls: [], reason: 'reason text here' } })
		).toThrow();
		expect(() =>
			assertRouteRawFetchBaselineWellFormed({ 'a/+page.svelte': { reason: 'a real reason' } })
		).toThrow();
		expect(() =>
			assertRouteRawFetchBaselineWellFormed({ 'a/+page.svelte': { calls: ['fetch GET "/a"'], count: 1 } })
		).toThrow();
		expect(() =>
			assertRouteRawFetchBaselineWellFormed({ 'a/+page.svelte': { calls: ['fetch GET "/a"'], reason: 'a real reason' } })
		).not.toThrow();
	});

	it('freezes the post-completion census: 16 grandfathered files, 42 calls', () => {
		const files = Object.keys(routeRawFetchBaseline);
		expect(files).toHaveLength(16);
		const entries = routeRawFetchBaseline as Record<string, { calls: string[]; reason: string }>;
		const total = Object.values(entries).reduce((sum, e) => sum + e.calls.length, 0);
		expect(total).toBe(42);
		// Every fingerprint names its raw callee and method — the binding the
		// review demanded instead of per-file counts.
		for (const [file, entry] of Object.entries(entries)) {
			for (const fp of entry.calls) {
				expect(fp, `${file}: ${fp}`).toMatch(/^(fetch|window\.fetch|globalThis\.fetch) (GET|POST|PUT|DELETE|PATCH|HEAD) /);
			}
		}
	});

	it('gives the four migrated routes no grandfathering', () => {
		const entries = routeRawFetchBaseline as Record<string, { calls: string[] } | undefined>;
		// Fully migrated: any new raw fetch in these files fails with noBaseline.
		expect(entries['settings/signatures/+page.svelte']).toBeUndefined();
		expect(entries['settings/privacy/+page.svelte']).toBeUndefined();
		expect(entries['quarantine/+page.svelte']).toBeUndefined();
		expect(entries['settings/security/+page.svelte']).toBeUndefined();
	});
});
