import { describe, it, expect } from 'vitest';
import { isSupportedMajor, parseMajor, fetchLatestElectronMajor } from './patch-cadence';

describe('patch-cadence boundary (N-2 pass / N-3 fail)', () => {
	it('passes at latest, latest-1, latest-2', () => {
		expect(isSupportedMajor(43, 43)).toBe(true);
		expect(isSupportedMajor(42, 43)).toBe(true);
		expect(isSupportedMajor(41, 43)).toBe(true);
	});
	it('fails at latest-3 and older', () => {
		expect(isSupportedMajor(40, 43)).toBe(false);
		expect(isSupportedMajor(30, 43)).toBe(false);
	});
	it('parses the major from a version range', () => {
		expect(parseMajor('^43.0.0')).toBe(43);
		expect(parseMajor('43.1.2')).toBe(43);
		expect(() => parseMajor('latest')).toThrow();
	});
	it('fetchLatestElectronMajor returns null (skip-not-fail) on a network error', async () => {
		const boom: typeof fetch = (async () => {
			throw new Error('network down');
		}) as typeof fetch;
		expect(await fetchLatestElectronMajor(boom)).toBeNull();
	});
	it('fetchLatestElectronMajor reads npm latest stable dist-tag', async () => {
		const feed: typeof fetch = (async () =>
			new Response(JSON.stringify({ version: '43.2.1' }), {
				status: 200,
			})) as typeof fetch;
		expect(await fetchLatestElectronMajor(feed)).toBe(43);
	});
	it('fetchLatestElectronMajor rejects malformed registry payloads', async () => {
		const malformed: typeof fetch = (async () =>
			new Response(JSON.stringify({ version: 'not-a-version' }), { status: 200 })) as typeof fetch;
		expect(await fetchLatestElectronMajor(malformed)).toBeNull();
	});
});
