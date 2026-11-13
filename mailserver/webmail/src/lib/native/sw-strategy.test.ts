import { describe, it, expect } from 'vitest';
import { chooseStrategy } from './sw-strategy';

describe('chooseStrategy', () => {
	const publicAssets = new Set(['/_app/immutable/chunk.js', '/manifest.webmanifest']);

	it('serves only exact manifest-declared public assets cache-first', () => {
		expect(chooseStrategy(new URL('https://h/_app/immutable/chunk.js'), 'GET', publicAssets)).toBe('cache-first');
		expect(chooseStrategy(new URL('https://h/manifest.webmanifest'), 'GET', publicAssets)).toBe('cache-first');
		expect(chooseStrategy(new URL('https://h/_app/immutable/chunk.js.map'), 'GET', publicAssets)).toBe('network-only');
		expect(chooseStrategy(new URL('https://h/unknown.js'), 'GET', publicAssets)).toBe('network-only');
	});

	it('keeps query-bearing assets network-only even when the pathname is public', () => {
		expect(chooseStrategy(new URL('https://h/_app/immutable/chunk.js?token=secret'), 'GET', publicAssets)).toBe('network-only');
	});

	it('serves JMAP / API / auth network-only', () => {
		expect(chooseStrategy(new URL('https://h/jmap/'), 'GET')).toBe('network-only');
		expect(chooseStrategy(new URL('https://h/.well-known/jmap'), 'GET')).toBe('network-only');
		expect(chooseStrategy(new URL('https://h/api/v1/version'), 'GET')).toBe('network-only');
	});

	it('does not let a malformed public manifest override sensitive route classes', () => {
		const poisoned = new Set(['/api/me/approvals', '/jmap/download/x', '/blobs/x']);
		expect(chooseStrategy(new URL('https://h/api/me/approvals'), 'GET', poisoned)).toBe('network-only');
		expect(chooseStrategy(new URL('https://h/jmap/download/x'), 'GET', poisoned)).toBe('network-only');
		expect(chooseStrategy(new URL('https://h/blobs/x'), 'GET', poisoned)).toBe('network-only');
	});

	it('serves authenticated admin / per-user reads network-only', () => {
		expect(chooseStrategy(new URL('https://h/api/admin/approval-policies?consumer_type=x'), 'GET')).toBe('network-only');
		expect(chooseStrategy(new URL('https://h/api/me/approvals'), 'GET')).toBe('network-only');
		expect(chooseStrategy(new URL('https://h/api/user/login-history'), 'GET')).toBe('network-only');
		expect(chooseStrategy(new URL('https://h/terms/pending'), 'GET')).toBe('network-only');
	});

	it('never caches non-GET', () => {
		expect(chooseStrategy(new URL('https://h/_app/x.js'), 'POST', publicAssets)).toBe('passthrough');
	});

	it('keeps the /mail-attachment content route network-only (no drift with the shell ban list)', () => {
		const sha = 'a'.repeat(64);
		expect(chooseStrategy(new URL('https://h/mail-attachment/' + sha), 'GET')).toBe('network-only');
		// Even a poisoned manifest entry naming the attachment route stays banned.
		const poisoned = new Set(['/mail-attachment/' + sha]);
		expect(chooseStrategy(new URL('https://h/mail-attachment/' + sha), 'GET', poisoned)).toBe('network-only');
	});
});
