import { describe, expect, it } from 'vitest';
import { parseOIDCOPContinuation } from './oidcContinue';

describe('parseOIDCOPContinuation', () => {
	it('accepts and normalizes the exact OIDC OP completion route', () => {
		expect(
			parseOIDCOPContinuation('/auth/oidc/op/complete?id=request%201'),
		).toBe('/auth/oidc/op/complete?id=request%201');
	});

	it.each([
		null,
		'',
		'https://evil.example/auth/oidc/op/complete?id=x',
		'//evil.example/auth/oidc/op/complete?id=x',
		'/apps',
		'/auth/oidc/op/complete',
		'/auth/oidc/op/complete?id=x&id=y',
		'/auth/oidc/op/complete?id=x&next=%2Fapps',
		'/auth/oidc/op/complete?id=x#fragment',
	])('rejects an unsafe or unrelated continuation: %s', (raw) => {
		expect(parseOIDCOPContinuation(raw)).toBeNull();
	});

	it('rejects an oversized request identifier', () => {
		expect(
			parseOIDCOPContinuation(
				`/auth/oidc/op/complete?id=${'x'.repeat(257)}`,
			),
		).toBeNull();
	});
});
