import { describe, it, expect } from 'vitest';
import { normalizeAddresses, addressKindKey } from './directoryAddresses';
import type { DirectoryAddress } from '$lib/types/jmap';

const set = (...as: DirectoryAddress[]) => as;

describe('normalizeAddresses (ARCH-004 directory/GAL address set)', () => {
	it('puts the primary first and partitions the rest as secondary', () => {
		const r = normalizeAddresses(
			set(
				{ email: 'a.smith@example.com', type: 'alias', isPrimary: false },
				{ email: 'alice@example.com', type: 'primary', isPrimary: true },
				{ email: 'asmith@corp.local', type: 'upn', isPrimary: false }
			)
		);
		expect(r.primary).toBe('alice@example.com');
		expect(r.secondary.map((a) => a.email)).toEqual(['a.smith@example.com', 'asmith@corp.local']);
		expect(r.hasMultiple).toBe(true);
	});

	it('deduplicates case-insensitively and never repeats the primary', () => {
		const r = normalizeAddresses(
			set(
				{ email: 'Alice@Example.com', type: 'primary', isPrimary: true },
				{ email: 'alice@example.COM', type: 'alias', isPrimary: false },
				{ email: 'a.smith@example.com', type: 'alias', isPrimary: false }
			)
		);
		expect(r.primary).toBe('Alice@Example.com');
		expect(r.secondary.map((a) => a.email)).toEqual(['a.smith@example.com']);
	});

	it('treats a single address as non-multiple', () => {
		const r = normalizeAddresses(set({ email: 'solo@example.com', type: 'primary', isPrimary: true }));
		expect(r.primary).toBe('solo@example.com');
		expect(r.secondary).toEqual([]);
		expect(r.hasMultiple).toBe(false);
	});

	it('uses the first entry as primary when none is flagged', () => {
		const r = normalizeAddresses(
			set(
				{ email: 'first@example.com', type: 'alias', isPrimary: false },
				{ email: 'second@example.com', type: 'alias', isPrimary: false }
			)
		);
		expect(r.primary).toBe('first@example.com');
		expect(r.secondary.map((a) => a.email)).toEqual(['second@example.com']);
	});

	it('falls back to the bare email when the address set is absent (legacy payload)', () => {
		const r = normalizeAddresses(undefined, 'legacy@example.com');
		expect(r.primary).toBe('legacy@example.com');
		expect(r.secondary).toEqual([]);
		expect(r.hasMultiple).toBe(false);
	});

	it('ignores blank entries', () => {
		const r = normalizeAddresses(
			set(
				{ email: '  ', type: 'alias', isPrimary: false },
				{ email: 'real@example.com', type: 'primary', isPrimary: true }
			)
		);
		expect(r.primary).toBe('real@example.com');
		expect(r.hasMultiple).toBe(false);
	});
});

describe('addressKindKey', () => {
	it('maps upn to the UPN label key and everything else to the alias key', () => {
		expect(addressKindKey('upn')).toBe('directory.address.upn');
		expect(addressKindKey('alias')).toBe('directory.address.alias');
		expect(addressKindKey('primary')).toBe('directory.address.alias');
	});
});
