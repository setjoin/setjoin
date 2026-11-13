import { describe, it, expect } from 'vitest';
import { normalizeOptions, type SelectOption } from './types';

describe('normalizeOptions', () => {
	it('maps plain strings to {value,label} pairs with value === label', () => {
		expect(normalizeOptions(['Later today', 'Next week'])).toEqual([
			{ value: 'Later today', label: 'Later today' },
			{ value: 'Next week', label: 'Next week' }
		]);
	});

	it('passes through {value,label} objects unchanged', () => {
		const opts: SelectOption[] = [
			{ value: 'super_admin', label: 'Super admin' },
			{ value: 'auditor', label: 'Auditor' }
		];
		expect(normalizeOptions(opts)).toEqual(opts);
	});

	it('handles mixed arrays and preserves order', () => {
		expect(normalizeOptions(['a', { value: 'b', label: 'B' }])).toEqual([
			{ value: 'a', label: 'a' },
			{ value: 'b', label: 'B' }
		]);
	});

	it('returns an empty array for empty input', () => {
		expect(normalizeOptions([])).toEqual([]);
	});
});
