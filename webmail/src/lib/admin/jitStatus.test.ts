import { describe, it, expect } from 'vitest';
import { roleStatus, remainingMinutes, splitWindow } from './jitStatus';
import type { MyRole } from './client';

const NOW = 1_000_000_000_000;

function role(over: Partial<MyRole>): MyRole {
	return {
		roleGroupId: 1,
		name: 'R',
		eligible: true,
		activatedUntil: null,
		expiresAt: null,
		policy: { maxDurationMinutes: 60, requireJustification: false },
		...over,
	};
}

describe('jitStatus', () => {
	it('standing = not eligible', () => {
		expect(roleStatus(role({ eligible: false }), NOW)).toBe('standing');
	});

	it('dormant = eligible with no live window', () => {
		expect(roleStatus(role({ eligible: true, activatedUntil: null }), NOW)).toBe('dormant');
		// past window also reads dormant
		expect(roleStatus(role({ activatedUntil: new Date(NOW - 1000).toISOString() }), NOW)).toBe('dormant');
	});

	it('active above 5 min, expiring at/below 5 min', () => {
		expect(roleStatus(role({ activatedUntil: new Date(NOW + 10 * 60_000).toISOString() }), NOW)).toBe('active');
		expect(roleStatus(role({ activatedUntil: new Date(NOW + 4 * 60_000).toISOString() }), NOW)).toBe('expiring');
	});

	it('remainingMinutes rounds up; splitWindow folds exact hours', () => {
		expect(remainingMinutes(role({ activatedUntil: new Date(NOW + 90_000).toISOString() }), NOW)).toBe(2);
		expect(splitWindow(30)).toEqual({ n: 30, unit: 'min' });
		expect(splitWindow(120)).toEqual({ n: 2, unit: 'hr' });
	});
});
