import { describe, it, expect } from 'vitest';
import { enrollBadge, actionsFor, relativeAge, queueEmptyKind, formatCount } from './device-lockdown';

describe('device-lockdown helpers', () => {
	it('maps every enroll state to a badge', () => {
		expect(enrollBadge('enrolled').variant).toBe('warning');
		expect(enrollBadge('approved').variant).toBe('success');
		expect(enrollBadge('revoked').variant).toBe('danger');
		expect(enrollBadge('unenrolled').variant).toBe('neutral');
	});

	it('offers approve for a waiting device, revoke for approved, nothing for revoked', () => {
		expect(actionsFor('enrolled')).toEqual(['approve', 'revoke']);
		expect(actionsFor('approved')).toEqual(['revoke']);
		expect(actionsFor('revoked')).toEqual([]);
	});

	it('distinguishes a truly-empty queue from a filtered-empty one', () => {
		expect(queueEmptyKind({ state: 'enrolled', query: '' })).toBe('caught_up');
		expect(queueEmptyKind({ state: 'enrolled', query: 'bob' })).toBe('no_match');
		expect(queueEmptyKind({ state: 'revoked', query: '' })).toBe('no_match');
	});

	it('renders a relative age', () => {
		const now = Date.now();
		expect(relativeAge(new Date(now - 2 * 3600_000).toISOString(), now)).toMatch(/2/);
	});

	it('formats huge counts with thousands separators', () => {
		expect(formatCount(1204)).toMatch(/1[.,\s]?204/); // locale-grouped
	});
});
