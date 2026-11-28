import { describe, expect, it } from 'vitest';
import { isExternalParticipant } from './participantAttributes';

describe('isExternalParticipant', () => {
	it('accepts only the exact server-authored true attribute', () => {
		expect(isExternalParticipant({ attributes: { 'setjoin.external': 'true' } })).toBe(true);
		expect(isExternalParticipant({ attributes: { 'setjoin.external': 'false' } })).toBe(false);
		expect(isExternalParticipant({ attributes: { 'setjoin.external': 'TRUE' } })).toBe(false);
		expect(isExternalParticipant({ attributes: {} })).toBe(false);
		expect(isExternalParticipant(undefined)).toBe(false);
	});
});
