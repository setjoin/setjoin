import { describe, it, expect } from 'vitest';
import { effectiveAccess, GLOBAL_FEATURE_MAP } from './appAccess';

describe('effectiveAccess', () => {
	it('returns blocked and limitedGlobally when global toggle is false, regardless of perUser', () => {
		const result = effectiveAccess(false, true);
		expect(result.effective).toBe(false);
		expect(result.limitedGlobally).toBe(true);
	});

	it('returns blocked and limitedGlobally when global toggle is false, even if perUser is also false', () => {
		const result = effectiveAccess(false, false);
		expect(result.effective).toBe(false);
		expect(result.limitedGlobally).toBe(true);
	});

	it('returns allowed and not limitedGlobally when global=true and perUser=true', () => {
		const result = effectiveAccess(true, true);
		expect(result.effective).toBe(true);
		expect(result.limitedGlobally).toBe(false);
	});

	it('returns blocked and not limitedGlobally when global=true but perUser=false (admin override)', () => {
		const result = effectiveAccess(true, false);
		expect(result.effective).toBe(false);
		expect(result.limitedGlobally).toBe(false);
	});

	it('shows "global" as limiting factor only when global=false', () => {
		// global=false => block is global (limitedGlobally=true)
		expect(effectiveAccess(false, true).limitedGlobally).toBe(true);
		// perUser=false => block is per-user (limitedGlobally=false)
		expect(effectiveAccess(true, false).limitedGlobally).toBe(false);
	});

	it('returns allowed for global=true, perUser=true (default-allow contract)', () => {
		// Absent rows default to allowed; both being true means effective access is granted
		const result = effectiveAccess(true, true);
		expect(result.effective).toBe(true);
	});
});

describe('GLOBAL_FEATURE_MAP', () => {
	it('maps calendar to feature.caldav', () => {
		expect(GLOBAL_FEATURE_MAP.calendar).toBe('feature.caldav');
	});

	it('maps contacts to feature.carddav', () => {
		expect(GLOBAL_FEATURE_MAP.contacts).toBe('feature.carddav');
	});

	it('maps tasks to feature.tasks', () => {
		expect(GLOBAL_FEATURE_MAP.tasks).toBe('feature.tasks');
	});

	it('does NOT map mail to any global feature (mail is always globally available)', () => {
		expect(GLOBAL_FEATURE_MAP.mail).toBeUndefined();
	});
});
