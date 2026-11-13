import { describe, it, expect } from 'vitest';
import { parseError } from './errors';

describe('parseError', () => {
	// 1. Network TypeError → user-friendly message, not raw "Failed to fetch"
	it('returns user-friendly message for network TypeError', () => {
		const result = parseError(new TypeError('Failed to fetch'));
		expect(result.message).not.toContain('Failed to fetch');
		expect(result.message).toContain('Network');
		expect(result.technical).toBe('Failed to fetch');
	});

	// 2. AbortError → user-friendly message, not raw DOMException
	it('returns user-friendly message for AbortError', () => {
		const result = parseError(new DOMException('The operation was aborted', 'AbortError'));
		expect(result.message).not.toContain('The operation was aborted');
		expect(result.message).toContain('cancelled');
	});

	// 3. Regular Error passes message through (these are authored by us)
	it('returns message from regular Error', () => {
		const result = parseError(new Error('Session expired — please log in again'));
		expect(result.message).toBe('Session expired — please log in again');
	});

	// 4. String input returns as-is
	it('returns string as message', () => {
		const result = parseError('something broke');
		expect(result.message).toBe('something broke');
	});

	// 5. null/undefined → fallback message
	it('returns fallback for null/undefined', () => {
		expect(parseError(null).message).toBe('Something went wrong');
		expect(parseError(undefined).message).toBe('Something went wrong');
	});

	// 6. Non-Error object → fallback
	it('returns fallback for non-Error objects', () => {
		const result = parseError({ code: 500 });
		expect(result.message).toBe('Something went wrong');
	});

	// 7. Number → fallback
	it('returns fallback for numbers', () => {
		const result = parseError(42);
		expect(result.message).toBe('Something went wrong');
	});

	// 8. Does not expose stack traces to end-user message
	it('does not expose stack traces to the user-facing message', () => {
		const err = new Error('Internal failure');
		err.stack = 'Error: Internal failure\n    at foo (bar.ts:1:2)';
		const result = parseError(err);
		expect(result.message).not.toContain('bar.ts');
		expect(result.message).not.toContain('stack');
	});

	// 9. Auth-related error strings pass through for server-authored messages
	it('passes through auth-related error strings from server', () => {
		const result = parseError('Session expired — please log in again');
		expect(result.message).toBe('Session expired — please log in again');
	});

	// 10. TypeError for any fetch failure returns network message, not raw TypeError
	it('returns network message for any TypeError (not just "Failed to fetch")', () => {
		const result = parseError(new TypeError('Load failed'));
		expect(result.message).not.toContain('Load failed');
		expect(result.message).toContain('Network');
		expect(result.technical).toBe('Load failed');
	});

	// 11. AbortError → special message (not an error per se)
	it('returns cancellation message for AbortError with any message text', () => {
		const result = parseError(new DOMException('User aborted', 'AbortError'));
		expect(result.message).not.toContain('User aborted');
		expect(result.message).toContain('cancelled');
	});

	// 12. Boolean thrown (defensive — should never happen but must not crash)
	it('returns fallback for boolean values', () => {
		const result = parseError(true);
		expect(result.message).toBe('Something went wrong');
	});

	// 13. Symbol thrown (defensive)
	it('returns fallback for symbols', () => {
		const result = parseError(Symbol('err'));
		expect(result.message).toBe('Something went wrong');
	});
});
