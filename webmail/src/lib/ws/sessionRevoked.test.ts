import { describe, it, expect, vi } from 'vitest';
import { handleSessionRevoked } from './sessionRevoked';

describe('sessionRevoked', () => {
	it('clears token + redirects on a SessionRevoked envelope', () => {
		const clearToken = vi.fn();
		const redirect = vi.fn();
		const acted = handleSessionRevoked({ '@type': 'SessionRevoked' }, { clearToken, redirect });
		expect(acted).toBe(true);
		expect(clearToken).toHaveBeenCalledOnce();
		expect(redirect).toHaveBeenCalledWith('/login');
	});

	it('ignores unrelated envelopes', () => {
		const clearToken = vi.fn();
		const redirect = vi.fn();
		const acted = handleSessionRevoked({ '@type': 'StateChange' }, { clearToken, redirect });
		expect(acted).toBe(false);
		expect(clearToken).not.toHaveBeenCalled();
	});
});
